use chrono::{NaiveDateTime, Utc};
use data_encoding::BASE64URL;
use derive_more::{Display, From};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    api::EmptyResult,
    crypto,
    db::{DbConn, schema::devices},
    error::MapResult,
    util::{format_date, get_uuid},
};
use macros::{IdFromParam, UuidFromParam};

use super::{AuthRequest, UserId};

// No `AsChangeset`: every write names its columns, so that a device read before a concurrent change, as a revoked
// session or a removal, can't undo that change when it is written back. See `Device::save`.
#[derive(Identifiable, Queryable, Insertable)]
#[diesel(table_name = devices)]
#[diesel(primary_key(uuid, user_uuid))]
pub struct Device {
    pub uuid: DeviceId,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,

    pub user_uuid: UserId,

    pub name: String,
    pub atype: i32, // https://github.com/bitwarden/server/blob/8d547dcc280babab70dd4a3c94ced6a34b12dfbf/src/Core/Enums/DeviceType.cs
    pub push_uuid: Option<PushId>,
    pub push_token: Option<String>,

    pub refresh_token: String,
    pub twofactor_remember: Option<String>,
}

/// Local methods
impl Device {
    pub fn new(uuid: DeviceId, user_uuid: UserId, name: String, atype: i32) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid,
            created_at: now,
            updated_at: now,

            user_uuid,
            name,
            atype,

            push_uuid: Some(PushId(get_uuid())),
            push_token: None,
            refresh_token: Self::generate_refresh_token(),
            twofactor_remember: None,
        }
    }

    #[inline(always)]
    pub fn generate_refresh_token() -> String {
        crypto::encode_random_bytes::<64>(&BASE64URL)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "name": self.name,
            "type": self.atype,
            "identifier": self.uuid,
            "creationDate": format_date(&self.created_at),
            "isTrusted": false,
            "object":"device"
        })
    }

    pub fn refresh_twofactor_remember(&mut self) -> String {
        use crate::auth::{encode_jwt, generate_2fa_remember_claims};

        let two_factor_remember_claim = generate_2fa_remember_claims(self.uuid.clone(), self.user_uuid.clone());
        let two_factor_remember_string = encode_jwt(&two_factor_remember_claim);
        self.twofactor_remember = Some(two_factor_remember_string.clone());

        two_factor_remember_string
    }

    pub fn delete_twofactor_remember(&mut self) {
        self.twofactor_remember = None;
    }

    // This rely on the fact we only update the device after a successful login
    pub fn is_new(&self) -> bool {
        self.created_at == self.updated_at
    }

    pub fn is_push_device(&self) -> bool {
        matches!(DeviceType::from_i32(self.atype), DeviceType::Android | DeviceType::Ios)
    }

    pub fn is_cli(&self) -> bool {
        matches!(DeviceType::from_i32(self.atype), DeviceType::WindowsCLI | DeviceType::MacOsCLI | DeviceType::LinuxCLI)
    }

    pub fn is_mobile(&self) -> bool {
        matches!(DeviceType::from_i32(self.atype), DeviceType::Android | DeviceType::Ios)
    }
}

pub struct DeviceWithAuthRequest {
    pub device: Device,
    pub pending_auth_request: Option<AuthRequest>,
}

impl DeviceWithAuthRequest {
    pub fn to_json(&self) -> Value {
        let auth_request = match &self.pending_auth_request {
            Some(auth_request) => auth_request.to_json_for_pending_device(),
            None => Value::Null,
        };
        json!({
            "id": self.device.uuid,
            "name": self.device.name,
            "type": self.device.atype,
            "identifier": self.device.uuid,
            "creationDate": format_date(&self.device.created_at),
            "devicePendingAuthRequest": auth_request,
            "isTrusted": false,
            "encryptedPublicKey": null,
            "encryptedUserKey": null,
            "object": "device",
        })
    }

    pub fn from(c: Device, a: Option<AuthRequest>) -> Self {
        Self {
            device: c,
            pending_auth_request: a,
        }
    }
}

/// Database methods
impl Device {
    /// Inserts a new device. A known device is only ever updated, by the methods below, so that a request that read it
    /// before it was removed can't bring it back.
    pub async fn create(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            crate::util::retry(|| diesel::insert_into(devices::table).values(self).execute(conn), 10)
                .map_res("Error saving device")
        })
        .await
    }

    /// Saves the activity and the push registration of the device, its `updated_at` with `update_time`, but only while
    /// this copy is of the current session. A logout or a security stamp change replaces the refresh token and a
    /// removal drops the device, and either makes this fail, instead of writing back what they replaced or removed.
    pub async fn save(&mut self, update_time: bool, conn: &DbConn) -> EmptyResult {
        if update_time {
            self.updated_at = Utc::now().naive_utc();
        }
        let device = &*self;

        let updated = conn
            .run(move |conn| {
                crate::util::retry(
                    || {
                        diesel::update(
                            devices::table
                                .filter(devices::uuid.eq(&device.uuid))
                                .filter(devices::user_uuid.eq(&device.user_uuid))
                                .filter(devices::refresh_token.eq(&device.refresh_token)),
                        )
                        .set((
                            devices::updated_at.eq(device.updated_at),
                            devices::push_uuid.eq(&device.push_uuid),
                            devices::push_token.eq(&device.push_token),
                        ))
                        .execute(conn)
                    },
                    10,
                )
                .map(|updated| updated == 1)
                .map_res("Error saving device")
            })
            .await?;

        if !updated {
            err!("The session of this device has ended", format!("Device {} no longer has this session", device.uuid))
        }
        Ok(())
    }

    /// Saves the remembered two-step login of the device: a new token only while this copy is of the current session,
    /// see `save`, its removal in any case.
    pub async fn save_twofactor_remember(&self, conn: &DbConn) -> EmptyResult {
        let updated = conn
            .run(move |conn| {
                let device =
                    devices::table.filter(devices::uuid.eq(&self.uuid)).filter(devices::user_uuid.eq(&self.user_uuid));
                match &self.twofactor_remember {
                    None => diesel::update(device)
                        .set(devices::twofactor_remember.eq::<Option<String>>(None))
                        .execute(conn)
                        .map(|_| true),
                    Some(token) => diesel::update(device.filter(devices::refresh_token.eq(&self.refresh_token)))
                        .set(devices::twofactor_remember.eq(token))
                        .execute(conn)
                        .map(|updated| updated == 1),
                }
                .map_res("Error saving the remembered two-step login")
            })
            .await?;

        if !updated {
            err!("The session of this device has ended", format!("Device {} no longer has this session", self.uuid))
        }
        Ok(())
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(devices::table.filter(devices::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error removing devices for user")
        })
        .await
    }

    pub async fn find_by_uuid_and_user(uuid: &DeviceId, user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            devices::table
                .filter(devices::uuid.eq(uuid))
                .filter(devices::user_uuid.eq(user_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_with_auth_request_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<DeviceWithAuthRequest> {
        let devices = Self::find_by_user(user_uuid, conn).await;
        let mut result = Vec::new();
        for device in devices {
            let auth_request = AuthRequest::find_by_user_and_requested_device(user_uuid, &device.uuid, conn).await;
            result.push(DeviceWithAuthRequest::from(device, auth_request));
        }
        result
    }

    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            devices::table.filter(devices::user_uuid.eq(user_uuid)).load::<Self>(conn).expect("Error loading devices")
        })
        .await
    }

    pub async fn find_by_uuid(uuid: &DeviceId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| devices::table.filter(devices::uuid.eq(uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn clear_push_token_by_uuid(uuid: &DeviceId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::update(devices::table)
                .filter(devices::uuid.eq(uuid))
                .set(devices::push_token.eq::<Option<String>>(None))
                .execute(conn)
                .map_res("Error removing push token")
        })
        .await
    }
    pub async fn find_by_refresh_token(refresh_token: &str, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| devices::table.filter(devices::refresh_token.eq(refresh_token)).first::<Self>(conn).ok())
            .await
    }

    pub async fn find_latest_active_by_user(user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .order(devices::updated_at.desc())
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_push_devices_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .filter(devices::push_token.is_not_null())
                .load::<Self>(conn)
                .expect("Error loading push devices")
        })
        .await
    }

    pub async fn check_user_has_push_device(user_uuid: &UserId, conn: &DbConn) -> bool {
        conn.run(move |conn| {
            devices::table
                .filter(devices::user_uuid.eq(user_uuid))
                .filter(devices::push_token.is_not_null())
                .count()
                .first::<i64>(conn)
                .ok()
                .unwrap_or(0)
                != 0
        })
        .await
    }

    /// Ends the session of every device of the user: a new refresh token invalidates the ones handed out, and the
    /// remembered two-step login is forgotten.
    pub async fn rotate_refresh_tokens_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        let device_ids: Vec<DeviceId> = Self::find_by_user(user_uuid, conn).await.into_iter().map(|d| d.uuid).collect();

        // Generate a new token per device.
        // We cannot do a single UPDATE with one value because each device needs a unique token.
        // Only these two columns: writing back whole devices read before would undo what changed meanwhile, and bring
        // back a device that was removed.
        conn.run(move |conn| {
            conn.transaction(|conn| -> EmptyResult {
                for device_id in device_ids {
                    let _: () = diesel::update(
                        devices::table.filter(devices::uuid.eq(device_id)).filter(devices::user_uuid.eq(&user_uuid)),
                    )
                    .set((
                        devices::refresh_token.eq(Self::generate_refresh_token()),
                        devices::twofactor_remember.eq::<Option<String>>(None),
                    ))
                    .execute(conn)
                    .map_res("Error rotating the refresh tokens")?;
                }
                Ok(())
            })
        })
        .await
    }

    pub async fn clear_twofactor_remember_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::update(devices::table)
                .filter(devices::user_uuid.eq(user_uuid))
                .set(devices::twofactor_remember.eq::<Option<String>>(None))
                .execute(conn)
                .map_res("Error removing two factor remember tokens")
        })
        .await
    }
}

#[derive(Display)]
pub enum DeviceType {
    #[display("Android")]
    Android = 0,
    #[display("iOS")]
    Ios = 1,
    #[display("Chrome Extension")]
    ChromeExtension = 2,
    #[display("Firefox Extension")]
    FirefoxExtension = 3,
    #[display("Opera Extension")]
    OperaExtension = 4,
    #[display("Edge Extension")]
    EdgeExtension = 5,
    #[display("Windows")]
    WindowsDesktop = 6,
    #[display("macOS")]
    MacOsDesktop = 7,
    #[display("Linux")]
    LinuxDesktop = 8,
    #[display("Chrome")]
    ChromeBrowser = 9,
    #[display("Firefox")]
    FirefoxBrowser = 10,
    #[display("Opera")]
    OperaBrowser = 11,
    #[display("Edge")]
    EdgeBrowser = 12,
    #[display("Internet Explorer")]
    IEBrowser = 13,
    #[display("Unknown Browser")]
    UnknownBrowser = 14,
    #[display("Android")]
    AndroidAmazon = 15,
    #[display("UWP")]
    Uwp = 16,
    #[display("Safari")]
    SafariBrowser = 17,
    #[display("Vivaldi")]
    VivaldiBrowser = 18,
    #[display("Vivaldi Extension")]
    VivaldiExtension = 19,
    #[display("Safari Extension")]
    SafariExtension = 20,
    #[display("SDK")]
    Sdk = 21,
    #[display("Server")]
    Server = 22,
    #[display("Windows CLI")]
    WindowsCLI = 23,
    #[display("macOS CLI")]
    MacOsCLI = 24,
    #[display("Linux CLI")]
    LinuxCLI = 25,
    #[display("DuckDuckGo")]
    DuckDuckGoBrowser = 26,
}

impl DeviceType {
    #[expect(clippy::match_same_arms, reason = "Specifically define 14 and have a fallback for new types")]
    pub fn from_i32(value: i32) -> Self {
        match value {
            0 => Self::Android,
            1 => Self::Ios,
            2 => Self::ChromeExtension,
            3 => Self::FirefoxExtension,
            4 => Self::OperaExtension,
            5 => Self::EdgeExtension,
            6 => Self::WindowsDesktop,
            7 => Self::MacOsDesktop,
            8 => Self::LinuxDesktop,
            9 => Self::ChromeBrowser,
            10 => Self::FirefoxBrowser,
            11 => Self::OperaBrowser,
            12 => Self::EdgeBrowser,
            13 => Self::IEBrowser,
            14 => Self::UnknownBrowser,
            15 => Self::AndroidAmazon,
            16 => Self::Uwp,
            17 => Self::SafariBrowser,
            18 => Self::VivaldiBrowser,
            19 => Self::VivaldiExtension,
            20 => Self::SafariExtension,
            21 => Self::Sdk,
            22 => Self::Server,
            23 => Self::WindowsCLI,
            24 => Self::MacOsCLI,
            25 => Self::LinuxCLI,
            26 => Self::DuckDuckGoBrowser,
            _ => Self::UnknownBrowser,
        }
    }
}

#[derive(
    Clone, Debug, DieselNewType, Display, From, FromForm, Hash, PartialEq, Eq, Serialize, Deserialize, IdFromParam,
)]
pub struct DeviceId(String);

#[derive(Clone, Debug, DieselNewType, Display, From, FromForm, Serialize, Deserialize, UuidFromParam)]
pub struct PushId(pub String);

#[cfg(all(test, sqlite))]
mod tests {
    use super::*;

    async fn saved_device(conn: &DbConn) -> Device {
        let mut user = crate::db::models::User::new(&format!("{}@example.com", get_uuid()), None);
        user.save(conn).await.unwrap();
        let mut device = Device::new(get_uuid().into(), user.uuid, String::new(), 9);
        device.twofactor_remember = Some(String::from("remembered"));
        device.create(conn).await.unwrap();
        device
    }

    async fn reload(device: &Device, conn: &DbConn) -> Option<Device> {
        Device::find_by_uuid_and_user(&device.uuid, &device.user_uuid, conn).await
    }

    /// Each copy below is read before the change it races with, as by a request that is still running when another one
    /// changes the device, and written back after it.
    #[test]
    fn a_device_read_before_a_change_cannot_undo_it() {
        crate::db::test_db::run(async |db| {
            let conn = db.conn();

            // A logout or security stamp change: neither the refresh token nor the remembered two-step login come back,
            // and the copy can't save anything anymore
            let mut stale = saved_device(&conn).await;
            Device::rotate_refresh_tokens_by_user(&stale.user_uuid, &conn).await.unwrap();
            let rotated = reload(&stale, &conn).await.unwrap();
            stale.push_token = Some(String::from("stale push token"));
            assert!(stale.save(true, &conn).await.is_err());
            assert!(stale.save_twofactor_remember(&conn).await.is_err());
            let saved = reload(&stale, &conn).await.unwrap();
            assert_eq!(saved.refresh_token, rotated.refresh_token);
            assert!(saved.twofactor_remember.is_none());
            assert!(saved.push_token.is_none());
            // A removal of the remembered two-step login works on any copy
            stale.delete_twofactor_remember();
            stale.save_twofactor_remember(&conn).await.unwrap();

            // Two-step login forgotten without a new session, as removing the second factors does: the copy still has the
            // session and saves its activity, but not the remembered login it read
            let mut stale = saved_device(&conn).await;
            Device::clear_twofactor_remember_by_user(&stale.user_uuid, &conn).await.unwrap();
            stale.save(true, &conn).await.unwrap();
            assert!(reload(&stale, &conn).await.unwrap().twofactor_remember.is_none());

            // A removal, as the deauthorization of all sessions does: the device stays removed, with its session
            let mut stale = saved_device(&conn).await;
            Device::delete_all_by_user(&stale.user_uuid, &conn).await.unwrap();
            assert!(stale.save(true, &conn).await.is_err());
            assert!(stale.save_twofactor_remember(&conn).await.is_err());
            assert!(reload(&stale, &conn).await.is_none());
        });
    }

    #[test]
    fn only_a_new_device_is_inserted() {
        crate::db::test_db::run(async |db| {
            let conn = db.conn();
            let device = saved_device(&conn).await;
            // Its first save is an insert, a second one fails instead of overwriting it
            assert!(device.create(&conn).await.is_err());

            // An update never inserts
            let mut unknown = Device::new(get_uuid().into(), device.user_uuid.clone(), String::new(), 9);
            assert!(unknown.save(true, &conn).await.is_err());
            assert!(reload(&unknown, &conn).await.is_none());

            // The current copy saves its activity, push registration and a new remembered two-step login
            let mut current = reload(&device, &conn).await.unwrap();
            current.push_token = Some(String::from("push token"));
            current.save(true, &conn).await.unwrap();
            current.twofactor_remember = Some(String::from("remembered again"));
            current.save_twofactor_remember(&conn).await.unwrap();
            let saved = reload(&device, &conn).await.unwrap();
            assert_eq!(saved.push_token.as_deref(), Some("push token"));
            assert_eq!(saved.twofactor_remember.as_deref(), Some("remembered again"));
            assert_eq!(saved.refresh_token, device.refresh_token);
        });
    }
}
