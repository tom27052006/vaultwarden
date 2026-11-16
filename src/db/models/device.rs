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

// No `AsChangeset`: an update of a whole device would also write its trust keys, see `DeviceWithoutTrustKeys`.
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

    // Trusted device encryption: the user key wrapped for the device key pair, its public key wrapped with the
    // user key and its private key wrapped with the device key, which never leaves the device.
    // `Device::save` leaves them alone, see `DeviceWithoutTrustKeys`.
    pub encrypted_user_key: Option<String>,
    pub encrypted_public_key: Option<String>,
    pub encrypted_private_key: Option<String>,
}

/// What `Device::save` updates: everything but the trust keys, so that saving a device that was read before a
/// concurrent untrust or key change doesn't undo it. Only `save_trust_keys`, `untrust_many` and
/// `update_keys_for_rotation` write them.
#[derive(AsChangeset)]
#[diesel(table_name = devices)]
#[diesel(treat_none_as_null = true)]
struct DeviceWithoutTrustKeys {
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
    name: String,
    atype: i32,
    push_uuid: Option<PushId>,
    push_token: Option<String>,
    refresh_token: String,
    twofactor_remember: Option<String>,
}

impl From<&Device> for DeviceWithoutTrustKeys {
    fn from(device: &Device) -> Self {
        // Every field by name, so that a new column has to be added here, or left out on purpose
        let Device {
            uuid: _,
            created_at,
            updated_at,
            user_uuid: _,
            name,
            atype,
            push_uuid,
            push_token,
            refresh_token,
            twofactor_remember,
            encrypted_user_key: _,
            encrypted_public_key: _,
            encrypted_private_key: _,
        } = device;

        Self {
            created_at: *created_at,
            updated_at: *updated_at,
            name: name.clone(),
            atype: *atype,
            push_uuid: push_uuid.clone(),
            push_token: push_token.clone(),
            refresh_token: refresh_token.clone(),
            twofactor_remember: twofactor_remember.clone(),
        }
    }
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
            refresh_token: Device::generate_refresh_token(),
            twofactor_remember: None,

            encrypted_user_key: None,
            encrypted_public_key: None,
            encrypted_private_key: None,
        }
    }

    #[inline(always)]
    pub fn generate_refresh_token() -> String {
        crypto::encode_random_bytes::<64>(&BASE64URL)
    }

    /// Like upstream's `DeviceExtensions.IsTrusted`
    pub fn is_trusted(&self) -> bool {
        [&self.encrypted_user_key, &self.encrypted_public_key, &self.encrypted_private_key]
            .iter()
            .all(|key| key.as_ref().is_some_and(|key| !key.is_empty()))
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "name": self.name,
            "type": self.atype,
            "identifier": self.uuid,
            "creationDate": format_date(&self.created_at),
            "isTrusted": self.is_trusted(),
            "encryptedUserKey": self.encrypted_user_key,
            "encryptedPublicKey": self.encrypted_public_key,
            "object":"device"
        })
    }

    /// Response of `POST /devices/<identifier>/retrieve-keys`
    pub fn to_protected_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "name": self.name,
            "type": self.atype,
            "identifier": self.uuid,
            "creationDate": format_date(&self.created_at),
            "encryptedUserKey": self.encrypted_user_key,
            "encryptedPublicKey": self.encrypted_public_key,
            "object": "protectedDevice"
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
            "isTrusted": self.device.is_trusted(),
            "encryptedPublicKey": self.device.encrypted_public_key,
            "encryptedUserKey": self.device.encrypted_user_key,
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
    pub async fn save(&mut self, update_time: bool, conn: &DbConn) -> EmptyResult {
        if update_time {
            self.updated_at = Utc::now().naive_utc();
        }
        let changes = DeviceWithoutTrustKeys::from(&*self);

        db_run! { conn:
            mysql {
                crate::util::retry(||
                    diesel::insert_into(devices::table)
                        .values(&*self)
                        .on_conflict(diesel::dsl::DuplicatedKeys)
                        .do_update()
                        .set(&changes)
                        .execute(conn),
                    10,
                ).map_res("Error saving device")
            }
            postgresql, sqlite {
                crate::util::retry(||
                    diesel::insert_into(devices::table)
                        .values(&*self)
                        .on_conflict((devices::uuid, devices::user_uuid))
                        .do_update()
                        .set(&changes)
                        .execute(conn),
                    10,
                ).map_res("Error saving device")
            }
        }
    }

    /// Writes the trust keys of the device, which `save` leaves alone.
    pub async fn save_trust_keys(&mut self, conn: &DbConn) -> EmptyResult {
        self.updated_at = Utc::now().naive_utc();

        conn.run(move |conn| {
            diesel::update(
                devices::table.filter(devices::uuid.eq(&self.uuid)).filter(devices::user_uuid.eq(&self.user_uuid)),
            )
            .set((
                devices::updated_at.eq(self.updated_at),
                devices::encrypted_user_key.eq(self.encrypted_user_key.clone()),
                devices::encrypted_public_key.eq(self.encrypted_public_key.clone()),
                devices::encrypted_private_key.eq(self.encrypted_private_key.clone()),
            ))
            .execute(conn)
            .map_res("Error saving the device keys")
        })
        .await
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(devices::table.filter(devices::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error removing devices for user")
        })
        .await
    }

    /// Removes the device, which ends its session and its trust.
    pub async fn delete(&self, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(
                devices::table.filter(devices::uuid.eq(&self.uuid)).filter(devices::user_uuid.eq(&self.user_uuid)),
            )
            .execute(conn)
            .map_res("Error removing the device")
        })
        .await
    }

    /// Ends the sessions of all devices of the user, as removing them did: a new refresh token invalidates the refresh
    /// tokens handed out, and the remembered two-step login is forgotten. Unlike removing them, the devices keep their
    /// trust, as upstream's devices do when the security stamp changes.
    pub async fn end_sessions_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        let device_ids: Vec<DeviceId> = Self::find_by_user(user_uuid, conn).await.into_iter().map(|d| d.uuid).collect();

        conn.run(move |conn| {
            conn.transaction(|conn| -> EmptyResult {
                for device_id in device_ids {
                    let _: () = diesel::update(
                        devices::table.filter(devices::uuid.eq(device_id)).filter(devices::user_uuid.eq(&user_uuid)),
                    )
                    .set((
                        devices::refresh_token.eq(Device::generate_refresh_token()),
                        devices::twofactor_remember.eq::<Option<String>>(None),
                    ))
                    .execute(conn)
                    .map_res("Error ending the device sessions")?;
                }
                Ok(())
            })
        })
        .await
    }

    /// Drops every stored key of the named devices, in one statement so it cannot half apply.
    pub async fn untrust_many(user_uuid: &UserId, device_ids: Vec<DeviceId>, conn: &DbConn) -> EmptyResult {
        if device_ids.is_empty() {
            return Ok(());
        }

        conn.run(move |conn| {
            diesel::update(
                devices::table.filter(devices::user_uuid.eq(user_uuid)).filter(devices::uuid.eq_any(device_ids)),
            )
            .set((
                devices::encrypted_user_key.eq::<Option<String>>(None),
                devices::encrypted_public_key.eq::<Option<String>>(None),
                devices::encrypted_private_key.eq::<Option<String>>(None),
            ))
            .execute(conn)
            .map_res("Error untrusting the devices")
        })
        .await
    }

    /// Writes the re-wrapped keys of the listed devices, like upstream's `UpdateKeysForRotationAsync`.
    pub async fn update_keys_for_rotation(
        user_uuid: &UserId,
        updates: Vec<(DeviceId, String, String)>,
        conn: &DbConn,
    ) -> EmptyResult {
        conn.run(move |conn| {
            conn.transaction(|conn| -> EmptyResult {
                for (device_id, encrypted_user_key, encrypted_public_key) in updates {
                    let _: () = diesel::update(
                        devices::table.filter(devices::uuid.eq(device_id)).filter(devices::user_uuid.eq(&user_uuid)),
                    )
                    .set((
                        devices::encrypted_user_key.eq(Some(encrypted_user_key)),
                        devices::encrypted_public_key.eq(Some(encrypted_public_key)),
                    ))
                    .execute(conn)
                    .map_res("Error rotating the device keys")?;
                }
                Ok(())
            })
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

    pub async fn rotate_refresh_tokens_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        // Generate a new token per device.
        // We cannot do a single UPDATE with one value because each device needs a unique token.
        let devices = Self::find_by_user(user_uuid, conn).await;
        for mut device in devices {
            device.refresh_token = Device::generate_refresh_token();
            device.twofactor_remember = None;
            device.save(false, conn).await?;
        }
        Ok(())
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
    #[display("DuckDuckGo Extension")]
    DuckDuckGoExtension = 27,
}

impl DeviceType {
    #[expect(clippy::match_same_arms, reason = "Specifically define 14 and have a fallback for new types")]
    pub fn from_i32(value: i32) -> DeviceType {
        match value {
            0 => DeviceType::Android,
            1 => DeviceType::Ios,
            2 => DeviceType::ChromeExtension,
            3 => DeviceType::FirefoxExtension,
            4 => DeviceType::OperaExtension,
            5 => DeviceType::EdgeExtension,
            6 => DeviceType::WindowsDesktop,
            7 => DeviceType::MacOsDesktop,
            8 => DeviceType::LinuxDesktop,
            9 => DeviceType::ChromeBrowser,
            10 => DeviceType::FirefoxBrowser,
            11 => DeviceType::OperaBrowser,
            12 => DeviceType::EdgeBrowser,
            13 => DeviceType::IEBrowser,
            14 => DeviceType::UnknownBrowser,
            15 => DeviceType::AndroidAmazon,
            16 => DeviceType::Uwp,
            17 => DeviceType::SafariBrowser,
            18 => DeviceType::VivaldiBrowser,
            19 => DeviceType::VivaldiExtension,
            20 => DeviceType::SafariExtension,
            21 => DeviceType::Sdk,
            22 => DeviceType::Server,
            23 => DeviceType::WindowsCLI,
            24 => DeviceType::MacOsCLI,
            25 => DeviceType::LinuxCLI,
            26 => DeviceType::DuckDuckGoBrowser,
            27 => DeviceType::DuckDuckGoExtension,
            _ => DeviceType::UnknownBrowser,
        }
    }

    /// Like upstream's `LoginApprovingClientTypes`: the mobile, desktop, browser extension and web clients that
    /// `DeviceTypes.ToClientType` knows. Not the SDK, the server, the CLIs, or a type that is not known yet.
    pub fn can_approve_login_requests(atype: i32) -> bool {
        matches!(atype, 0..=20 | 26 | 27)
    }
}

#[derive(
    Clone, Debug, DieselNewType, Display, From, FromForm, Hash, PartialEq, Eq, Serialize, Deserialize, IdFromParam,
)]
pub struct DeviceId(String);

#[derive(Clone, Debug, DieselNewType, Display, From, FromForm, Serialize, Deserialize, UuidFromParam)]
pub struct PushId(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    fn trusted_device() -> Device {
        let mut device = Device::new(String::from("device").into(), String::from("user").into(), String::new(), 9);
        device.encrypted_user_key = Some(String::from("2.user"));
        device.encrypted_public_key = Some(String::from("2.public"));
        device.encrypted_private_key = Some(String::from("2.private"));
        device
    }

    #[test]
    fn a_device_is_only_trusted_with_all_three_keys() {
        assert!(trusted_device().is_trusted());

        let keys: [fn(&mut Device) -> &mut Option<String>; 3] = [
            |device| &mut device.encrypted_user_key,
            |device| &mut device.encrypted_public_key,
            |device| &mut device.encrypted_private_key,
        ];
        for key in keys {
            for missing in [None, Some(String::new())] {
                let mut device = trusted_device();
                *key(&mut device) = missing;
                assert!(!device.is_trusted());
            }
        }
    }

    #[test]
    fn only_interactive_clients_can_approve_a_login_request() {
        for atype in -1..=30 {
            let expected = matches!(atype, 0..=27) && !matches!(atype, 21..=25);
            assert_eq!(DeviceType::can_approve_login_requests(atype), expected, "device type {atype}");
        }
        assert_eq!(DeviceType::from_i32(27).to_string(), "DuckDuckGo Extension");
    }

    #[cfg(sqlite)]
    #[test]
    fn ending_the_sessions_keeps_the_devices_and_their_trust() {
        use crate::db::{models::User, test_db};

        test_db::run(async |db| {
            let conn = db.conn();
            let mut user = User::new("trusted@example.com", None);
            user.save(&conn).await.unwrap();
            let mut device = trusted_device();
            device.user_uuid = user.uuid.clone();
            device.twofactor_remember = Some(String::from("remembered"));
            device.save(true, &conn).await.unwrap();

            Device::end_sessions_by_user(&user.uuid, &conn).await.unwrap();

            let saved = Device::find_by_uuid_and_user(&device.uuid, &user.uuid, &conn).await.unwrap();
            assert_ne!(saved.refresh_token, device.refresh_token);
            assert!(saved.twofactor_remember.is_none());
            assert!(saved.is_trusted());

            // A device read before an untrust doesn't bring its keys back when it is saved
            let mut stale = saved;
            Device::untrust_many(&user.uuid, vec![stale.uuid.clone()], &conn).await.unwrap();
            stale.save(true, &conn).await.unwrap();
            assert!(!Device::find_by_uuid_and_user(&device.uuid, &user.uuid, &conn).await.unwrap().is_trusted());

            stale.delete(&conn).await.unwrap();
            assert!(Device::find_by_uuid_and_user(&device.uuid, &user.uuid, &conn).await.is_none());
        });
    }
}
