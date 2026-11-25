use std::collections::HashSet;

use chrono::{NaiveDateTime, TimeDelta, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    CONFIG,
    api::{ApiResult, EmptyResult},
    crypto::ct_eq,
    db::{DbConn, schema::auth_requests},
    error::MapResult,
    util::format_date,
};
use macros::UuidFromParam;

use super::{DeviceId, DeviceType, OrganizationId, UserId};

#[derive(Identifiable, Queryable, Insertable, AsChangeset, Deserialize, Serialize)]
#[diesel(table_name = auth_requests)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct AuthRequest {
    pub uuid: AuthRequestId,
    pub user_uuid: UserId,
    pub organization_uuid: Option<OrganizationId>,
    pub atype: i32,

    pub request_device_identifier: DeviceId,
    pub device_type: i32, // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/Enums/DeviceType.cs

    pub request_ip: String,
    pub response_device_id: Option<DeviceId>,

    pub access_code: String,
    pub public_key: String,

    pub enc_key: Option<String>,

    pub master_password_hash: Option<String>,
    pub approved: Option<bool>,
    pub creation_date: NaiveDateTime,
    pub response_date: Option<NaiveDateTime>,

    pub authentication_date: Option<NaiveDateTime>,
}

/// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Core/Auth/Enums/AuthRequestType.cs>
#[derive(Clone, Copy, Debug, PartialEq, Eq, num_derive::FromPrimitive)]
pub enum AuthRequestType {
    AuthenticateAndUnlock = 0,
    Unlock = 1,
    AdminApproval = 2,
}

impl AuthRequest {
    // Upstream's `PasswordlessAuth` defaults
    pub const USER_REQUEST_EXPIRATION: TimeDelta = TimeDelta::minutes(15);
    /// Not upstream, which allows the whole `USER_REQUEST_EXPIRATION`: vaultwarden logs in with a request only
    /// within its first five minutes
    pub const LOGIN_EXPIRATION: TimeDelta = TimeDelta::minutes(5);

    pub fn new(
        user_uuid: UserId,
        atype: AuthRequestType,
        request_device_identifier: DeviceId,
        device_type: i32,
        request_ip: String,
        access_code: String,
        public_key: String,
    ) -> Self {
        let now = Utc::now().naive_utc();

        Self {
            uuid: AuthRequestId(crate::util::get_uuid()),
            user_uuid,
            organization_uuid: None,
            atype: atype as i32,

            request_device_identifier,
            device_type,
            request_ip,
            response_device_id: None,
            access_code,
            public_key,
            enc_key: None,
            master_password_hash: None,
            approved: None,
            creation_date: now,
            response_date: None,
            authentication_date: None,
        }
    }

    pub fn to_json(&self) -> Value {
        // Like upstream, the host of the web vault
        let origin = url::Url::parse(&CONFIG.domain()).ok().and_then(|url| url.host_str().map(str::to_owned));

        json!({
            "id": self.uuid,
            "publicKey": self.public_key,
            "requestDeviceIdentifier": self.request_device_identifier,
            "requestDeviceTypeValue": self.device_type,
            "requestDeviceType": DeviceType::from_i32(self.device_type).to_string(),
            "requestIpAddress": self.request_ip,
            "requestCountryName": null,
            "key": self.enc_key,
            "masterPasswordHash": self.master_password_hash,
            "creationDate": format_date(&self.creation_date),
            "responseDate": self.response_date.as_ref().map(format_date),
            "requestApproved": self.approved.unwrap_or(false),
            "origin": origin.unwrap_or_default(),
            "object": "auth-request"
        })
    }

    /// Like upstream's `AuthRequestService.IsAuthRequestValid`
    pub fn is_expired(&self) -> bool {
        Utc::now().naive_utc() > self.creation_date + Self::USER_REQUEST_EXPIRATION
    }

    /// Like upstream's `AuthRequest.IsValidForAuthentication`: only an approved and unused request that asked to log in
    /// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Core/Auth/Entities/AuthRequest.cs>
    pub fn is_valid_for_authentication(&self, user_uuid: &UserId, access_code: &str) -> bool {
        self.response_date.is_some()
            && self.approved == Some(true)
            && !self.is_expired()
            && self.atype == AuthRequestType::AuthenticateAndUnlock as i32
            && self.authentication_date.is_none()
            && &self.user_uuid == user_uuid
            && self.check_access_code(access_code)
    }

    /// `is_valid_for_authentication`, within `LOGIN_EXPIRATION` of the request
    pub fn is_valid_for_login(&self, user_uuid: &UserId, access_code: &str) -> bool {
        self.is_valid_for_authentication(user_uuid, access_code)
            && Utc::now().naive_utc() < self.creation_date + Self::LOGIN_EXPIRATION
    }

    pub fn to_json_for_pending_device(&self) -> Value {
        json!({
            "id": self.uuid,
            "creationDate": format_date(&self.creation_date),
        })
    }
}

impl AuthRequest {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            mysql {
                diesel::insert_into(auth_requests::table)
                    .values(self)
                    .on_conflict(diesel::dsl::DuplicatedKeys)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving auth_request")
            }
            postgresql, sqlite {
                diesel::insert_into(auth_requests::table)
                    .values(self)
                    .on_conflict(auth_requests::uuid)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving auth_request")
            }
        }
    }

    pub async fn find_by_uuid(uuid: &AuthRequestId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| auth_requests::table.filter(auth_requests::uuid.eq(uuid)).first::<Self>(conn).ok()).await
    }

    pub async fn find_by_uuid_and_user(uuid: &AuthRequestId, user_uuid: &UserId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            auth_requests::table
                .filter(auth_requests::uuid.eq(uuid))
                .filter(auth_requests::user_uuid.eq(user_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        conn.run(move |conn| {
            auth_requests::table
                .filter(auth_requests::user_uuid.eq(user_uuid))
                .load::<Self>(conn)
                .expect("Error loading auth_requests")
        })
        .await
    }

    /// The pending request of a device, which its owner's other devices answer. Like upstream, only the newest request of
    /// the device can be pending, so an answered newer one leaves none.
    /// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Sql/dbo/Auth/Stored%20Procedures/Device_ReadActiveWithPendingAuthRequestsByUserId.sql>
    pub async fn find_by_user_and_requested_device(
        user_uuid: &UserId,
        device_uuid: &DeviceId,
        conn: &DbConn,
    ) -> Option<Self> {
        let oldest = Utc::now().naive_utc() - Self::USER_REQUEST_EXPIRATION;

        conn.run(move |conn| {
            auth_requests::table
                .filter(auth_requests::user_uuid.eq(user_uuid))
                .filter(auth_requests::request_device_identifier.eq(device_uuid))
                .filter(auth_requests::atype.ne(AuthRequestType::AdminApproval as i32))
                .filter(auth_requests::creation_date.ge(oldest))
                .order_by(auth_requests::creation_date.desc())
                // The same tie-break as `find_pending_by_user`, so that the list and the approval agree on the newest
                .then_order_by(auth_requests::uuid.desc())
                .first::<Self>(conn)
                .ok()
        })
        .await
        .filter(|auth_request| auth_request.approved.is_none())
    }

    /// The pending request of each device of the user, newest first. Like upstream, only the newest request of a
    /// device can be pending, so an answered newer one leaves none.
    /// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Sql/dbo/Auth/Views/AuthRequestPendingDetailsView.sql>
    pub async fn find_pending_by_user(user_uuid: &UserId, conn: &DbConn) -> Vec<Self> {
        let oldest = Utc::now().naive_utc() - Self::USER_REQUEST_EXPIRATION;

        let requests = conn
            .run(move |conn| {
                auth_requests::table
                    .filter(auth_requests::user_uuid.eq(user_uuid))
                    .filter(auth_requests::atype.ne(AuthRequestType::AdminApproval as i32))
                    .filter(auth_requests::creation_date.ge(oldest))
                    .order_by(auth_requests::creation_date.desc())
                    // The same tie-break as `find_by_user_and_requested_device`
                    .then_order_by(auth_requests::uuid.desc())
                    .load::<Self>(conn)
                    .expect("Error loading auth_requests")
            })
            .await;

        Self::newest_unanswered_per_device(requests)
    }

    /// Of requests ordered newest first, the newest of each device, if it has no answer yet
    fn newest_unanswered_per_device(requests: Vec<Self>) -> Vec<Self> {
        let mut devices = HashSet::new();
        requests
            .into_iter()
            .filter(|auth_request| devices.insert(auth_request.request_device_identifier.clone()))
            .filter(|auth_request| auth_request.approved.is_none())
            .collect()
    }

    pub async fn delete_all_by_user(user_uuid: &UserId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(auth_requests::table.filter(auth_requests::user_uuid.eq(user_uuid)))
                .execute(conn)
                .map_res("Error deleting auth requests for user")
        })
        .await
    }

    /// Writes the answer, as upstream's `AuthRequest_Update` does, but only to a request that has none yet. Returns
    /// false when it was answered or purged meanwhile, which upstream doesn't check.
    pub async fn save_answer(&self, conn: &DbConn) -> ApiResult<bool> {
        conn.run(move |conn| {
            diesel::update(auth_requests::table)
                .filter(auth_requests::uuid.eq(&self.uuid))
                .filter(auth_requests::approved.is_null())
                .set((
                    auth_requests::approved.eq(self.approved),
                    auth_requests::response_date.eq(self.response_date),
                    auth_requests::response_device_id.eq(&self.response_device_id),
                    auth_requests::enc_key.eq(&self.enc_key),
                    auth_requests::master_password_hash.eq(&self.master_password_hash),
                ))
                .execute(conn)
                .map(|updated| updated == 1)
                .map_res("Error saving the answer of the auth request")
        })
        .await
    }

    /// Marks the request as used to log in. Returns false when it already was, so it only works once.
    pub async fn set_authentication_date(uuid: &AuthRequestId, conn: &DbConn) -> ApiResult<bool> {
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            diesel::update(auth_requests::table)
                .filter(auth_requests::uuid.eq(uuid))
                .filter(auth_requests::authentication_date.is_null())
                .set(auth_requests::authentication_date.eq(now))
                .execute(conn)
                .map(|updated| updated == 1)
                .map_res("Error updating auth request")
        })
        .await
    }

    pub fn check_access_code(&self, access_code: &str) -> bool {
        ct_eq(&self.access_code, access_code)
    }

    /// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Sql/dbo/Auth/Stored%20Procedures/AuthRequest_DeleteIfExpired.sql>
    pub async fn purge_expired_auth_requests(conn: &DbConn) {
        let expired = Utc::now().naive_utc() - Self::USER_REQUEST_EXPIRATION;

        let result = conn
            .run(move |conn| -> EmptyResult {
                diesel::delete(auth_requests::table.filter(auth_requests::creation_date.lt(expired)))
                    .execute(conn)
                    .map_res("Error purging the expired auth requests")
            })
            .await;

        if let Err(e) = result {
            error!("Error purging the expired auth requests: {e:#?}");
        }
    }
}

#[derive(
    Clone,
    Debug,
    AsRef,
    Deref,
    DieselNewType,
    Display,
    From,
    FromForm,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    UuidFromParam,
)]
pub struct AuthRequestId(String);

#[cfg(test)]
mod tests {
    use super::*;

    fn request(atype: AuthRequestType, age: TimeDelta) -> AuthRequest {
        let mut auth_request = AuthRequest::new(
            String::from("user").into(),
            atype,
            String::from("device").into(),
            9,
            String::from("127.0.0.1"),
            String::from("code"),
            String::from("2.public"),
        );
        auth_request.creation_date = Utc::now().naive_utc() - age;
        auth_request
    }

    fn approved(atype: AuthRequestType, age: TimeDelta) -> AuthRequest {
        let mut auth_request = request(atype, age);
        auth_request.approved = Some(true);
        auth_request.response_date = Some(Utc::now().naive_utc());
        auth_request
    }

    #[test]
    fn only_an_approved_unused_login_request_logs_in() {
        let user = UserId::from(String::from("user"));
        let minute = TimeDelta::try_minutes(1).unwrap();

        assert!(approved(AuthRequestType::AuthenticateAndUnlock, minute).is_valid_for_authentication(&user, "code"));
        assert!(!approved(AuthRequestType::AuthenticateAndUnlock, minute).is_valid_for_authentication(&user, "other"));
        assert!(
            !approved(AuthRequestType::AuthenticateAndUnlock, minute)
                .is_valid_for_authentication(&UserId::from(String::from("other")), "code")
        );
        assert!(!request(AuthRequestType::AuthenticateAndUnlock, minute).is_valid_for_authentication(&user, "code"));
        assert!(!approved(AuthRequestType::Unlock, minute).is_valid_for_authentication(&user, "code"));
        assert!(!approved(AuthRequestType::AdminApproval, minute).is_valid_for_authentication(&user, "code"));

        let expired = approved(AuthRequestType::AuthenticateAndUnlock, TimeDelta::try_minutes(16).unwrap());
        assert!(!expired.is_valid_for_authentication(&user, "code"));

        let mut logged_in = approved(AuthRequestType::AuthenticateAndUnlock, minute);
        logged_in.authentication_date = Some(Utc::now().naive_utc());
        assert!(!logged_in.is_valid_for_authentication(&user, "code"));

        let mut denied = approved(AuthRequestType::AuthenticateAndUnlock, minute);
        denied.approved = Some(false);
        assert!(!denied.is_valid_for_authentication(&user, "code"));
    }

    #[test]
    fn a_request_logs_in_only_within_five_minutes() {
        let user = UserId::from(String::from("user"));

        assert!(
            approved(AuthRequestType::AuthenticateAndUnlock, TimeDelta::try_minutes(4).unwrap())
                .is_valid_for_login(&user, "code")
        );
        let late = approved(AuthRequestType::AuthenticateAndUnlock, TimeDelta::try_minutes(6).unwrap());
        assert!(late.is_valid_for_authentication(&user, "code"));
        assert!(!late.is_valid_for_login(&user, "code"));
        assert!(
            !approved(AuthRequestType::Unlock, TimeDelta::try_minutes(1).unwrap()).is_valid_for_login(&user, "code")
        );
    }

    #[test]
    fn each_request_type_expires_after_its_own_window() {
        assert!(!request(AuthRequestType::AuthenticateAndUnlock, TimeDelta::try_minutes(14).unwrap()).is_expired());
        assert!(request(AuthRequestType::AuthenticateAndUnlock, TimeDelta::try_minutes(16).unwrap()).is_expired());
        assert!(request(AuthRequestType::Unlock, TimeDelta::try_minutes(16).unwrap()).is_expired());
    }

    #[test]
    fn only_the_newest_request_of_a_device_is_pending() {
        let minute = TimeDelta::try_minutes(1).unwrap();
        let on = |device: &str, answered: bool| {
            let mut auth_request = if answered {
                approved(AuthRequestType::AuthenticateAndUnlock, minute)
            } else {
                request(AuthRequestType::AuthenticateAndUnlock, minute)
            };
            auth_request.request_device_identifier = device.to_owned().into();
            auth_request
        };

        // Newest first: "a" asked twice, the newer request of "b" is answered already, "c" asked once
        let requests = vec![on("a", false), on("b", true), on("a", false), on("b", false), on("c", false)];
        let expected = [requests[0].uuid.clone(), requests[4].uuid.clone()];

        let pending = AuthRequest::newest_unanswered_per_device(requests);
        assert_eq!(pending.iter().map(|auth_request| auth_request.uuid.clone()).collect::<Vec<_>>(), expected);
    }
}
