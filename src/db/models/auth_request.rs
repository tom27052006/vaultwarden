use std::collections::HashSet;

use chrono::{NaiveDateTime, TimeDelta, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;
use serde_json::Value;

use crate::{
    CONFIG,
    api::{ApiResult, EmptyResult},
    crypto::ct_eq,
    db::{
        DbConn,
        schema::{auth_requests, users, users_organizations},
    },
    error::MapResult,
    util::format_date,
};
use macros::UuidFromParam;

use super::{DeviceId, DeviceType, MembershipId, OrganizationId, UserId};

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
    pub const ADMIN_REQUEST_EXPIRATION: TimeDelta = TimeDelta::days(7);
    pub const AFTER_ADMIN_APPROVAL_EXPIRATION: TimeDelta = TimeDelta::hours(12);
    /// Not upstream, which allows the whole `USER_REQUEST_EXPIRATION`: vaultwarden logs in with a request only
    /// within its first five minutes
    pub const LOGIN_EXPIRATION: TimeDelta = TimeDelta::minutes(5);

    /// A request without an organization; an admin approval then sets the organization it goes to
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

    pub fn is_admin_approval(&self) -> bool {
        self.atype == AuthRequestType::AdminApproval as i32
    }

    /// Like upstream's `AuthRequestService.IsAuthRequestValid`: an approved admin approval counts from its answer
    pub fn is_expired(&self) -> bool {
        let now = Utc::now().naive_utc();

        if self.is_admin_approval() {
            if let (Some(true), Some(response_date)) = (self.approved, self.response_date) {
                return now > response_date + Self::AFTER_ADMIN_APPROVAL_EXPIRATION;
            }
            return now > self.creation_date + Self::ADMIN_REQUEST_EXPIRATION;
        }

        now > self.creation_date + Self::USER_REQUEST_EXPIRATION
    }

    /// Answered or used, like the check of upstream's `AuthRequestUpdateProcessor`
    pub fn is_spent(&self) -> bool {
        self.approved.is_some() || self.response_date.is_some() || self.authentication_date.is_some()
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

    /// Like upstream's `PendingOrganizationAuthRequestResponseModel`
    pub fn to_json_for_organization(&self, email: &str, member_id: &MembershipId) -> Value {
        json!({
            "id": self.uuid,
            "userId": self.user_uuid,
            "organizationUserId": member_id,
            "email": email,
            "publicKey": self.public_key,
            "requestDeviceIdentifier": self.request_device_identifier,
            "requestDeviceType": DeviceType::from_i32(self.device_type).to_string(),
            "requestIpAddress": self.request_ip,
            "requestCountryName": null,
            "creationDate": format_date(&self.creation_date),
            "object": "pending-org-auth-request",
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

    /// The unanswered admin approvals of an organization with the member and email of whoever asked
    /// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Sql/dbo/Auth/Stored%20Procedures/AuthRequest_ReadPendingByOrganizationId.sql>
    pub async fn find_pending_admin_approvals_by_org(
        org_uuid: &OrganizationId,
        conn: &DbConn,
    ) -> Vec<(Self, MembershipId, String)> {
        conn.run(move |conn| {
            auth_requests::table
                .inner_join(users::table)
                .inner_join(
                    users_organizations::table.on(users_organizations::user_uuid
                        .eq(auth_requests::user_uuid)
                        .and(users_organizations::org_uuid.eq(org_uuid))),
                )
                .filter(auth_requests::organization_uuid.eq(org_uuid))
                .filter(auth_requests::atype.eq(AuthRequestType::AdminApproval as i32))
                .filter(auth_requests::response_date.is_null())
                .order_by(auth_requests::creation_date.desc())
                .select((auth_requests::all_columns, users_organizations::uuid, users::email))
                .load::<(Self, MembershipId, String)>(conn)
                .expect("Error loading auth_requests")
        })
        .await
    }

    /// Admin approvals of an organization by id, with the member who asked
    /// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Sql/dbo/Auth/Stored%20Procedures/AuthRequest_ReadAdminApprovalsByIds.sql>
    pub async fn find_admin_approvals_by_org_and_uuids(
        org_uuid: &OrganizationId,
        uuids: Vec<AuthRequestId>,
        conn: &DbConn,
    ) -> Vec<(Self, MembershipId)> {
        conn.run(move |conn| {
            auth_requests::table
                .inner_join(
                    users_organizations::table.on(users_organizations::user_uuid
                        .eq(auth_requests::user_uuid)
                        .and(users_organizations::org_uuid.eq(org_uuid))),
                )
                .filter(auth_requests::organization_uuid.eq(org_uuid))
                .filter(auth_requests::atype.eq(AuthRequestType::AdminApproval as i32))
                .filter(auth_requests::uuid.eq_any(uuids))
                .select((auth_requests::all_columns, users_organizations::uuid))
                .load::<(Self, MembershipId)>(conn)
                .expect("Error loading auth_requests")
        })
        .await
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(auth_requests::table.filter(auth_requests::organization_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error deleting auth requests for organization")
        })
        .await
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
        let now = Utc::now().naive_utc();
        let admin = AuthRequestType::AdminApproval as i32;

        let between_devices = now - Self::USER_REQUEST_EXPIRATION;
        let for_an_admin = now - Self::ADMIN_REQUEST_EXPIRATION;
        let after_approval = now - Self::AFTER_ADMIN_APPROVAL_EXPIRATION;

        let result = conn
            .run(move |conn| -> EmptyResult {
                let _: () = diesel::delete(
                    auth_requests::table
                        .filter(auth_requests::atype.ne(admin))
                        .filter(auth_requests::creation_date.lt(between_devices)),
                )
                .execute(conn)
                .map_res("Error purging the expired auth requests")?;

                let _: () = diesel::delete(
                    auth_requests::table
                        .filter(auth_requests::atype.eq(admin))
                        .filter(auth_requests::approved.eq(true))
                        .filter(auth_requests::response_date.lt(after_approval)),
                )
                .execute(conn)
                .map_res("Error purging the approved auth requests")?;

                diesel::delete(
                    auth_requests::table
                        .filter(auth_requests::atype.eq(admin))
                        .filter(auth_requests::approved.is_null().or(auth_requests::approved.eq(false)))
                        .filter(auth_requests::creation_date.lt(for_an_admin)),
                )
                .execute(conn)
                .map_res("Error purging the unanswered auth requests")
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
    fn an_answered_or_used_request_is_spent() {
        let minute = TimeDelta::try_minutes(1).unwrap();
        assert!(!request(AuthRequestType::AdminApproval, minute).is_spent());
        assert!(approved(AuthRequestType::AdminApproval, minute).is_spent());

        let mut used = request(AuthRequestType::AdminApproval, minute);
        used.authentication_date = Some(Utc::now().naive_utc());
        assert!(used.is_spent());
    }

    #[test]
    fn each_request_type_expires_after_its_own_window() {
        assert!(!request(AuthRequestType::AuthenticateAndUnlock, TimeDelta::try_minutes(14).unwrap()).is_expired());
        assert!(request(AuthRequestType::AuthenticateAndUnlock, TimeDelta::try_minutes(16).unwrap()).is_expired());
        assert!(request(AuthRequestType::Unlock, TimeDelta::try_minutes(16).unwrap()).is_expired());

        let week = TimeDelta::try_days(7).unwrap();
        assert!(!request(AuthRequestType::AdminApproval, week - TimeDelta::minutes(1)).is_expired());
        assert!(request(AuthRequestType::AdminApproval, week + TimeDelta::seconds(1)).is_expired());
    }

    #[test]
    fn the_answer_of_an_administrator_starts_its_own_clock() {
        let mut auth_request = request(AuthRequestType::AdminApproval, TimeDelta::try_days(7).unwrap());
        auth_request.approved = Some(true);

        auth_request.response_date = Some(Utc::now().naive_utc() - TimeDelta::try_hours(11).unwrap());
        assert!(!auth_request.is_expired());

        auth_request.response_date = Some(Utc::now().naive_utc() - TimeDelta::try_hours(13).unwrap());
        assert!(auth_request.is_expired());

        auth_request.approved = Some(false);
        auth_request.response_date = Some(Utc::now().naive_utc());
        assert!(auth_request.is_expired());
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
