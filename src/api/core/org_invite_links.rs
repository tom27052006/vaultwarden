use chrono::Utc;
use rocket::{Route, http::Status, response::status, serde::json::Json};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{
        ApiResult, EmptyResult, JsonResult, Notify, UpdateType,
        core::{log_event, two_factor::email},
    },
    auth::{AdminHeaders, Headers},
    db::{
        DbConn,
        models::{
            EventType, Membership, MembershipStatus, MembershipType, OrgInviteLink, OrgPolicy, OrgPolicyType,
            Organization, OrganizationId, PolicyViolation, User,
        },
    },
    mail,
};

// Upstream: https://github.com/bitwarden/server/blob/aa786fc9cd3803f48e79f15067e910e99d768b69/src/Api/AdminConsole/Controllers/OrganizationInviteLinksController.cs
// and the invite link endpoints in OrganizationUsersController.cs of the same commit.
// The error messages are the same as upstream, the clients choose what to show by them.
pub fn routes() -> Vec<Route> {
    routes![
        get_invite_link,
        create_invite_link,
        update_invite_link,
        update_invite_link_confirmation,
        delete_invite_link,
        refresh_invite_link,
        get_invite_link_status,
        get_invite_link_policies,
        validate_invite_link_email_domain,
        get_invite,
        accept_invite_link,
        confirm_invite_link,
    ]
}

const NOT_FOUND: &str = "Invite link not found.";

/// Identifies an invite link for the endpoints used to join, the code is the secret part of it
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteLinkRef {
    organization_id: OrganizationId,
    code: String,
}

/// An invite link a user registers through
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenOrgInvite {
    #[serde(flatten)]
    link: InviteLinkRef,
    /// Opaque data the clients need after the email verification, only sent when the registration starts
    pub sealed_open_org_invite_data: Option<String>,
}

impl OpenOrgInvite {
    pub fn org_id(&self) -> &OrganizationId {
        &self.link.organization_id
    }

    /// Errors if the link can't be used with the email address, like upstream. Otherwise returns whether the link
    /// lets the address register when signups are disabled, which needs the same settings as inviting it by email.
    pub async fn allows_signup(&self, email: &str, conn: &DbConn) -> ApiResult<bool> {
        if self.sealed_open_org_invite_data.as_ref().is_some_and(|data| data.len() > 4096) {
            err!("The field SealedOpenOrgInviteData must be a string or array type with a maximum length of '4096'.")
        }
        match find_link(&self.link, conn).await {
            Ok((link, _)) if link.allows_email(email) => {
                Ok(CONFIG.invitations_allowed() && CONFIG.is_email_domain_allowed(email))
            }
            _ => err!("Invalid or expired organization invite link."),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteData {
    invite: String,
    supports_confirmation: bool,
}

impl InviteData {
    fn validate(&self) -> EmptyResult {
        if self.invite.is_empty() {
            err!("The Invite field is required.")
        }
        // The server only stores the invite, but limit its size like upstream
        if self.invite.len() > 3000 {
            err!("The field Invite must be a string with a maximum length of 3000.")
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateInviteLinkData {
    allowed_domains: Vec<String>,
    #[serde(flatten)]
    invite: InviteData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AllowedDomainsData {
    allowed_domains: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmailDomainData {
    #[serde(flatten)]
    link: InviteLinkRef,
    email: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcceptInviteLinkData {
    #[serde(flatten)]
    link: InviteLinkRef,
    reset_password_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfirmInviteLinkData {
    #[serde(flatten)]
    link: InviteLinkRef,
    org_user_key: String,
    reset_password_key: Option<String>,
    // For the default collection of the Organization Data Ownership policy (My Items), which is not supported yet
    #[allow(dead_code)]
    default_user_collection_name: String,
}

/// The link and organization of a link reference. A wrong organization and a wrong code are reported the same, so
/// nothing can be learned about an organization without the code of its link.
async fn find_link(link: &InviteLinkRef, conn: &DbConn) -> ApiResult<(OrgInviteLink, Organization)> {
    if let Some(invite_link) = OrgInviteLink::find_by_org(&link.organization_id, conn).await
        && invite_link.code_matches(&link.code)
        && let Some(org) = Organization::find_by_uuid(&invite_link.org_uuid, conn).await
    {
        return Ok((invite_link, org));
    }
    err_code!(NOT_FOUND, Status::NotFound.code)
}

async fn find_org_link(org_id: &OrganizationId, headers: &AdminHeaders, conn: &DbConn) -> ApiResult<OrgInviteLink> {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(link) = OrgInviteLink::find_by_org(org_id, conn).await else {
        err_code!(NOT_FOUND, Status::NotFound.code)
    };
    Ok(link)
}

async fn conflict_if_link_exists(org_id: &OrganizationId, conn: &DbConn) -> EmptyResult {
    if OrgInviteLink::find_by_org(org_id, conn).await.is_some() {
        err_code!("An invite link already exists for this organization.", Status::Conflict.code)
    }
    Ok(())
}

#[get("/organizations/<org_id>/invite-link")]
async fn get_invite_link(org_id: OrganizationId, headers: AdminHeaders, conn: DbConn) -> JsonResult {
    Ok(Json(find_org_link(&org_id, &headers, &conn).await?.to_json()))
}

#[post("/organizations/<org_id>/invite-link", data = "<data>")]
async fn create_invite_link(
    org_id: OrganizationId,
    data: Json<CreateInviteLinkData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> ApiResult<status::Created<Json<Value>>> {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();
    let domains = OrgInviteLink::clean_domains(data.allowed_domains)?;
    data.invite.validate()?;
    conflict_if_link_exists(&org_id, &conn).await?;

    let mut link = OrgInviteLink::new(org_id.clone(), data.invite.invite, data.invite.supports_confirmation);
    link.set_allowed_domains(&domains);
    if let Err(e) = link.insert(&conn).await {
        // The unique index on the organization rejected a link a concurrent request created first
        conflict_if_link_exists(&org_id, &conn).await?;
        return Err(e);
    }

    headers.log_event(EventType::OrganizationInviteLinkCreated, &org_id, &org_id, &conn).await;
    Ok(status::Created::new(format!("organizations/{org_id}/invite-link")).body(Json(link.to_json())))
}

#[put("/organizations/<org_id>/invite-link", data = "<data>")]
async fn update_invite_link(
    org_id: OrganizationId,
    data: Json<AllowedDomainsData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    let domains = OrgInviteLink::clean_domains(data.into_inner().allowed_domains)?;
    let mut link = find_org_link(&org_id, &headers, &conn).await?;
    link.set_allowed_domains(&domains);
    link.revision_date = Utc::now().naive_utc();
    if !link.update_allowed_domains(&conn).await? {
        err_code!(NOT_FOUND, Status::NotFound.code)
    }

    headers.log_event(EventType::OrganizationInviteLinkDomainsEdited, &org_id, &org_id, &conn).await;
    Ok(Json(link.to_json()))
}

/// The clients change the invite along with this setting, but keep its secret, so the link stays the same
#[put("/organizations/<org_id>/invite-link/support-confirm", data = "<data>")]
async fn update_invite_link_confirmation(
    org_id: OrganizationId,
    data: Json<InviteData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    let data = data.into_inner();
    data.validate()?;
    let mut link = find_org_link(&org_id, &headers, &conn).await?;
    link.invite = data.invite;
    link.supports_confirmation = data.supports_confirmation;
    link.revision_date = Utc::now().naive_utc();
    if !link.replace(&link.uuid, &conn).await? {
        err_code!(NOT_FOUND, Status::NotFound.code)
    }

    let event = if link.supports_confirmation {
        EventType::OrganizationInviteLinkConfirmEnabled
    } else {
        EventType::OrganizationInviteLinkConfirmDisabled
    };
    headers.log_event(event, &org_id, &org_id, &conn).await;
    Ok(Json(link.to_json()))
}

#[delete("/organizations/<org_id>/invite-link")]
async fn delete_invite_link(
    org_id: OrganizationId,
    headers: AdminHeaders,
    conn: DbConn,
) -> ApiResult<status::NoContent> {
    find_org_link(&org_id, &headers, &conn).await?;
    // Members who joined through the link stay members
    OrgInviteLink::delete_all_by_organization(&org_id, &conn).await?;

    headers.log_event(EventType::OrganizationInviteLinkDeleted, &org_id, &org_id, &conn).await;
    Ok(status::NoContent)
}

/// Replaces the link with one with a new code and invite, the old link stops working. The allowed domains stay.
#[post("/organizations/<org_id>/invite-link/refresh", data = "<data>")]
async fn refresh_invite_link(
    org_id: OrganizationId,
    data: Json<InviteData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    let data = data.into_inner();
    data.validate()?;
    let old_link = find_org_link(&org_id, &headers, &conn).await?;
    let link = OrgInviteLink {
        allowed_domains: old_link.allowed_domains,
        ..OrgInviteLink::new(org_id.clone(), data.invite, data.supports_confirmation)
    };
    if !link.replace(&old_link.uuid, &conn).await? {
        err_code!(NOT_FOUND, Status::NotFound.code)
    }

    headers.log_event(EventType::OrganizationInviteLinkRefreshed, &org_id, &org_id, &conn).await;
    Ok(Json(link.to_json()))
}

#[post("/organizations/invite-link/status", data = "<data>")]
async fn get_invite_link_status(data: Json<InviteLinkRef>, conn: DbConn) -> JsonResult {
    let (link, org) = find_link(&data, &conn).await?;
    Ok(Json(json!({
        "organizationName": org.name,
        "linksEnabled": true,
        // Vaultwarden has no seat limit
        "seatsAvailable": true,
        "supportsConfirmation": link.supports_confirmation,
        // SSO isn't configured per organization. Clients also expect SSO sign-ups of such organizations to add the
        // membership and drop the invite afterwards, which Vaultwarden's SSO does not do.
        "sso": null,
        "object": "inviteLinkStatus",
    })))
}

/// The policies the clients need before joining: the master password requirements and account recovery enrollment
#[post("/organizations/invite-link/policies", data = "<data>")]
async fn get_invite_link_policies(data: Json<InviteLinkRef>, conn: DbConn) -> JsonResult {
    let (_, org) = find_link(&data, &conn).await?;
    let policies: Vec<Value> = OrgPolicy::find_by_org(&org.uuid, &conn)
        .await
        .iter()
        .filter(|p| {
            p.enabled && (p.has_type(OrgPolicyType::MasterPassword) || p.has_type(OrgPolicyType::ResetPassword))
        })
        .map(OrgPolicy::to_json)
        .collect();

    Ok(Json(json!({
        "data": policies,
        "object": "list",
        "continuationToken": null
    })))
}

#[post("/organizations/invite-link/validate-email-domain", data = "<data>")]
async fn validate_invite_link_email_domain(data: Json<EmailDomainData>, conn: DbConn) -> JsonResult {
    let (link, _) = find_link(&data.link, &conn).await?;
    Ok(Json(json!({
        "isAllowed": link.allows_email(&data.email),
    })))
}

/// The existing membership of a user joining through a link, or a new one, and the status it had. Like upstream this
/// checks everything but the policies: a revoked member can't get around the revocation, nobody can join twice
/// (`max_status` is the highest status which can still join), and allowed domains only count for verified addresses.
async fn joining_member(
    user: &User,
    link: &OrgInviteLink,
    org: &Organization,
    max_status: MembershipStatus,
    conn: &DbConn,
) -> ApiResult<(Membership, Option<i32>)> {
    let member = Membership::find_by_user_and_org(&user.uuid, &org.uuid, conn).await;
    if let Some(member) = &member {
        if member.status < MembershipStatus::Invited as i32 {
            err!(format!("Your access to the {} vault has been revoked.", org.name))
        }
        if member.status > max_status as i32 {
            err!(format!("You're already a member of {}.", org.name))
        }
    }
    if user.verified_at.is_none() {
        err!("You must verify your email address before joining an organization.")
    }
    if !link.allows_email(&user.email) {
        err!(format!("You're not allowed to join the {} vault with your email domain.", org.name))
    }

    Ok(match member {
        Some(member) => {
            let status = member.status;
            (member, Some(status))
        }
        None => (Membership::new(user.uuid.clone(), org.uuid.clone(), None), None),
    })
}

/// Checks the policies of the organization and stores the joined membership. Nothing is stored if a check fails,
/// and a concurrent request can neither create a second membership nor get a revocation undone.
async fn save_joined_member(
    member: &mut Membership,
    previous_status: Option<i32>,
    reset_password_key: Option<String>,
    headers: &Headers,
    org: &Organization,
    conn: &DbConn,
) -> EmptyResult {
    // The checks of `OrgPolicy::check_user_allowed`, in the order and with the messages of upstream
    let violations = OrgPolicy::find_violations(member, conn).await;
    if violations.contains(&PolicyViolation::SingleOrgOther) {
        err!(
            "Member cannot join this organization's vault because they are a member of another organization which forbids it."
        )
    }
    if violations.contains(&PolicyViolation::SingleOrgThis) {
        err!("Member cannot join this organization vault until they leave all other organization vaults.")
    }
    let activate_email_2fa = violations.contains(&PolicyViolation::TwoFactorMissing);
    if activate_email_2fa && !CONFIG.email_2fa_auto_fallback() {
        err!("You cannot join this organization vault until you enable two-step login on your user account.")
    }

    // Like upstream, the recovery key is only required and stored when the organization enrolls members automatically
    let auto_enroll = OrgPolicy::org_is_reset_password_auto_enroll(&org.uuid, conn).await;
    if auto_enroll {
        match reset_password_key {
            Some(key) if !key.trim().is_empty() => member.reset_password_key = Some(key),
            _ => err!("Master Password reset is required, but not provided."),
        }
    }

    if activate_email_2fa {
        email::activate_email_2fa(&headers.user, conn).await?;
    }
    let saved = match previous_status {
        Some(status) => member.update_status_if(status, conn).await?,
        None => member.insert_new(conn).await?,
    };
    if !saved {
        err!(format!("You're already a member of {}.", org.name))
    }

    if auto_enroll {
        log_member_event(EventType::OrganizationUserResetPasswordEnroll, member, headers, conn).await;
    }
    Ok(())
}

async fn log_member_event(event_type: EventType, member: &Membership, headers: &Headers, conn: &DbConn) {
    log_event(
        event_type,
        &member.uuid,
        &member.org_uuid,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;
}

/// The invite, which lets the client open the link with its secret and, for links supporting confirmation, contains
/// the organization key. So it needs the checks of the following accept or confirm, apart from the policies.
#[post("/organizations/users/invite-link/invite", data = "<data>")]
async fn get_invite(data: Json<InviteLinkRef>, headers: Headers, conn: DbConn) -> JsonResult {
    let (link, org) = find_link(&data, &conn).await?;
    let max_status = if link.supports_confirmation {
        MembershipStatus::Accepted
    } else {
        MembershipStatus::Invited
    };
    joining_member(&headers.user, &link, &org, max_status, &conn).await?;
    Ok(Json(json!({
        "invite": link.invite,
    })))
}

/// Joins as an accepted member, which an admin still has to confirm
#[post("/organizations/users/invite-link/accept", data = "<data>")]
async fn accept_invite_link(data: Json<AcceptInviteLinkData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data = data.into_inner();
    let (link, org) = find_link(&data.link, &conn).await?;
    let (mut member, previous_status) =
        joining_member(&headers.user, &link, &org, MembershipStatus::Invited, &conn).await?;
    member.status = MembershipStatus::Accepted as i32;
    save_joined_member(&mut member, previous_status, data.reset_password_key, &headers, &org, &conn).await?;

    log_member_event(EventType::OrganizationUserInviteLinkAccepted, &member, &headers, &conn).await;

    if CONFIG.mail_enabled() {
        // The member who sent an email invitation, otherwise all admins like upstream
        let mut addresses = Vec::from_iter(member.invited_by_email.clone());
        if addresses.is_empty() {
            for admin in Membership::find_confirmed_by_org(&org.uuid, &conn).await {
                if admin.atype >= MembershipType::Admin
                    && let Some(user) = User::find_by_uuid(&admin.user_uuid, &conn).await
                {
                    addresses.push(user.email);
                }
            }
        }
        for address in addresses {
            if let Err(e) = mail::send_invite_accepted(&headers.user.email, &address, &org.name).await {
                error!("Error sending invite accepted email: {e:#?}");
            }
        }
    }
    Ok(())
}

/// Joins as a confirmed member, with the organization key the client took from the invite
#[post("/organizations/users/invite-link/confirm", data = "<data>")]
async fn confirm_invite_link(
    data: Json<ConfirmInviteLinkData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let data = data.into_inner();
    let (link, org) = find_link(&data.link, &conn).await?;
    if !link.supports_confirmation {
        err!("This invite link does not support confirmation.")
    }
    if data.org_user_key.is_empty() {
        err!("The OrgUserKey field is required.")
    }
    let (mut member, previous_status) =
        joining_member(&headers.user, &link, &org, MembershipStatus::Accepted, &conn).await?;
    member.status = MembershipStatus::Confirmed as i32;
    member.akey = data.org_user_key;
    save_joined_member(&mut member, previous_status, data.reset_password_key, &headers, &org, &conn).await?;

    log_member_event(EventType::OrganizationUserInviteLinkConfirmed, &member, &headers, &conn).await;

    nt.send_user_update(UpdateType::SyncOrgKeys, &headers.user, headers.device.push_uuid.as_ref(), &conn).await;
    Ok(())
}
