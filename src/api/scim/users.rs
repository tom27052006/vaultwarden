//! SCIM `/Users` endpoints.
//!
//! A SCIM `User` is an **organization membership**, not a Vaultwarden account. Provisioning adds
//! someone to one organization; deprovisioning removes them from it. The global account and its
//! personal vault are never created, renamed or deleted on an identity provider's say-so beyond
//! the shell account an invitation already implies.
//!
//! Every lookup binds the membership id and the organization id together, so a membership that
//! belongs to another organization is indistinguishable from one that does not exist.

use rocket::Route;
use serde_json::Value;

use crate::{
    CONFIG,
    api::{
        Notify, UpdateType,
        core::{
            log_event,
            organizations::{ProvisionState, provision_org_member, try_restore_member, try_revoke_member},
        },
    },
    db::{
        DbConn,
        models::{EventType, Invitation, Membership, MembershipId, User},
    },
};

use super::{
    ACTING_SCIM_USER, ListQuery, ProjectionQuery, SCIM_DEVICE_TYPE, ScimContext, ScimToken, USER_SCHEMA,
    error::{ScimError, ScimResult},
    filter::{Filter, USER_ATTRS},
    json::{ScimBody, ScimResponse},
    list_response,
    patch::{FieldChange, PatchRequest, UserChanges, plan_user_patch},
    resource::{ScimUserRequest, UserView, ensure_schema, normalize_external_id, normalize_user_name},
};

pub fn routes() -> Vec<Route> {
    routes![get_users, get_user, post_user, put_user, patch_user, delete_user]
}

// ---------------------------------------------------------------------------------------------
// Lookup helpers
// ---------------------------------------------------------------------------------------------

/// Fetch one membership of this organization, together with its account.
///
/// The organization id is part of the query rather than something checked afterwards: a
/// membership from another organization must never be loaded in the first place.
async fn load_member(ctx: &ScimContext, id: &str, conn: &DbConn) -> ScimResult<(Membership, User)> {
    let member_id = MembershipId::from(id.to_owned());

    Membership::find_by_uuid_and_org_with_user(&member_id, &ctx.org_id, conn)
        .await
        .ok_or_else(|| ScimError::not_found(format!("User '{id}' not found.")))
}

/// Refuse to modify a membership SCIM does not own.
///
/// Owners, Admins and Managers are read-only through SCIM. This one rule is what makes "SCIM
/// cannot create, demote, restore or remove a privileged member" true by construction: there is
/// no code path that writes to such a membership at all.
///
/// A plain `403` with **no** `scimType`. This is Vaultwarden's provisioning policy refusing to
/// hand a whole *resource* to an identity provider, not a schema statement about one *attribute*:
/// there is no `active`, no `externalId` and no anything else that would be accepted on this
/// member, so `mutability` -- which tells a client one attribute violated its declared
/// changeability -- would describe the wrong fault and point at a fix that does not exist. The
/// attribute-level faults (`userName`, `displayName`, `emails`) keep the RFC's `400` +
/// `mutability`. See `docs/scim/design.md` section 7.
fn ensure_manageable(view: &UserView) -> ScimResult<()> {
    if view.is_scim_manageable() {
        return Ok(());
    }

    Err(ScimError::forbidden(format!(
        "User '{}' holds a privileged organization role and cannot be modified through SCIM. \
         Change the member's role to 'User' in the web vault first.",
        view.id
    )))
}

/// Reject an attempt to rename the underlying account.
///
/// `User.email` is Vaultwarden's global account identity: the login identifier, the invitation
/// target, and how every other organization resolves the same person. Letting one organization's
/// identity provider rewrite it would be an account-takeover primitive and a cross-tenant
/// mutation, so a genuine change is refused. A `userName` that matches is a no-op, which is what
/// identity providers send on every update.
fn ensure_user_name_unchanged(asserted: Option<&String>, current: &str) -> ScimResult<()> {
    let Some(asserted) = asserted else {
        return Ok(());
    };

    if asserted == current {
        return Ok(());
    }

    Err(ScimError::immutable(
        "'userName' cannot be changed through SCIM because it is the account's global identity. \
         Deprovision the user and provision the new address instead.",
    ))
}

/// Reject an attempt to rename the underlying account's display name.
///
/// `User.name` is not an authorization attribute, but it is just as global as the email: it is
/// shown in every organization the account belongs to, so one organization's identity provider
/// must not rewrite what the others see. Discovery advertises `displayName` as `immutable`, and
/// this is what makes that true: a value that matches is the no-op an identity provider sends on
/// every update, and a genuine change is refused rather than silently dropped.
///
/// [`FieldChange::Clear`] -- an explicit `remove` -- is refused for the same reason: an immutable
/// attribute cannot be unset any more than it can be changed.
fn ensure_display_name_unchanged(asserted: &FieldChange, current: &str) -> ScimResult<()> {
    match asserted {
        FieldChange::Unchanged => Ok(()),
        FieldChange::Set(asserted) if asserted == current => Ok(()),
        FieldChange::Set(_) => Err(ScimError::immutable(
            "'displayName' cannot be changed through SCIM because it is the account's global name, \
             shown in every organization the account belongs to. Change it in the web vault instead.",
        )),
        FieldChange::Clear => Err(ScimError::immutable(
            "'displayName' cannot be removed through SCIM because it is the account's global name.",
        )),
    }
}

/// Apply the server's signup policy to an address that has no Vaultwarden account yet.
///
/// Provisioning such an address creates a global account, so the same two checks the interactive
/// invite endpoint makes at the same point apply here. Without this, an identity provider could
/// create accounts on domains the operator excluded, or while invitations are switched off
/// entirely -- a quiet bypass of a stated server policy.
///
/// The Directory Connector import deliberately keeps its existing behaviour and does not perform
/// these checks, so they live here rather than in the shared `provision_org_member`.
fn ensure_account_creation_allowed(email: &str, invitations_allowed: bool, domain_allowed: bool) -> ScimResult<()> {
    if !invitations_allowed {
        return Err(ScimError::forbidden(
            "This server does not allow invitations, so SCIM cannot create an account for a new address. \
             Set INVITATIONS_ALLOWED, or provision only addresses that already have an account.",
        ));
    }

    if !domain_allowed {
        return Err(ScimError::invalid_value(format!(
            "The email domain of '{email}' is not allowed to be invited on this server."
        )));
    }

    Ok(())
}

/// Ensure no other membership in this organization already uses `external_id`.
async fn ensure_external_id_available(
    ctx: &ScimContext,
    external_id: Option<&String>,
    current: Option<&MembershipId>,
    conn: &DbConn,
) -> ScimResult<()> {
    let Some(external_id) = external_id else {
        return Ok(());
    };

    if let Some(existing) = Membership::find_by_external_id_and_org(external_id, &ctx.org_id, conn).await
        && Some(&existing.uuid) != current
    {
        return Err(ScimError::conflict(format!(
            "Another user in this organization already uses externalId '{external_id}'."
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------------------------

/// Attributes a user filter can be resolved through with a single indexed query.
///
/// `emails.value` is here because Microsoft requires any attribute used for user matching to be
/// filterable, and it always resolves to the same account email as `userName`.
const INDEXABLE_ATTRS: &[&str] = &["id", "username", "emails.value", "externalid"];

/// Narrow a filter to at most one membership using an indexed lookup.
///
/// Returns `None` when the filter has no equality this can use, in which case the caller falls
/// back to loading the organization. The result is only a *candidate*: the caller re-applies the
/// whole filter to it, so this never has to reproduce the filter's exact semantics.
async fn narrow_by_index(ctx: &ScimContext, filter: &Filter, conn: &DbConn) -> Option<Vec<(Membership, User)>> {
    let (attr, value) = filter.required_eq_on(INDEXABLE_ATTRS)?;

    let found = match attr {
        "id" => {
            let id = MembershipId::from(value.to_owned());
            Membership::find_by_uuid_and_org_with_user(&id, &ctx.org_id, conn).await
        }
        "username" | "emails.value" => {
            // Normalisation failures are not an error here: a filter for an address that cannot
            // exist simply matches nothing.
            let email = normalize_user_name(value).ok()?;
            match User::find_by_mail(&email, conn).await {
                Some(user) => Membership::find_by_user_and_org(&user.uuid, &ctx.org_id, conn).await.map(|m| (m, user)),
                None => None,
            }
        }
        "externalid" => {
            // Every match, not just the first: `external_id` has no unique constraint and legacy
            // Directory Connector data may already contain duplicates, so returning one row would
            // make the optimisation silently drop resources from a filtered listing.
            let mut rows = Vec::new();
            for member in Membership::find_all_by_external_id_and_org(value, &ctx.org_id, conn).await {
                if let Some(user) = User::find_by_uuid(&member.user_uuid, conn).await {
                    rows.push((member, user));
                }
            }
            return Some(rows);
        }
        _ => return None,
    };

    Some(found.into_iter().collect())
}

#[get("/<org_id>/Users?<query..>")]
async fn get_users(org_id: &str, query: ListQuery, token: ScimToken, conn: DbConn) -> ScimResult<ScimResponse> {
    let ctx = ScimContext::resolve(&token, org_id)?;

    let pagination = query.pagination()?;
    // Parsed against the User schema, so a Group-qualified attribute name is foreign here and
    // cannot alias onto a User attribute that shares its last segment.
    let projection = query.projection(USER_SCHEMA)?;

    let filter = query.filter.as_deref().map(|raw| Filter::parse(raw, USER_ATTRS, USER_SCHEMA)).transpose()?;

    let mut views: Vec<UserView> = match &filter {
        Some(filter) => {
            // An equality the filter requires becomes one indexed query instead of a scan; the
            // full filter is then applied to whatever that returned, so narrowing can never
            // change which resources match.
            let candidates = match narrow_by_index(&ctx, filter, &conn).await {
                Some(rows) => rows,
                None => Membership::find_by_org_with_user(&ctx.org_id, &conn).await,
            };

            candidates
                .iter()
                .map(|(m, u)| UserView::from_membership(m, u))
                .filter(|view| filter.matches(&view.to_filter_resource(), USER_ATTRS))
                .collect()
        }
        None => Membership::find_by_org_with_user(&ctx.org_id, &conn)
            .await
            .iter()
            .map(|(m, u)| UserView::from_membership(m, u))
            .collect(),
    };

    // Paging slices this list, so it needs a defined order. Without one, two requests over an
    // unchanged collection could return the same resource twice or skip it entirely.
    views.sort_by(|a, b| a.id.cmp(&b.id));

    let total = views.len();
    let page = pagination.slice_range(total);
    let resources: Vec<Value> = views[page]
        .iter()
        .map(|view| projection.apply(view.to_json(&ctx.resource_location("User", &view.id))))
        .collect();

    Ok(ScimResponse::ok(list_response(total, &pagination, resources)))
}

#[get("/<org_id>/Users/<user_id>?<query..>")]
async fn get_user(
    org_id: &str,
    user_id: &str,
    query: ProjectionQuery,
    token: ScimToken,
    conn: DbConn,
) -> ScimResult<ScimResponse> {
    let ctx = ScimContext::resolve(&token, org_id)?;
    let (member, user) = load_member(&ctx, user_id, &conn).await?;
    let view = UserView::from_membership(&member, &user);

    // Projection applies to every representation, not just list endpoints.
    let projection = query.projection(USER_SCHEMA)?;

    let location = ctx.resource_location("User", &view.id);
    Ok(ScimResponse::resource(projection.apply(view.to_json(&location)), location))
}

// ---------------------------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------------------------

#[post("/<org_id>/Users?<query..>", data = "<body>")]
async fn post_user(
    org_id: &str,
    query: ProjectionQuery,
    body: ScimBody<ScimUserRequest>,
    token: ScimToken,
    conn: DbConn,
) -> ScimResult<ScimResponse> {
    let ctx = ScimContext::resolve(&token, org_id)?;
    let request = body.into_inner()?;

    // Validate everything before touching the database. The projection is parsed here too, so a
    // request that cannot be rendered fails before it provisions anybody.
    let projection = query.projection(USER_SCHEMA)?;
    ensure_schema(request.schemas.as_ref(), USER_SCHEMA)?;
    let user_name = request.resolve_user_name()?;
    let external_id = normalize_external_id(request.external_id.as_deref())?;
    // Bounded here, not inside the provisioning helper, because it is only ever written to an
    // account this request creates. An over-long name is refused rather than silently truncated.
    let display_name = request.resolve_display_name()?;

    if Membership::find_by_email_and_org(&user_name, &ctx.org_id, &conn).await.is_some() {
        return Err(ScimError::conflict(format!("User '{user_name}' is already a member of this organization.")));
    }
    ensure_external_id_available(&ctx, external_id.as_ref(), None, &conn).await?;

    // Provisioning an address with no account creates one, so the server's own policy about who
    // may be given an account applies -- the same policy the interactive invite endpoint enforces
    // at the same point. An address that already has an account is unaffected: adding a
    // membership is not a signup.
    if User::find_by_mail(&user_name, &conn).await.is_none() {
        ensure_account_creation_allowed(
            &user_name,
            CONFIG.invitations_allowed(),
            CONFIG.is_email_domain_allowed(&user_name),
        )?;
    }

    // An identity provider may provision somebody who is already out of scope. The desired state
    // has to be decided *here*, before provisioning runs: creating an active member and revoking
    // them afterwards would already have sent them an invitation email and, with mail disabled,
    // left behind an `Invitation` record they could use to register -- neither of which can be
    // taken back, and both of which contradict the inactive state the client asked for.
    let state = if request.active == Some(false) {
        ProvisionState::Inactive
    } else {
        ProvisionState::Active
    };

    // The membership is always created as an unprivileged `User`; `provision_org_member` has no
    // parameter for anything else. The display name is only used if this creates a new account.
    let member = provision_org_member(&ctx.org_id, &user_name, display_name, external_id, state, &conn).await?;

    let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
        return Err(ScimError::internal("Provisioned membership has no account", &member.user_uuid));
    };

    log_event(
        EventType::OrganizationUserInvited,
        &member.uuid,
        &ctx.org_id,
        &ACTING_SCIM_USER.into(),
        SCIM_DEVICE_TYPE,
        &token.ip,
        &conn,
    )
    .await;

    if state == ProvisionState::Inactive {
        log_event(
            EventType::OrganizationUserRevoked,
            &member.uuid,
            &ctx.org_id,
            &ACTING_SCIM_USER.into(),
            SCIM_DEVICE_TYPE,
            &token.ip,
            &conn,
        )
        .await;
    }

    let view = UserView::from_membership(&member, &user);
    let location = ctx.resource_location("User", &view.id);

    Ok(ScimResponse::created(projection.apply(view.to_json(&location)), location))
}

// ---------------------------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------------------------

/// Everything about a membership that a SCIM `User` write can change.
///
/// Captured before the first mutation so a failure *after* the row has been saved can put the
/// resource back exactly as the client found it, which is what RFC 7644 section 3.5.2 requires of
/// a `PATCH`: "if any operation fails, the service provider SHALL return the resource to its
/// original state".
///
/// An explicit snapshot rather than a handful of local variables, so that adding a SCIM-writable
/// membership field is a compile-time prompt to include it here: the struct is built and restored
/// field by field, and a new one that is not listed is visible in this file rather than absent
/// from a rollback nobody re-reads.
///
/// Only the two SCIM-visible fields are held. Restoring the whole `Membership` would also undo
/// anything another request changed in between, which is a wider promise than this makes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScimMembershipSnapshot {
    /// The raw status column, not the derived `active` flag: `restore()` returns a membership to
    /// its *previous* status (Invited, Accepted or Confirmed), so "was it active" is not enough
    /// to put it back.
    status: i32,
    external_id: Option<String>,
}

impl ScimMembershipSnapshot {
    fn capture(member: &Membership) -> Self {
        Self {
            status: member.status,
            external_id: member.external_id.clone(),
        }
    }

    /// Put the captured state back into `member`, in memory.
    fn restore_into(&self, member: &mut Membership) {
        member.status = self.status;
        member.external_id.clone_from(&self.external_id);
    }
}

/// Apply a validated change set to a membership.
///
/// Both `PUT` and `PATCH` funnel through here, so the rules about what SCIM may change live in
/// one place. Nothing is written until every check has passed, and anything that fails after the
/// write is rolled back from [`ScimMembershipSnapshot`].
async fn apply_user_changes(
    ctx: &ScimContext,
    token: &ScimToken,
    member: &mut Membership,
    user: &User,
    changes: &UserChanges,
    conn: &DbConn,
) -> ScimResult<()> {
    let view = UserView::from_membership(member, user);
    ensure_manageable(&view)?;
    ensure_user_name_unchanged(changes.user_name_assertion.as_ref(), &view.user_name)?;
    ensure_display_name_unchanged(&changes.display_name_assertion, &view.display_name)?;

    if !changes.external_id.is_unchanged() {
        ensure_external_id_available(ctx, changes.external_id.to_stored().as_ref(), Some(&member.uuid), conn).await?;
    }

    // Decide the whole outcome before writing anything. The snapshot is taken here, after the
    // last check that can refuse the request and before the first mutation, so it always holds
    // the state the client would see if the request had never arrived.
    let original = ScimMembershipSnapshot::capture(member);
    let mut dirty = false;
    let mut event: Option<EventType> = None;
    let mut restored = false;

    if !changes.external_id.is_unchanged() {
        dirty |= member.set_external_id(changes.external_id.to_stored());
    }

    match changes.active {
        Some(false) if view.active => {
            // The only refusal here is the last confirmed owner, which `ensure_manageable` has
            // already ruled out, but report it as a refusal rather than a server error if the
            // membership rules ever change.
            try_revoke_member(member, conn)
                .await
                .map_err(|e| ScimError::forbidden(format!("This member cannot be deactivated: {}", e.message())))?;
            dirty = true;
            event = Some(EventType::OrganizationUserRevoked);
        }
        Some(true) if !view.active => {
            // Enforces the same organization policies as the interactive restore endpoint --
            // two-step login enforcement, the single-organization policy -- and puts the
            // membership back into its revoked state if they refuse.
            //
            // That refusal is a normal outcome an operator has to be able to act on, so it is a
            // 403 carrying the policy's own message rather than a generic 500. The message comes
            // from `OrgPolicy::check_user_allowed` and names the policy, not any internals.
            try_restore_member(member, conn).await.map_err(|e| {
                ScimError::forbidden(format!(
                    "This organization's policies do not currently allow reactivating this member: {}",
                    e.message()
                ))
            })?;
            dirty = true;
            event = Some(EventType::OrganizationUserRestored);
            restored = true;
        }
        _ => {}
    }

    if dirty {
        member.save(conn).await?;
    }

    // Somebody provisioned inactive never got an invitation, because sending one would have
    // contradicted the state the identity provider asked for. Reactivation is the moment it
    // becomes wanted, so an account that still cannot sign in gets one now.
    //
    // If that fails, the whole request fails with it. `active: true` on an unregistered account is
    // a promise that the person can now get in; leaving the membership active while the only way
    // in was never created would tell the identity provider the change succeeded when the user
    // has no usable path to the organization, and nothing downstream would ever notice.
    //
    // This is the one side effect that can fail *after* the row has been saved, so it is the one
    // place a rollback is needed. Every SCIM-visible field this request may have written is put
    // back from the snapshot -- not just the status. A `PATCH` that set `externalId` and `active`
    // in one document is a single operation as far as RFC 7644 section 3.5.2 is concerned: an
    // earlier revision kept the new `externalId` on the grounds that it was "correct anyway",
    // which left the resource in a state the client never asked for and never saw reported.
    //
    // The rollback is honest about what it cannot undo. Restoring the membership is a single row
    // write on a row already loaded and is reliable. An invitation *email* that was already handed
    // to the MTA before the call reported failure cannot be recalled -- so the person may receive
    // a mail for a membership that is revoked again, which is the same harmless state as any
    // revoked invitee. See docs/scim/design.md section 7.
    if restored && let Err(e) = super::settings::ensure_invitation(member, conn).await {
        warn!(target: "scim", "Could not issue an invitation while reactivating {}: {e:?}", member.uuid);

        // Put the membership back where it was, so the identity provider's next attempt starts
        // from the state it thinks it is in. Retries are safe: `ensure_invitation_for` is
        // idempotent -- it creates an `Invitation` row only when none exists -- so a retry that
        // succeeds does not double-provision, and a membership that is already active never
        // reaches this path at all.
        original.restore_into(member);
        if let Err(rollback) = member.save(conn).await {
            error!(
                target: "scim",
                "Could not roll back the SCIM changes to {} after the invitation failed: {rollback:?}. \
                 The membership may be left active with an updated externalId while its account has \
                 no way to accept the invitation.",
                member.uuid
            );
        }

        // No event is logged for any of it: nothing that was asked for survived, so an
        // `OrganizationUserRestored` entry would record a change that did not happen.
        return Err(ScimError::internal("Issuing an invitation for a reactivated SCIM member", &e));
    }

    if let Some(event) = event {
        log_event(event, &member.uuid, &ctx.org_id, &ACTING_SCIM_USER.into(), SCIM_DEVICE_TYPE, &token.ip, conn).await;
    }

    Ok(())
}

#[put("/<org_id>/Users/<user_id>?<query..>", data = "<body>")]
async fn put_user(
    org_id: &str,
    user_id: &str,
    query: ProjectionQuery,
    body: ScimBody<ScimUserRequest>,
    token: ScimToken,
    conn: DbConn,
) -> ScimResult<ScimResponse> {
    let ctx = ScimContext::resolve(&token, org_id)?;
    let request = body.into_inner()?;
    let projection = query.projection(USER_SCHEMA)?;
    ensure_schema(request.schemas.as_ref(), USER_SCHEMA)?;

    let (mut member, user) = load_member(&ctx, user_id, &conn).await?;

    // An absent attribute means "unchanged", not "clear". A strict reading of RFC 7644 section
    // 3.5.1 would clear it, which turns a sparse client payload into silent deprovisioning.
    //
    // `userName` and `displayName` are assertions, not writes: the two immutable attributes are
    // compared against the stored account and a genuine change is refused. Identity is resolved
    // from `emails[].value` as well, because that is what `POST` accepts and a client that
    // provisions by email updates by email.
    let changes = UserChanges {
        active: request.active,
        external_id: match request.external_id.as_deref() {
            Some(raw) => FieldChange::from_normalized(normalize_external_id(Some(raw))?),
            None => FieldChange::Unchanged,
        },
        // Already resolved with `userName` taking precedence over `emails`, which is why the
        // planner's separate email slot stays empty here.
        user_name_assertion: request.resolve_user_name_assertion()?,
        email_assertion: None,
        display_name_assertion: match request.asserted_display_name() {
            Some(name) => FieldChange::Set(name),
            None => FieldChange::Unchanged,
        },
    };

    apply_user_changes(&ctx, &token, &mut member, &user, &changes, &conn).await?;

    let view = UserView::from_membership(&member, &user);
    let location = ctx.resource_location("User", &view.id);
    Ok(ScimResponse::resource(projection.apply(view.to_json(&location)), location))
}

#[patch("/<org_id>/Users/<user_id>?<query..>", data = "<body>")]
async fn patch_user(
    org_id: &str,
    user_id: &str,
    query: ProjectionQuery,
    body: ScimBody<PatchRequest>,
    token: ScimToken,
    conn: DbConn,
) -> ScimResult<ScimResponse> {
    let ctx = ScimContext::resolve(&token, org_id)?;
    let request = body.into_inner()?;
    let projection = query.projection(USER_SCHEMA)?;
    let (mut member, user) = load_member(&ctx, user_id, &conn).await?;

    // The whole document is planned and validated first; a single bad operation fails the request
    // without any of it having been applied.
    //
    // The stored address goes in because a value path (`emails[type eq "work"].value`) selects
    // against the resource as it is now, and the one virtual `emails` element this server renders
    // carries that address. Planning still touches nothing: it only decides whether the selector
    // matched.
    let changes = plan_user_patch(&request, &user.email.to_lowercase())?;

    apply_user_changes(&ctx, &token, &mut member, &user, &changes, &conn).await?;

    let view = UserView::from_membership(&member, &user);
    let location = ctx.resource_location("User", &view.id);
    Ok(ScimResponse::resource(projection.apply(view.to_json(&location)), location))
}

// ---------------------------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------------------------

/// Remove the membership. The Vaultwarden account, its personal vault and its memberships in
/// other organizations are untouched.
///
/// The row is genuinely removed rather than revoked because RFC 7644 section 3.6 requires a later
/// `GET` to return `404`; a resource that keeps being returned after a successful `DELETE` makes
/// identity providers retry indefinitely. Operators who want the reversible behaviour should
/// deprovision with `active: false`, which is Entra ID's default.
#[delete("/<org_id>/Users/<user_id>")]
async fn delete_user(
    org_id: &str,
    user_id: &str,
    token: ScimToken,
    conn: DbConn,
    nt: Notify<'_>,
) -> ScimResult<ScimResponse> {
    let ctx = ScimContext::resolve(&token, org_id)?;
    let (member, user) = load_member(&ctx, user_id, &conn).await?;

    ensure_manageable(&UserView::from_membership(&member, &user))?;

    // Mirrors the interactive remove-member path: a pending invitation is only useful while the
    // account still has somewhere to accept an invitation to.
    if !CONFIG.mail_enabled()
        && !Membership::find_invited_by_user(&user.uuid, &conn).await.into_iter().any(|m| m.uuid != member.uuid)
    {
        Invitation::take(&user.email, &conn).await;
    }

    // Delete first, then record it. An event that says a member was removed must not outlive a
    // removal that failed.
    let member_uuid = member.uuid.clone();
    member.delete(&conn).await?;

    log_event(
        EventType::OrganizationUserRemoved,
        &member_uuid,
        &ctx.org_id,
        &ACTING_SCIM_USER.into(),
        SCIM_DEVICE_TYPE,
        &token.ip,
        &conn,
    )
    .await;

    nt.send_user_update(UpdateType::SyncOrgKeys, &user, None, &conn).await;

    Ok(ScimResponse::no_content())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::models::MembershipType;

    fn view(active: bool, membership_type: MembershipType, user_name: &str) -> UserView {
        UserView {
            id: MembershipId::from("member-1".to_owned()),
            external_id: None,
            user_name: user_name.to_owned(),
            display_name: "Alice".to_owned(),
            active,
            membership_type: membership_type as i32,
        }
    }

    #[test]
    fn plain_members_are_manageable() {
        assert!(ensure_manageable(&view(true, MembershipType::User, "a@example.test")).is_ok());
    }

    #[test]
    fn privileged_members_are_refused_with_a_plain_403() {
        // A provisioning-policy refusal of a whole resource, not an attribute mutability fault:
        // there is no value for any attribute that would make the request work, so labelling it
        // `mutability` would describe a problem the client could fix by sending something else.
        for role in [MembershipType::Owner, MembershipType::Admin, MembershipType::Manager] {
            let err = ensure_manageable(&view(true, role, "a@example.test")).unwrap_err();
            assert_eq!(err.status, rocket::http::Status::Forbidden);
            assert_eq!(err.scim_type, None, "a resource-level refusal carries no scimType");
        }
    }

    #[test]
    fn a_revoked_owner_is_still_refused() {
        // Otherwise a stale token could restore privileged access that an administrator revoked.
        assert!(ensure_manageable(&view(false, MembershipType::Owner, "a@example.test")).is_err());
    }

    #[test]
    fn a_matching_user_name_is_accepted_as_a_no_op() {
        assert!(ensure_user_name_unchanged(Some(&"a@example.test".to_owned()), "a@example.test").is_ok());
    }

    #[test]
    fn an_absent_user_name_is_accepted() {
        assert!(ensure_user_name_unchanged(None, "a@example.test").is_ok());
    }

    #[test]
    fn account_creation_follows_the_server_signup_policy() {
        // Both checks pass on a default server.
        assert!(ensure_account_creation_allowed("a@example.test", true, true).is_ok());
    }

    #[test]
    fn account_creation_is_refused_when_invitations_are_off() {
        let err = ensure_account_creation_allowed("a@example.test", false, true).unwrap_err();
        assert_eq!(err.status, rocket::http::Status::Forbidden);
        assert!(err.detail.contains("INVITATIONS_ALLOWED"), "the error should say how to fix it");
    }

    #[test]
    fn account_creation_is_refused_for_an_excluded_domain() {
        let err = ensure_account_creation_allowed("a@blocked.test", true, false).unwrap_err();
        assert_eq!(err.scim_type, Some(super::super::error::ScimType::InvalidValue));
        assert!(err.detail.contains("blocked.test"));
    }

    #[test]
    fn a_changed_user_name_is_refused_as_immutable() {
        let err = ensure_user_name_unchanged(Some(&"attacker@evil.test".to_owned()), "a@example.test").unwrap_err();

        assert_eq!(err.status, rocket::http::Status::BadRequest);
        assert_eq!(err.scim_type, Some(super::super::error::ScimType::Mutability));
        assert!(err.detail.contains("Deprovision"), "the error should say what to do instead");
    }

    // -- displayName immutability ----------------------------------------------------------------
    //
    // The User schema advertises `displayName` as `immutable`, so the three outcomes have to be
    // exactly the three the RFC gives that word: settable at creation, a no-op when re-asserted,
    // and an error when changed.

    #[test]
    fn an_absent_display_name_is_accepted() {
        assert!(ensure_display_name_unchanged(&FieldChange::Unchanged, "Alice").is_ok());
    }

    #[test]
    fn a_matching_display_name_is_accepted_as_a_no_op() {
        // What an identity provider sends on every sync once the account exists.
        assert!(ensure_display_name_unchanged(&FieldChange::Set("Alice".to_owned()), "Alice").is_ok());
    }

    #[test]
    fn a_changed_display_name_is_refused_as_immutable() {
        let err = ensure_display_name_unchanged(&FieldChange::Set("Someone Else".to_owned()), "Alice").unwrap_err();

        assert_eq!(err.status, rocket::http::Status::BadRequest);
        assert_eq!(err.scim_type, Some(super::super::error::ScimType::Mutability));
        assert!(err.detail.contains("web vault"), "the error should say where the name can be changed");
    }

    #[test]
    fn removing_the_display_name_is_refused_as_immutable() {
        // An immutable attribute cannot be unset any more than it can be changed.
        let err = ensure_display_name_unchanged(&FieldChange::Clear, "Alice").unwrap_err();

        assert_eq!(err.status, rocket::http::Status::BadRequest);
        assert_eq!(err.scim_type, Some(super::super::error::ScimType::Mutability));
    }

    #[test]
    fn display_name_comparison_is_exact() {
        // Names are not identifiers: "alice" and "Alice" are different names, and accepting one
        // for the other would mean the response did not describe what the server holds.
        assert!(ensure_display_name_unchanged(&FieldChange::Set("alice".to_owned()), "Alice").is_err());
    }
}
