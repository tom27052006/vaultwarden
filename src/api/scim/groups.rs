//! SCIM `/Groups` endpoints, backed by Vaultwarden's existing `Group` and `GroupUser` models.
//!
//! Two rules govern everything here:
//!
//! 1. A group and every membership it contains must belong to the same organization.
//!    `GroupUser::save()` does not check that, so this module resolves every `members[].value`
//!    through an organization-bound lookup **before** any mutation. That is what prevents an
//!    organization B membership from being injected into an organization A group.
//! 2. An omitted `members` attribute means "unchanged", never "clear". See
//!    `docs/scim/design.md` section 8.

use std::collections::HashSet;

use rocket::Route;
use serde_json::Value;

use crate::{
    api::core::log_event,
    db::{
        DbConn,
        models::{EventType, Group, GroupId, GroupSaveOutcome, GroupUser, Membership, MembershipId},
    },
};

use super::{
    ACTING_SCIM_USER, AttributeProjection, GROUP_SCHEMA, ListQuery, Pagination, SCIM_DEVICE_TYPE, ScimContext,
    ScimToken,
    error::{ScimError, ScimResult, ScimType},
    filter::{Filter, GROUP_ATTRS},
    json::{ScimBody, ScimResponse},
    list_response,
    patch::{FieldChange, PatchRequest, apply_member_ops, plan_group_patch},
    resource::{
        GroupView, MAX_MEMBERS_PER_REQUEST, ScimGroupRequest, ensure_schema, normalize_display_name,
        normalize_external_id,
    },
};

pub fn routes() -> Vec<Route> {
    routes![get_groups, get_group, post_group, put_group, patch_group, delete_group]
}

// ---------------------------------------------------------------------------------------------
// Preconditions and lookups
// ---------------------------------------------------------------------------------------------

/// Groups only exist when the server has them switched on.
///
/// `501` rather than `404`, and the `Group` resource type is left out of `/ResourceTypes` and
/// `/Schemas` entirely, so discovery never advertises something that cannot work.
fn ensure_groups_enabled() -> ScimResult<()> {
    if super::settings::groups_enabled() {
        return Ok(());
    }

    Err(ScimError::not_implemented(
        "Organization groups are disabled on this server. Set ORG_GROUPS_ENABLED to use SCIM group provisioning.",
    ))
}

async fn load_group(ctx: &ScimContext, id: &str, conn: &DbConn) -> ScimResult<Group> {
    let group_id = GroupId::from(id.to_owned());

    Group::find_by_uuid_and_org(&group_id, &ctx.org_id, conn)
        .await
        .ok_or_else(|| ScimError::not_found(format!("Group '{id}' not found.")))
}

/// The group's current membership, in a stable order.
async fn current_members(ctx: &ScimContext, group_id: &GroupId, conn: &DbConn) -> Vec<MembershipId> {
    let mut members: Vec<MembershipId> = GroupUser::find_by_group(group_id, &ctx.org_id, conn)
        .await
        .into_iter()
        .map(|gu| gu.users_organizations_uuid)
        .collect();

    // `groups_users` has no ordering column, so sort for a deterministic response.
    members.sort_by_key(ToString::to_string);
    members
}

/// Check that every referenced membership exists **in this organization**.
///
/// Called before any write, so a request naming even one foreign or unknown membership changes
/// nothing at all. The error deliberately does not say whether the id exists elsewhere.
///
/// The lookup is batched: one query for the whole request rather than one per member, which is
/// what keeps synchronising a large group from generating thousands of round trips. Tenancy is
/// unchanged -- the organization is still bound into the query, so an id from another
/// organization simply does not come back and the request is refused.
///
/// **Privileged memberships are accepted here on purpose.** Owners, Admins and Managers are
/// read-only as *User* resources -- SCIM cannot change their role, revoke them or delete them --
/// but their group association is ordinary directory data that an identity provider is expected
/// to manage. See `docs/scim/design.md` for the security consequences.
async fn resolve_members(ctx: &ScimContext, ids: &[MembershipId], conn: &DbConn) -> ScimResult<()> {
    if ids.is_empty() {
        return Ok(());
    }

    let found: HashSet<MembershipId> =
        Membership::find_existing_uuids_in_org(ids, &ctx.org_id, conn).await.into_iter().collect();

    if let Some(missing) = ids.iter().find(|id| !found.contains(*id)) {
        return Err(ScimError::invalid_value(format!("Member '{missing}' is not a member of this organization.")));
    }

    Ok(())
}

async fn ensure_group_external_id_available(
    ctx: &ScimContext,
    external_id: Option<&String>,
    current: Option<&GroupId>,
    conn: &DbConn,
) -> ScimResult<()> {
    let Some(external_id) = external_id else {
        return Ok(());
    };

    if let Some(existing) = Group::find_by_external_id_and_org(external_id, &ctx.org_id, conn).await
        && Some(&existing.uuid) != current
    {
        return Err(ScimError::conflict(format!(
            "Another group in this organization already uses externalId '{external_id}'."
        )));
    }

    Ok(())
}

/// Refuse to give a group a name another group in the organization already has.
///
/// RFC 7643 does not require `displayName` to be unique and Vaultwarden does not enforce it in the
/// database, but identity providers treat it as a group's natural key: without this, every sync
/// would create another copy of the same group.
///
/// Enforced on create **and** on rename -- `current` excludes the group being renamed -- because
/// an invariant only checked on create is one a rename can walk straight through. Existing
/// duplicates created by other means keep working; only new collisions are refused.
///
/// Comparison is Unicode case-insensitive, the same way everywhere, so a name is not "taken" on
/// one code path and free on another.
async fn ensure_display_name_available(
    ctx: &ScimContext,
    display_name: &str,
    current: Option<&GroupId>,
    conn: &DbConn,
) -> ScimResult<()> {
    let wanted = display_name.to_lowercase();

    let taken = Group::find_by_organization(&ctx.org_id, conn)
        .await
        .iter()
        .any(|g| g.name.to_lowercase() == wanted && Some(&g.uuid) != current);

    if taken {
        return Err(ScimError::conflict(format!(
            "A group named '{display_name}' already exists in this organization."
        )));
    }

    Ok(())
}

/// Apply the non-membership changes to `group` in memory.
///
/// Returns whether anything actually changed, so the caller can skip a pointless write and a
/// misleading "group updated" event. Shared by `PUT` and `PATCH` so both agree on what an absent
/// attribute means: unchanged, never cleared.
fn apply_group_metadata(group: &mut Group, display_name: Option<String>, external_id: &FieldChange) -> bool {
    let name_changed = match display_name {
        Some(display_name) if group.name != display_name => {
            group.name = display_name;
            true
        }
        _ => false,
    };

    let external_id_changed = if external_id.is_unchanged() {
        false
    } else {
        let value = external_id.to_stored();
        if group.external_id == value {
            false
        } else {
            group.set_external_id(value);
            true
        }
    };

    name_changed || external_id_changed
}

/// Record what a committed group mutation actually did.
///
/// Called **after** the transaction succeeds, so the audit log never claims a change that was
/// rolled back. Only memberships that genuinely moved get an event: updating `{A, B}` to `{A, C}`
/// records C joining and B leaving and says nothing about A, who did not change.
async fn log_group_changes(
    ctx: &ScimContext,
    token: &ScimToken,
    group: &Group,
    event: EventType,
    outcome: &GroupSaveOutcome,
    conn: &DbConn,
) {
    log_event(event, &group.uuid, &ctx.org_id, &ACTING_SCIM_USER.into(), SCIM_DEVICE_TYPE, &token.ip, conn).await;

    for member_id in outcome.added.iter().chain(outcome.removed.iter()) {
        log_event(
            EventType::OrganizationUserUpdatedGroups,
            member_id,
            &ctx.org_id,
            &ACTING_SCIM_USER.into(),
            SCIM_DEVICE_TYPE,
            &token.ip,
            conn,
        )
        .await;
    }
}

/// Build the response body for a group, loading its membership only if the caller wants it.
async fn render_group(ctx: &ScimContext, group: &Group, projection: &AttributeProjection, conn: &DbConn) -> Value {
    let members = if projection.wants("members") {
        Some(current_members(ctx, &group.uuid, conn).await)
    } else {
        None
    };

    let view = GroupView::from_group(group, members);
    projection.apply(view.to_json(&ctx.resource_location("Group", &view.id), &ctx.base_url()))
}

// ---------------------------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------------------------

/// Attributes a group filter can be resolved through with a single indexed query.
///
/// `displayName` is deliberately absent: it has no unique index, so a lookup by name is a scan
/// either way.
const INDEXABLE_ATTRS: &[&str] = &["id", "externalid"];

/// Narrow a filter to at most one group using an indexed lookup.
///
/// The result is only a *candidate*: the caller re-applies the whole filter to it.
async fn narrow_by_index(ctx: &ScimContext, filter: &Filter, conn: &DbConn) -> Option<Vec<Group>> {
    let (attr, value) = filter.required_eq_on(INDEXABLE_ATTRS)?;

    match attr {
        "id" => {
            let id = GroupId::from(value.to_owned());
            Some(Group::find_by_uuid_and_org(&id, &ctx.org_id, conn).await.into_iter().collect())
        }
        // Every match, not just the first: `external_id` carries no unique constraint, and
        // existing installations may hold duplicates from the Directory Connector. Returning one
        // row would make the optimisation quietly change the result set it is optimising.
        "externalid" => Some(Group::find_all_by_external_id_and_org(value, &ctx.org_id, conn).await),
        // `displayName` has no unique index, so it is resolved by scanning the organization's
        // groups rather than by a single-row lookup.
        _ => None,
    }
}

#[get("/<org_id>/Groups?<query..>")]
async fn get_groups(org_id: &str, query: ListQuery, token: ScimToken, conn: DbConn) -> ScimResult<ScimResponse> {
    ensure_groups_enabled()?;
    let ctx = ScimContext::resolve(&token, org_id)?;

    let pagination = Pagination::parse(query.start_index.as_deref(), query.count.as_deref())?;
    // Entra ID asks for groups with `excludedAttributes=members`; honouring that lets us skip the
    // membership lookup entirely.
    let projection = AttributeProjection::parse(query.attributes.as_deref(), query.excluded_attributes.as_deref())?;

    let filter = query.filter.as_deref().map(|raw| Filter::parse(raw, GROUP_ATTRS, GROUP_SCHEMA)).transpose()?;

    let groups: Vec<Group> = match &filter {
        Some(filter) => {
            // Narrow with an indexed lookup where the filter allows it, then apply the whole
            // filter to the candidates, so narrowing can never change which groups match.
            let candidates = match narrow_by_index(&ctx, filter, &conn).await {
                Some(groups) => groups,
                None => Group::find_by_organization(&ctx.org_id, &conn).await,
            };

            // Loading membership costs one query per candidate, so only do it when the filter
            // actually looks at `members`. Without this, a filter on `displayName` alone would
            // still fan out across every group in the organization.
            let needs_members = filter.references("members");

            let mut matched = Vec::new();
            for group in candidates {
                let members = if needs_members {
                    Some(current_members(&ctx, &group.uuid, &conn).await)
                } else {
                    None
                };
                let view = GroupView::from_group(&group, members);
                if filter.matches(&view.to_filter_resource(), GROUP_ATTRS) {
                    matched.push(group);
                }
            }
            matched
        }
        None => Group::find_by_organization(&ctx.org_id, &conn).await,
    };

    // Paging slices this list, so it needs a defined order or two requests over an unchanged
    // collection could skip or repeat a group.
    let mut groups = groups;
    groups.sort_by(|a, b| a.uuid.cmp(&b.uuid));

    let total = groups.len();
    let page = pagination.slice_range(total);

    let mut resources = Vec::with_capacity(page.len());
    for group in &groups[page] {
        resources.push(render_group(&ctx, group, &projection, &conn).await);
    }

    Ok(ScimResponse::ok(list_response(total, &pagination, resources)))
}

#[get("/<org_id>/Groups/<group_id>?<query..>")]
async fn get_group(
    org_id: &str,
    group_id: &str,
    query: ListQuery,
    token: ScimToken,
    conn: DbConn,
) -> ScimResult<ScimResponse> {
    ensure_groups_enabled()?;
    let ctx = ScimContext::resolve(&token, org_id)?;
    let group = load_group(&ctx, group_id, &conn).await?;

    let projection = AttributeProjection::parse(query.attributes.as_deref(), query.excluded_attributes.as_deref())?;

    let body = render_group(&ctx, &group, &projection, &conn).await;
    Ok(ScimResponse::resource(body, ctx.resource_location("Group", &group.uuid)))
}

// ---------------------------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------------------------

#[post("/<org_id>/Groups", data = "<body>")]
async fn post_group(
    org_id: &str,
    body: ScimBody<ScimGroupRequest>,
    token: ScimToken,
    conn: DbConn,
) -> ScimResult<ScimResponse> {
    ensure_groups_enabled()?;
    let ctx = ScimContext::resolve(&token, org_id)?;
    let request = body.into_inner()?;

    // Everything is validated before the group is created, so a bad member reference does not
    // leave an empty group behind.
    ensure_schema(request.schemas.as_ref(), GROUP_SCHEMA)?;
    let Some(raw_name) = request.display_name.as_deref() else {
        return Err(ScimError::invalid_value("'displayName' is required."));
    };
    let display_name = normalize_display_name(raw_name)?;
    let external_id = normalize_external_id(request.external_id.as_deref())?;
    let members = request.member_ids()?.unwrap_or_default();

    ensure_display_name_available(&ctx, &display_name, None, &conn).await?;
    ensure_group_external_id_available(&ctx, external_id.as_ref(), None, &conn).await?;
    resolve_members(&ctx, &members, &conn).await?;

    // `access_all` is hard-coded off: SCIM must not be able to grant a group access to every
    // collection in the organization.
    let mut group = Group::new(ctx.org_id.clone(), display_name, false, external_id);

    // The group row and its membership are written in one transaction, so a failure while
    // persisting members rolls the group back too. Creating a group and then failing on its
    // members would otherwise leave an empty group behind that the client never asked for.
    let outcome = group.save_with_members(true, true, Some(members), &conn).await?;

    // Events only after the write has actually committed, so the audit log never records a
    // creation that was rolled back.
    log_group_changes(&ctx, &token, &group, EventType::GroupCreated, &outcome, &conn).await;

    let projection = AttributeProjection::none();
    let body = render_group(&ctx, &group, &projection, &conn).await;
    let location = ctx.resource_location("Group", &group.uuid);

    Ok(ScimResponse::created(body, location))
}

// ---------------------------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------------------------

#[put("/<org_id>/Groups/<group_id>", data = "<body>")]
async fn put_group(
    org_id: &str,
    group_id: &str,
    body: ScimBody<ScimGroupRequest>,
    token: ScimToken,
    conn: DbConn,
) -> ScimResult<ScimResponse> {
    ensure_groups_enabled()?;
    let ctx = ScimContext::resolve(&token, org_id)?;
    let request = body.into_inner()?;
    ensure_schema(request.schemas.as_ref(), GROUP_SCHEMA)?;

    let mut group = load_group(&ctx, group_id, &conn).await?;

    let display_name = request.display_name.as_deref().map(normalize_display_name).transpose()?;
    let external_id = match request.external_id.as_deref() {
        Some(raw) => FieldChange::from_normalized(normalize_external_id(Some(raw))?),
        None => FieldChange::Unchanged,
    };
    // `None` here means the client did not send `members` at all, which leaves membership alone.
    // `Some(vec![])` means it explicitly asked for an empty group.
    let members = request.member_ids()?;

    if let Some(display_name) = &display_name {
        // Enforced on rename as well as on create, excluding this group, so a rename cannot
        // produce the duplicate that creation refuses.
        ensure_display_name_available(&ctx, display_name, Some(&group.uuid), &conn).await?;
    }
    if !external_id.is_unchanged() {
        ensure_group_external_id_available(&ctx, external_id.to_stored().as_ref(), Some(&group.uuid), &conn).await?;
    }
    if let Some(members) = &members {
        resolve_members(&ctx, members, &conn).await?;
    }

    let metadata_changed = apply_group_metadata(&mut group, display_name, &external_id);

    // One transaction for the row and the membership: a failure persisting members must not
    // leave `displayName` or `externalId` changed.
    let outcome = group.save_with_members(false, metadata_changed, members, &conn).await?;

    if outcome.changed {
        log_group_changes(&ctx, &token, &group, EventType::GroupUpdated, &outcome, &conn).await;
    }

    let projection = AttributeProjection::none();
    let body = render_group(&ctx, &group, &projection, &conn).await;
    Ok(ScimResponse::resource(body, ctx.resource_location("Group", &group.uuid)))
}

#[patch("/<org_id>/Groups/<group_id>", data = "<body>")]
async fn patch_group(
    org_id: &str,
    group_id: &str,
    body: ScimBody<PatchRequest>,
    token: ScimToken,
    conn: DbConn,
) -> ScimResult<ScimResponse> {
    ensure_groups_enabled()?;
    let ctx = ScimContext::resolve(&token, org_id)?;
    let request = body.into_inner()?;
    let mut group = load_group(&ctx, group_id, &conn).await?;

    // Plan the whole document first. A single unsupported operation fails the request with
    // nothing applied.
    let changes = plan_group_patch(&request)?;

    if let Some(display_name) = &changes.display_name {
        ensure_display_name_available(&ctx, display_name, Some(&group.uuid), &conn).await?;
    }
    if !changes.external_id.is_unchanged() {
        ensure_group_external_id_available(&ctx, changes.external_id.to_stored().as_ref(), Some(&group.uuid), &conn)
            .await?;
    }
    // Validate every referenced membership against this organization before any write.
    resolve_members(&ctx, &changes.referenced_members(), &conn).await?;

    let new_members = if changes.touches_members() {
        let current = current_members(&ctx, &group.uuid, &conn).await;
        let resulting = apply_member_ops(&current, &changes.member_ops);

        // The resulting membership is bounded too, not just the request that produced it, so a
        // sequence of small `add` operations cannot grow a group past the limit.
        if resulting.len() > MAX_MEMBERS_PER_REQUEST {
            return Err(ScimError::bad_request(
                ScimType::TooMany,
                format!("A group may not exceed {MAX_MEMBERS_PER_REQUEST} members."),
            ));
        }
        Some(resulting)
    } else {
        None
    };

    let metadata_changed = apply_group_metadata(&mut group, changes.display_name, &changes.external_id);

    let outcome = group.save_with_members(false, metadata_changed, new_members, &conn).await?;

    if outcome.changed {
        log_group_changes(&ctx, &token, &group, EventType::GroupUpdated, &outcome, &conn).await;
    }

    let projection = AttributeProjection::none();
    let body = render_group(&ctx, &group, &projection, &conn).await;
    Ok(ScimResponse::resource(body, ctx.resource_location("Group", &group.uuid)))
}

// ---------------------------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------------------------

/// Delete the group and its assignments. The members themselves keep their organization
/// membership; only the grouping goes away.
#[delete("/<org_id>/Groups/<group_id>")]
async fn delete_group(org_id: &str, group_id: &str, token: ScimToken, conn: DbConn) -> ScimResult<ScimResponse> {
    ensure_groups_enabled()?;
    let ctx = ScimContext::resolve(&token, org_id)?;
    let group = load_group(&ctx, group_id, &conn).await?;

    // Delete first, then record it: an event claiming the group was deleted must not outlive a
    // delete that failed.
    let group_uuid = group.uuid.clone();
    group.delete(&ctx.org_id, &conn).await?;

    log_event(
        EventType::GroupDeleted,
        &group_uuid,
        &ctx.org_id,
        &ACTING_SCIM_USER.into(),
        SCIM_DEVICE_TYPE,
        &token.ip,
        &conn,
    )
    .await;

    Ok(ScimResponse::no_content())
}
