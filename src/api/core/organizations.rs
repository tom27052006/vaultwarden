use std::collections::{HashMap, HashSet};

use num_traits::FromPrimitive;
use rocket::{Route, http::Status, serde::json::Json};
use serde_json::Value;

use crate::{
    CONFIG,
    api::admin::FAKE_ADMIN_UUID,
    api::{
        EmptyResult, JsonResult, Notify, PasswordOrOtpData, UpdateType,
        core::{CipherSyncData, CipherSyncType, accept_org_invite, log_event, two_factor},
    },
    auth::{
        AccessImportExportHeaders, AdminHeaders, CollectionDeleteHeaders, CollectionReadHeaders, Headers,
        ManageGroupsHeaders, ManagePoliciesHeaders, ManageUsersHeaders, ManagerHeaders, ManagerHeadersLoose,
        OrgMemberHeaders, OwnerHeaders, can_read_collection_access, decode_invite,
    },
    db::{
        DbConn,
        models::{
            Cipher, CipherId, Collection, CollectionCipher, CollectionGroup, CollectionId, CollectionUser, EventType,
            Group, GroupId, GroupUser, Invitation, Membership, MembershipId, MembershipStatus, MembershipType,
            OrgPolicy, OrgPolicyType, Organization, OrganizationApiKey, OrganizationId, TwoFactor, TwoFactorType, User,
            UserId,
        },
    },
    mail,
    sso::FAKE_SSO_IDENTIFIER,
    util::{NumberOrString, convert_json_key_lcase_first},
};

pub fn routes() -> Vec<Route> {
    routes![
        get_organization,
        create_organization,
        delete_organization,
        post_delete_organization,
        leave_organization,
        get_user_collections,
        get_org_collections,
        get_org_collections_details,
        get_org_collection_detail,
        get_collection_users,
        put_organization,
        post_organization,
        post_organization_collections,
        post_bulk_access_collections,
        post_organization_collection_update,
        put_organization_collection_update,
        delete_organization_collection,
        post_organization_collection_delete,
        bulk_delete_organization_collections,
        post_bulk_collections,
        get_assigned_org_details,
        get_org_details,
        get_org_domain_sso_verified,
        get_members,
        send_invite,
        reinvite_member,
        bulk_reinvite_members,
        confirm_invite,
        bulk_confirm_invite,
        accept_invite,
        get_org_user_mini_details,
        get_user,
        edit_member,
        put_member,
        delete_member,
        bulk_delete_member,
        post_org_import,
        list_policies,
        list_policies_token,
        get_dummy_master_password_policy,
        get_master_password_policy,
        get_policy,
        put_policy,
        put_policy_vnext,
        get_plans,
        post_org_keys,
        get_organization_keys,
        get_organization_public_key,
        bulk_public_keys,
        revoke_member,
        bulk_revoke_members,
        restore_member,
        restore_member_vnext,
        bulk_restore_members,
        get_groups,
        get_groups_details,
        post_groups,
        get_group,
        put_group,
        post_group,
        get_group_details,
        delete_group,
        post_delete_group,
        bulk_delete_groups,
        get_group_members,
        put_group_members,
        post_delete_group_member,
        put_reset_password_enrollment,
        get_reset_password_details,
        put_reset_password,
        put_recover_account,
        get_org_export,
        post_api_key,
        rotate_api_key,
        get_billing_metadata,
        get_billing_warnings,
        get_auto_enroll_status,
        get_self_host_billing_metadata,
    ]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgData {
    billing_email: String,
    collection_name: String,
    key: String,
    name: String,
    keys: Option<OrgKeyData>,
    #[allow(dead_code)]
    plan_type: NumberOrString, // Ignored, always use the same plan
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OrganizationUpdateData {
    billing_email: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullCollectionData {
    name: String,
    groups: Vec<CollectionGroupData>,
    users: Vec<CollectionMembershipData>,
    external_id: Option<String>,
}

fn validate_collection_access(manage: bool, read_only: bool, hide_passwords: bool) -> EmptyResult {
    if manage && (read_only || hide_passwords) {
        err!(
            "The Manage property is mutually exclusive and cannot be true while the ReadOnly or HidePasswords properties are also true."
        )
    }
    Ok(())
}

impl FullCollectionData {
    pub async fn validate(&self, org_id: &OrganizationId, conn: &DbConn) -> EmptyResult {
        for group in &self.groups {
            validate_collection_access(group.manage, group.read_only, group.hide_passwords)?;
        }
        for user in &self.users {
            validate_collection_access(user.manage, user.read_only, user.hide_passwords)?;
        }

        let org_groups = Group::find_by_organization(org_id, conn).await;
        let org_group_ids: HashSet<&GroupId> = org_groups.iter().map(|c| &c.uuid).collect();
        if let Some(e) = self.groups.iter().find(|g| !org_group_ids.contains(&g.id)) {
            err!("Invalid group", format!("Group {} does not belong to organization {}!", e.id, org_id))
        }

        let org_memberships = Membership::find_by_org(org_id, conn).await;
        let org_membership_ids: HashSet<&MembershipId> = org_memberships.iter().map(|m| &m.uuid).collect();
        if let Some(e) = self.users.iter().find(|m| !org_membership_ids.contains(&m.id)) {
            err!("Invalid member", format!("Member {} does not belong to organization {}!", e.id, org_id))
        }

        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectionGroupData {
    hide_passwords: bool,
    id: GroupId,
    read_only: bool,
    manage: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectionMembershipData {
    hide_passwords: bool,
    id: MembershipId,
    read_only: bool,
    manage: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgKeyData {
    encrypted_private_key: String,
    public_key: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BulkGroupIds {
    ids: Vec<GroupId>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BulkMembershipIds {
    ids: Vec<MembershipId>,
}

#[post("/organizations", data = "<data>")]
async fn create_organization(headers: Headers, data: Json<OrgData>, conn: DbConn) -> JsonResult {
    if !CONFIG.is_org_creation_allowed(&headers.user.email) {
        err!("User not allowed to create organizations")
    }
    if OrgPolicy::is_applicable_to_user(&headers.user.uuid, OrgPolicyType::SingleOrg, None, &conn).await {
        err!(
            "You may not create an organization. You belong to an organization which has a policy that prohibits you from being a member of any other organization."
        )
    }

    let data: OrgData = data.into_inner();
    let (private_key, public_key) = if let Some(keys) = data.keys {
        (Some(keys.encrypted_private_key), Some(keys.public_key))
    } else {
        (None, None)
    };

    let org = Organization::new(data.name, &data.billing_email, private_key, public_key);
    let mut member = Membership::new(headers.user.uuid, org.uuid.clone(), None);
    let collection = Collection::new(org.uuid.clone(), data.collection_name, None);

    member.akey = data.key;
    member.atype = MembershipType::Owner as i32;
    member.status = MembershipStatus::Confirmed as i32;

    org.save(&conn).await?;
    member.save(&conn).await?;
    collection.save(&conn).await?;

    Ok(Json(org.to_json()))
}

#[delete("/organizations/<org_id>", data = "<data>")]
async fn delete_organization(
    org_id: OrganizationId,
    data: Json<PasswordOrOtpData>,
    headers: OwnerHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: PasswordOrOtpData = data.into_inner();

    data.validate(&headers.user, true, &conn).await?;

    match Organization::find_by_uuid(&org_id, &conn).await {
        None => err!("Organization not found"),
        Some(org) => org.delete(&conn).await,
    }
}

#[post("/organizations/<org_id>/delete", data = "<data>")]
async fn post_delete_organization(
    org_id: OrganizationId,
    data: Json<PasswordOrOtpData>,
    headers: OwnerHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_organization(org_id, data, headers, conn).await
}

#[post("/organizations/<org_id>/leave")]
async fn leave_organization(org_id: OrganizationId, headers: OrgMemberHeaders, conn: DbConn) -> EmptyResult {
    if headers.membership.status != MembershipStatus::Confirmed as i32 {
        err!("You need to be a Member of the Organization to call this endpoint")
    }
    let membership = headers.membership;

    if membership.atype == MembershipType::Owner
        && Membership::count_confirmed_by_org_and_type(&org_id, MembershipType::Owner, &conn).await <= 1
    {
        err!("The last owner can't leave")
    }

    log_event(
        EventType::OrganizationUserLeft,
        &membership.uuid,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    membership.delete(&conn).await
}

#[get("/organizations/<org_id>")]
async fn get_organization(org_id: OrganizationId, headers: OwnerHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if let Some(organization) = Organization::find_by_uuid(&org_id, &conn).await {
        Ok(Json(organization.to_json()))
    } else {
        err!("Can't find organization details")
    }
}

#[put("/organizations/<org_id>", data = "<data>")]
async fn put_organization(
    org_id: OrganizationId,
    headers: OwnerHeaders,
    data: Json<OrganizationUpdateData>,
    conn: DbConn,
) -> JsonResult {
    post_organization(org_id, headers, data, conn).await
}

#[post("/organizations/<org_id>", data = "<data>")]
async fn post_organization(
    org_id: OrganizationId,
    headers: OwnerHeaders,
    data: Json<OrganizationUpdateData>,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let data: OrganizationUpdateData = data.into_inner();

    let Some(mut org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err!("Organization not found")
    };

    org.name = data.name;
    org.billing_email = data.billing_email.to_lowercase();

    org.save(&conn).await?;

    log_event(
        EventType::OrganizationUpdated,
        org_id.as_ref(),
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    Ok(Json(org.to_json()))
}

// GET /api/collections?writeOnly=false
#[get("/collections")]
async fn get_user_collections(headers: Headers, conn: DbConn) -> Json<Value> {
    Json(json!({
        "data":
            Collection::find_by_user_uuid(headers.user.uuid, &conn).await
            .iter()
            .map(Collection::to_json)
            .collect::<Value>(),
        "object": "list",
        "continuationToken": null,
    }))
}

// Called during the SSO enrollment
// The `identifier` should be the value returned by `get_org_domain_sso_verified`
// The returned `Id` will then be passed to `get_master_password_policy` which will mainly ignore it
#[get("/organizations/<identifier>/auto-enroll-status")]
async fn get_auto_enroll_status(identifier: &str, headers: Headers, conn: DbConn) -> JsonResult {
    let org = if identifier == FAKE_SSO_IDENTIFIER {
        match Membership::find_main_user_org(&headers.user.uuid, &conn).await {
            Some(member) => Organization::find_by_uuid(&member.org_uuid, &conn).await,
            None => None,
        }
    } else {
        Organization::find_by_uuid(&identifier.into(), &conn).await
    };

    let (id, identifier, rp_auto_enroll) = match org {
        None => (identifier.to_owned(), identifier.to_owned(), false),
        Some(org) => (
            org.uuid.to_string(),
            org.uuid.to_string(),
            OrgPolicy::org_is_reset_password_auto_enroll(&org.uuid, &conn).await,
        ),
    };

    Ok(Json(json!({
        "id": id,
        "identifier": identifier,
        "resetPasswordEnabled": rp_auto_enroll,
    })))
}

#[get("/organizations/<org_id>/collections")]
async fn get_org_collections(org_id: OrganizationId, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }

    let can_read_all = may_read_all_collections(&headers.membership);
    let all_collections = Collection::find_by_organization(&org_id, &conn).await;
    let collections = if can_read_all {
        all_collections
    } else {
        let mut explicitly_managed = Vec::new();
        for collection in all_collections {
            if headers.membership.has_explicit_collection_manage_access(&collection.uuid, &conn).await {
                explicitly_managed.push(collection);
            }
        }
        explicitly_managed
    };
    Ok(Json(json!({
        "data": collections.iter().map(Collection::to_json).collect::<Value>(),
        "object": "list",
        "continuationToken": null,
    })))
}

#[get("/organizations/<org_id>/collections/details")]
async fn get_org_collections_details(org_id: OrganizationId, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }

    let Some(member) = Membership::find_by_user_and_org(&headers.user.uuid, &org_id, &conn).await else {
        err!("User is not part of organization")
    };

    // get all collection memberships for the current organization
    let col_users = CollectionUser::find_by_organization_swap_user_uuid_with_member_uuid(&org_id, &conn).await;
    // Generate a HashMap to get the correct MembershipType per user to determine the manage permission
    // We use the uuid instead of the user_uuid here, since that is what is used in CollectionUser
    let membership_type: HashMap<MembershipId, i32> =
        Membership::find_confirmed_by_org(&org_id, &conn).await.into_iter().map(|m| (m.uuid, m.atype)).collect();

    // check if current user has full access to the organization (either directly or via any group)
    let has_full_access_to_org = member.has_full_access()
        || (CONFIG.org_groups_enabled() && GroupUser::has_full_access_by_member(&org_id, &member.uuid, &conn).await);

    let can_read_all_access_details = may_read_all_collections_with_access(&member);
    // Get all admins, owners and managers who can manage/access all
    // Those are currently not listed in the col_users but need to be listed too.
    let manage_all_members: Vec<Value> = Membership::find_confirmed_and_manage_all_by_org(&org_id, &conn)
        .await
        .into_iter()
        .map(|member| {
            json!({
                "id": member.uuid,
                "readOnly": false,
                "hidePasswords": false,
                "manage": true,
            })
        })
        .collect();

    let mut data = Vec::new();
    for col in Collection::find_by_organization(&org_id, &conn).await {
        // check whether the current user has access to the given collection
        let assigned = has_full_access_to_org
            || CollectionUser::has_access_to_collection_by_user(&col.uuid, &member.user_uuid, &conn).await
            || (CONFIG.org_groups_enabled()
                && GroupUser::has_access_to_collection_by_member(&col.uuid, &member.uuid, &conn).await);

        if !can_read_all_access_details && !can_read_collection_access(&member, &col.uuid, &conn).await {
            continue;
        }

        let mut users: Vec<Value> = col_users
            .iter()
            .filter(|collection_member| collection_member.collection_uuid == col.uuid)
            .map(|collection_member| {
                collection_member.to_json_details_for_member(
                    *membership_type.get(&collection_member.membership_uuid).unwrap_or(&(MembershipType::User as i32)),
                )
            })
            .collect();
        users.extend_from_slice(&manage_all_members);

        let groups: Vec<Value> = if CONFIG.org_groups_enabled() {
            CollectionGroup::find_by_collection(&col.uuid, &conn)
                .await
                .iter()
                .map(CollectionGroup::to_json_details_for_group)
                .collect()
        } else {
            Vec::new()
        };

        let mut json_object = col.to_json_details(&headers.user.uuid, None, &conn).await;
        json_object["assigned"] = json!(assigned);
        json_object["users"] = json!(users);
        json_object["groups"] = json!(groups);
        json_object["object"] = json!("collectionAccessDetails");
        json_object["unmanaged"] = json!(false);
        data.push(json_object);
    }

    Ok(Json(json!({
        "data": data,
        "object": "list",
        "continuationToken": null,
    })))
}

fn may_read_all_collections(member: &Membership) -> bool {
    member.has_full_access()
        || member.has_manage_groups()
        || member.has_delete_any_collection()
        || member.has_access_import_export()
}

fn may_read_all_collections_with_access(member: &Membership) -> bool {
    member.has_full_access()
        || member.has_delete_any_collection()
        || member.has_manage_users()
        || member.has_manage_groups()
}

#[post("/organizations/<org_id>/collections", data = "<data>")]
async fn post_organization_collections(
    org_id: OrganizationId,
    headers: ManagerHeadersLoose,
    data: Json<FullCollectionData>,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }

    // Create is independent from Edit/Delete. In particular, Edit any collection (full access to
    // every collection) must not implicitly grant this endpoint.
    if !headers.membership.can_create_new_collections() {
        err!("You don't have permission to create collections")
    }

    let data: FullCollectionData = data.into_inner();
    data.validate(&org_id, &conn).await?;

    let collection = Collection::new(org_id.clone(), data.name, data.external_id);
    collection.save(&conn).await?;

    for group in data.groups {
        CollectionGroup::new(collection.uuid.clone(), group.id, group.read_only, group.hide_passwords, group.manage)
            .save(&org_id, &conn)
            .await?;
    }

    for user in data.users {
        let Some(member) = Membership::find_by_uuid_and_org(&user.id, &org_id, &conn).await else {
            err!("User is not part of organization")
        };

        if member.grants_access_to_all_collections() {
            continue;
        }

        CollectionUser::save(
            &member.user_uuid,
            &collection.uuid,
            user.read_only,
            user.hide_passwords,
            user.manage,
            &conn,
        )
        .await?;
    }

    log_event(
        EventType::CollectionCreated,
        &collection.uuid,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    Ok(Json(collection.to_json_details(&headers.membership.user_uuid, None, &conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkCollectionAccessData {
    collection_ids: Vec<CollectionId>,
    groups: Vec<CollectionGroupData>,
    users: Vec<CollectionMembershipData>,
}

#[post("/organizations/<org_id>/collections/bulk-access", data = "<data>", rank = 1)]
async fn post_bulk_access_collections(
    org_id: OrganizationId,
    headers: ManagerHeadersLoose,
    data: Json<BulkCollectionAccessData>,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: BulkCollectionAccessData = data.into_inner();

    for group in &data.groups {
        validate_collection_access(group.manage, group.read_only, group.hide_passwords)?;
    }
    for user in &data.users {
        validate_collection_access(user.manage, user.read_only, user.hide_passwords)?;
    }

    if Organization::find_by_uuid(&org_id, &conn).await.is_none() {
        err!("Can't find organization details")
    }

    // Security: authorization is per collection below, via the same `auth::can_edit_collection` the
    // single-collection edit endpoint uses — a body-param endpoint cannot use `ManagerHeaders`, and the
    // two must not diverge. Group `access_all` deliberately does not satisfy it (the previous
    // `is_manageable_by_user` check accepted it, and disagreed with the single-edit endpoint).

    // Security and atomicity: validate the whole request against this organization before mutating
    // anything — every collection, group and user must belong to it and be manageable by the caller.
    // Only then does the destructive delete/replace begin, so a foreign-tenant group can never be linked
    // and a later invalid element cannot leave earlier collections already wiped.
    let org_groups = Group::find_by_organization(&org_id, &conn).await;
    let org_group_ids: HashSet<&GroupId> = org_groups.iter().map(|g| &g.uuid).collect();
    if let Some(g) = data.groups.iter().find(|g| !org_group_ids.contains(&g.id)) {
        err!("Invalid group", format!("Group {} does not belong to organization {}!", g.id, org_id))
    }
    for user in &data.users {
        if Membership::find_by_uuid_and_org(&user.id, &org_id, &conn).await.is_none() {
            err!("User is not part of organization")
        }
    }
    let mut collections = Vec::with_capacity(data.collection_ids.len());
    for col_id in &data.collection_ids {
        let Some(collection) = Collection::find_by_uuid_and_org(col_id, &org_id, &conn).await else {
            err!("Collection not found")
        };

        if !crate::auth::can_edit_collection(&headers.membership, &collection.uuid, &conn).await {
            err!("Collection not found", "The current user isn't a manager for this collection")
        }

        collections.push(collection);
    }

    for collection in collections {
        let col_id = &collection.uuid;

        // update collection modification date
        collection.save(&conn).await?;

        log_event(
            EventType::CollectionUpdated,
            &collection.uuid,
            &org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &conn,
        )
        .await;

        CollectionGroup::delete_all_by_collection(col_id, &org_id, &conn).await?;
        for group in &data.groups {
            CollectionGroup::new(col_id.clone(), group.id.clone(), group.read_only, group.hide_passwords, group.manage)
                .save(&org_id, &conn)
                .await?;
        }

        CollectionUser::delete_all_by_collection(col_id, &conn).await?;
        for user in &data.users {
            let Some(member) = Membership::find_by_uuid_and_org(&user.id, &org_id, &conn).await else {
                err!("User is not part of organization")
            };

            if member.grants_access_to_all_collections() {
                continue;
            }

            CollectionUser::save(&member.user_uuid, col_id, user.read_only, user.hide_passwords, user.manage, &conn)
                .await?;
        }
    }

    Ok(())
}

#[put("/organizations/<org_id>/collections/<col_id>", data = "<data>")]
async fn put_organization_collection_update(
    org_id: OrganizationId,
    col_id: CollectionId,
    headers: ManagerHeaders,
    data: Json<FullCollectionData>,
    conn: DbConn,
) -> JsonResult {
    post_organization_collection_update(org_id, col_id, headers, data, conn).await
}

#[post("/organizations/<org_id>/collections/<col_id>", data = "<data>", rank = 2)]
async fn post_organization_collection_update(
    org_id: OrganizationId,
    col_id: CollectionId,
    headers: ManagerHeaders,
    data: Json<FullCollectionData>,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: FullCollectionData = data.into_inner();
    data.validate(&org_id, &conn).await?;

    if Organization::find_by_uuid(&org_id, &conn).await.is_none() {
        err!("Can't find organization details")
    }

    let Some(mut collection) = Collection::find_by_uuid_and_org(&col_id, &org_id, &conn).await else {
        err!("Collection not found")
    };

    collection.name = data.name;
    collection.external_id = match data.external_id {
        Some(external_id) if !external_id.trim().is_empty() => Some(external_id),
        _ => None,
    };

    collection.save(&conn).await?;

    log_event(
        EventType::CollectionUpdated,
        &collection.uuid,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    CollectionGroup::delete_all_by_collection(&col_id, &org_id, &conn).await?;

    for group in data.groups {
        CollectionGroup::new(col_id.clone(), group.id, group.read_only, group.hide_passwords, group.manage)
            .save(&org_id, &conn)
            .await?;
    }

    CollectionUser::delete_all_by_collection(&col_id, &conn).await?;

    for user in data.users {
        let Some(member) = Membership::find_by_uuid_and_org(&user.id, &org_id, &conn).await else {
            err!("User is not part of organization")
        };

        if member.grants_access_to_all_collections() {
            continue;
        }

        CollectionUser::save(&member.user_uuid, &col_id, user.read_only, user.hide_passwords, user.manage, &conn)
            .await?;
    }

    Ok(Json(collection.to_json_details(&headers.user.uuid, None, &conn).await))
}

async fn delete_organization_collection_impl(
    org_id: &OrganizationId,
    col_id: &CollectionId,
    headers: &CollectionDeleteHeaders,
    conn: &DbConn,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(collection) = Collection::find_by_uuid_and_org(col_id, org_id, conn).await else {
        err!("Collection not found", "Collection does not exist or does not belong to this organization")
    };
    log_event(
        EventType::CollectionDeleted,
        &collection.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;
    collection.delete(conn).await
}

#[delete("/organizations/<org_id>/collections/<col_id>")]
async fn delete_organization_collection(
    org_id: OrganizationId,
    col_id: CollectionId,
    headers: CollectionDeleteHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_organization_collection_impl(&org_id, &col_id, &headers, &conn).await
}

#[post("/organizations/<org_id>/collections/<col_id>/delete")]
async fn post_organization_collection_delete(
    org_id: OrganizationId,
    col_id: CollectionId,
    headers: CollectionDeleteHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_organization_collection_impl(&org_id, &col_id, &headers, &conn).await
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BulkCollectionIds {
    ids: Vec<CollectionId>,
}

#[delete("/organizations/<org_id>/collections", data = "<data>")]
async fn bulk_delete_organization_collections(
    org_id: OrganizationId,
    headers: ManagerHeadersLoose,
    data: Json<BulkCollectionIds>,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: BulkCollectionIds = data.into_inner();

    let collections = data.ids;

    let headers = CollectionDeleteHeaders::from_loose(headers, &collections, &conn).await?;

    for col_id in collections {
        delete_organization_collection_impl(&org_id, &col_id, &headers, &conn).await?;
    }
    Ok(())
}

#[get("/organizations/<org_id>/collections/<col_id>/details")]
async fn get_org_collection_detail(
    org_id: OrganizationId,
    col_id: CollectionId,
    headers: CollectionReadHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    match Collection::find_by_uuid_and_org(&col_id, &org_id, &conn).await {
        None => err!("Collection not found"),
        Some(collection) => {
            if collection.org_uuid != org_id {
                err!("Collection is not owned by organization")
            }

            let groups: Vec<Value> = if CONFIG.org_groups_enabled() {
                CollectionGroup::find_by_collection(&collection.uuid, &conn)
                    .await
                    .iter()
                    .map(CollectionGroup::to_json_details_for_group)
                    .collect()
            } else {
                // The Bitwarden clients seem to call this API regardless of whether groups are enabled,
                // so just act as if there are no groups.
                Vec::new()
            };

            // Generate a HashMap to get the correct MembershipType per user to determine the manage permission
            // We use the uuid instead of the user_uuid here, since that is what is used in CollectionUser
            let membership_type: HashMap<MembershipId, i32> = Membership::find_confirmed_by_org(&org_id, &conn)
                .await
                .into_iter()
                .map(|m| (m.uuid, m.atype))
                .collect();

            let users: Vec<Value> =
                CollectionUser::find_by_org_and_coll_swap_user_uuid_with_member_uuid(&org_id, &collection.uuid, &conn)
                    .await
                    .iter()
                    .map(|collection_member| {
                        collection_member.to_json_details_for_member(
                            *membership_type
                                .get(&collection_member.membership_uuid)
                                .unwrap_or(&(MembershipType::User as i32)),
                        )
                    })
                    .collect();

            let assigned = Collection::can_access_collection(&headers.membership, &collection.uuid, &conn).await;

            let mut json_object = collection.to_json_details(&headers.user.uuid, None, &conn).await;
            json_object["assigned"] = json!(assigned);
            json_object["users"] = json!(users);
            json_object["groups"] = json!(groups);
            json_object["object"] = json!("collectionAccessDetails");

            Ok(Json(json_object))
        }
    }
}

#[get("/organizations/<org_id>/collections/<col_id>/users")]
async fn get_collection_users(
    org_id: OrganizationId,
    col_id: CollectionId,
    headers: CollectionReadHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    // Get org and collection, check that collection is from org
    let Some(collection) = Collection::find_by_uuid_and_org(&col_id, &org_id, &conn).await else {
        err!("Collection not found in Organization")
    };

    let mut member_list = Vec::new();
    for col_user in CollectionUser::find_by_collection(&collection.uuid, &conn).await {
        member_list.push(
            Membership::find_by_user_and_org(&col_user.user_uuid, &org_id, &conn)
                .await
                .unwrap()
                .to_json_user_access_restrictions(&col_user),
        );
    }

    Ok(Json(json!(member_list)))
}

#[derive(FromForm)]
struct OrgIdData {
    #[field(name = "organizationId")]
    organization_id: OrganizationId,
}

fn filter_ciphers_for_organization(ciphers: Vec<Cipher>, org_id: &OrganizationId) -> Vec<Cipher> {
    ciphers.into_iter().filter(|cipher| cipher.organization_uuid.as_ref() == Some(org_id)).collect()
}

// The Admin Console calls this when the acting member may not read every cipher: DeleteAnyCollection
// alone needs an empty successful response so the collection list can finish loading.
//
// Security: start from the regular user-visible cipher query and constrain it to the requested
// organization. DeleteAnyCollection must never make cipher contents visible.
#[get("/ciphers/organization-details/assigned?<data..>")]
async fn get_assigned_org_details(data: OrgIdData, headers: Headers, conn: DbConn) -> JsonResult {
    if Membership::find_confirmed_by_user_and_org(&headers.user.uuid, &data.organization_id, &conn).await.is_none() {
        err_code!("Resource not found.", "User is not a confirmed member of the organization", Status::NotFound.code);
    }

    Ok(Json(json!({
        "data": assigned_org_ciphers_json(&data.organization_id, &headers.host, &headers.user.uuid, &conn).await?,
        "object": "list",
        "continuationToken": null,
    })))
}

// Serialize exactly the organization ciphers the user is actually assigned to, directly or via a group.
// `CipherSyncType::User` keeps the per-cipher access restrictions in place, so nothing outside the
// caller's own collections is returned and every cipher carries its real `edit`/`viewPassword` flags.
// NOTE: as everywhere else in Vaultwarden (and Bitwarden), `hidePasswords` is reported as
// `viewPassword: false` rather than redacted server-side, so this returns exactly what the same member
// already receives from `/api/sync` -- never more.
async fn assigned_org_ciphers_json(
    org_id: &OrganizationId,
    host: &str,
    user_id: &UserId,
    conn: &DbConn,
) -> Result<Value, crate::Error> {
    let ciphers = filter_ciphers_for_organization(Cipher::find_by_user_visible(user_id, conn).await, org_id);
    let cipher_sync_data = CipherSyncData::new(user_id, CipherSyncType::User, conn).await;

    let mut ciphers_json = Vec::with_capacity(ciphers.len());
    for cipher in ciphers {
        ciphers_json.push(cipher.to_json(host, user_id, Some(&cipher_sync_data), CipherSyncType::User, conn).await?);
    }

    Ok(Value::Array(ciphers_json))
}

// The organization cipher list the clients use for the admin vault view and for computing reports
// locally. Bitwarden grants the complete organization scope to AccessReports and AccessImportExport.
#[get("/ciphers/organization-details?<data..>")]
async fn get_org_details(data: OrgIdData, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    if data.organization_id != headers.membership.org_uuid {
        err_code!("Resource not found.", "Organization id's do not match", Status::NotFound.code);
    }

    let ciphers_json = match organization_report_scope(&headers.membership) {
        OrganizationReportScope::Complete => {
            get_org_details_impl(&data.organization_id, &headers.host, &headers.user.uuid, &conn).await?
        }
        OrganizationReportScope::Denied => {
            err_code!(
                "Resource not found.",
                "User does not have permission to read the organization ciphers",
                Status::NotFound.code
            );
        }
    };

    Ok(Json(json!({
        "data": ciphers_json,
        "object": "list",
        "continuationToken": null,
    })))
}

async fn get_org_details_impl(
    org_id: &OrganizationId,
    host: &str,
    user_id: &UserId,
    conn: &DbConn,
) -> Result<Value, crate::Error> {
    ciphers_to_org_json(Cipher::find_by_org(org_id, conn).await, org_id, host, user_id, conn).await
}

// Serialize an already-authorized set of organization ciphers. The caller decides which ciphers go
// in: `CipherSyncType::Organization` skips the per-cipher access restrictions, so this must never be
// handed a cipher the user is not allowed to see.
async fn ciphers_to_org_json(
    ciphers: Vec<Cipher>,
    org_id: &OrganizationId,
    host: &str,
    user_id: &UserId,
    conn: &DbConn,
) -> Result<Value, crate::Error> {
    let mut cipher_sync_data = CipherSyncData::new(user_id, CipherSyncType::Organization, conn).await;
    cipher_sync_data.cipher_collections =
        index_cipher_collections(Cipher::get_collections_with_cipher_by_organization(org_id, conn).await);

    let mut ciphers_json = Vec::with_capacity(ciphers.len());
    for c in ciphers {
        ciphers_json.push(c.to_json(host, user_id, Some(&cipher_sync_data), CipherSyncType::Organization, conn).await?);
    }
    Ok(json!(ciphers_json))
}

fn index_cipher_collections(relations: Vec<(CipherId, CollectionId)>) -> HashMap<CipherId, Vec<CollectionId>> {
    relations.into_iter().fold(HashMap::new(), |mut indexed, (cipher_id, collection_id)| {
        indexed.entry(cipher_id).or_default().push(collection_id);
        indexed
    })
}

// Returning a Domain/Organization here allow to prefill it and prevent prompting the user
// So we return a dummy value, since we only support a single SSO integration, and do not use the response anywhere
// In use since `v2025.6.0`, appears to use only the first `organizationIdentifier`
#[post("/organizations/domain/sso/verified")]
fn get_org_domain_sso_verified() -> JsonResult {
    // Always return a dummy value, no matter if SSO is enabled or not
    Ok(Json(json!({
        "object": "list",
        "data": [{
            "organizationIdentifier": FAKE_SSO_IDENTIFIER,
            // These appear to be unused
            "organizationName": FAKE_SSO_IDENTIFIER,
            "domainName": CONFIG.domain()
        }],
        "continuationToken": null
    })))
}

#[derive(FromForm)]
struct GetOrgUserData {
    #[field(name = "includeCollections")]
    include_collections: Option<bool>,
    #[field(name = "includeGroups")]
    include_groups: Option<bool>,
}

#[get("/organizations/<org_id>/users?<data..>")]
async fn get_members(
    data: GetOrgUserData,
    org_id: OrganizationId,
    // Security (audit M-1): the full member list exposes each member's PII, 2FA/enrollment status,
    // permission flags and (optionally) collection/group assignments. Reading it requires the
    // 'Manage Users' permission (or Admin/Owner), matching Bitwarden. Members who only need to
    // reference other users (e.g. the collection dialog) use the member-readable mini-details.
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let mut users_json = Vec::new();
    for u in Membership::find_by_org(&org_id, &conn).await {
        users_json.push(
            u.to_json_user_details(
                data.include_collections.unwrap_or(false),
                data.include_groups.unwrap_or(false),
                &conn,
            )
            .await,
        );
    }

    Ok(Json(json!({
        "data": users_json,
        "object": "list",
        "continuationToken": null,
    })))
}

#[post("/organizations/<org_id>/keys", data = "<data>")]
async fn post_org_keys(
    org_id: OrganizationId,
    data: Json<OrgKeyData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: OrgKeyData = data.into_inner();

    let mut org = if let Some(organization) = Organization::find_by_uuid(&org_id, &conn).await {
        if organization.private_key.is_some() && organization.public_key.is_some() {
            err!("Organization Keys already exist")
        }
        organization
    } else {
        err!("Can't find organization details")
    };

    org.private_key = Some(data.encrypted_private_key);
    org.public_key = Some(data.public_key);

    org.save(&conn).await?;

    Ok(Json(json!({
        "object": "organizationKeys",
        "publicKey": org.public_key,
        "privateKey": org.private_key,
    })))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
// This is intentionally a permission bitmap: every field represents an independent API grant.
#[allow(clippy::struct_excessive_bools)]
struct CustomRolePermissions {
    manage_users: bool,
    manage_groups: bool,
    manage_policies: bool,
    create_new_collections: bool,
    edit_any_collection: bool,
    delete_any_collection: bool,
    access_event_logs: bool,
    access_import_export: bool,
    access_reports: bool,
}

impl CustomRolePermissions {
    /// Read one known permission key.
    ///
    /// An absent key is `false`: the object is the complete set the caller wants. A key that *is* present
    /// must be a JSON boolean — treating `"true"`, `1` or `null` as "not `Value::Bool(true)`" turned a
    /// malformed request into a silent permission *removal* that still answered 200.
    fn read_known(permissions: &HashMap<String, Value>, key: &str) -> Result<bool, crate::Error> {
        match permissions.get(key) {
            None => Ok(false),
            Some(Value::Bool(value)) => Ok(*value),
            Some(other) => {
                let found = match other {
                    Value::Null => "null",
                    Value::String(_) => "a string",
                    Value::Number(_) => "a number",
                    Value::Array(_) => "an array",
                    Value::Object(_) => "an object",
                    Value::Bool(_) => unreachable!("booleans are handled above"),
                };
                err!(format!("Invalid permissions: '{key}' must be true or false, but is {found}"))
            }
        }
    }

    /// Parse a permissions object.
    ///
    /// Every known key is type-checked even when the role makes the flags inert, so a malformed request is
    /// rejected identically whatever role it names, and always before anything is mutated. Unknown keys are
    /// ignored: Bitwarden sends `manageSso`, `manageScim` and `manageResetPassword`, and rejecting them
    /// would break clients over permissions Vaultwarden does not implement.
    fn from_request(member_type: MembershipType, permissions: &HashMap<String, Value>) -> Result<Self, crate::Error> {
        let parsed = Self {
            manage_users: Self::read_known(permissions, "manageUsers")?,
            manage_groups: Self::read_known(permissions, "manageGroups")?,
            manage_policies: Self::read_known(permissions, "managePolicies")?,
            create_new_collections: Self::read_known(permissions, "createNewCollections")?,
            edit_any_collection: Self::read_known(permissions, "editAnyCollection")?,
            delete_any_collection: Self::read_known(permissions, "deleteAnyCollection")?,
            access_event_logs: Self::read_known(permissions, "accessEventLogs")?,
            access_import_export: Self::read_known(permissions, "accessImportExport")?,
            access_reports: Self::read_known(permissions, "accessReports")?,
        };

        if member_type == MembershipType::Custom {
            Ok(parsed)
        } else {
            Ok(Self::default())
        }
    }

    /// Whether the requested role/permissions give this member access to *every* collection in the
    /// org: Admins/Owners implicitly, and a Custom member holding Edit any collection. Such members
    /// do not need (and must not be given) individual per-collection assignments. Create and Delete
    /// remain completely independent of this.
    fn grants_full_collection_access(self, member_type: MembershipType) -> bool {
        member_type >= MembershipType::Admin || (member_type == MembershipType::Custom && self.edit_any_collection)
    }

    /// Parse permissions for an existing member without treating an omitted permissions object as
    /// an instruction to clear every Custom-role grant. Older clients send legacy role value `3`
    /// without the modern object; that value is normalized to Custom for compatibility.
    fn from_edit_request(
        member_type: MembershipType,
        permissions: Option<&HashMap<String, Value>>,
        membership: &Membership,
    ) -> Result<Self, crate::Error> {
        Ok(match permissions {
            Some(permissions) => Self::from_request(member_type, permissions)?,
            None if member_type == MembershipType::Custom && membership.atype == MembershipType::Custom as i32 => {
                Self {
                    manage_users: membership.manage_users,
                    manage_groups: membership.manage_groups,
                    manage_policies: membership.manage_policies,
                    create_new_collections: membership.create_new_collections,
                    edit_any_collection: membership.edit_any_collection,
                    delete_any_collection: membership.delete_any_collection,
                    access_event_logs: membership.access_event_logs,
                    access_import_export: membership.access_import_export,
                    access_reports: membership.access_reports,
                }
            }
            None => Self::default(),
        })
    }

    fn is_subset_of(self, caller: &Membership) -> bool {
        (!self.manage_users || caller.has_manage_users())
            && (!self.manage_groups || caller.has_manage_groups())
            && (!self.manage_policies || caller.has_manage_policies())
            && (!self.create_new_collections || caller.has_create_new_collections())
            && (!self.edit_any_collection || caller.has_edit_any_collection())
            && (!self.delete_any_collection || caller.has_delete_any_collection())
            && (!self.access_event_logs || caller.has_access_event_logs())
            && (!self.access_import_export || caller.has_access_import_export())
            && (!self.access_reports || caller.has_access_reports())
    }

    fn apply_to(self, membership: &mut Membership) {
        membership.manage_users = self.manage_users;
        membership.manage_groups = self.manage_groups;
        membership.manage_policies = self.manage_policies;
        membership.create_new_collections = self.create_new_collections;
        membership.edit_any_collection = self.edit_any_collection;
        membership.delete_any_collection = self.delete_any_collection;
        membership.access_event_logs = self.access_event_logs;
        membership.access_import_export = self.access_import_export;
        membership.access_reports = self.access_reports;
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InviteData {
    emails: Vec<String>,
    groups: Vec<GroupId>,
    r#type: NumberOrString,
    collections: Option<Vec<CollectionData>>,
    #[serde(default)]
    permissions: HashMap<String, Value>,
}

impl InviteData {
    async fn validate(&self, org_id: &OrganizationId, conn: &DbConn) -> EmptyResult {
        for collection in self.collections.iter().flatten() {
            validate_collection_access(collection.manage, collection.read_only, collection.hide_passwords)?;
        }

        let org_collections = Collection::find_by_organization(org_id, conn).await;
        let org_collection_ids: HashSet<&CollectionId> = org_collections.iter().map(|c| &c.uuid).collect();
        if let Some(e) = self.collections.iter().flatten().find(|c| !org_collection_ids.contains(&c.id)) {
            err!("Invalid collection", format!("Collection {} does not belong to organization {}!", e.id, org_id))
        }

        let org_groups = Group::find_by_organization(org_id, conn).await;
        let org_group_ids: HashSet<&GroupId> = org_groups.iter().map(|c| &c.uuid).collect();
        if let Some(e) = self.groups.iter().find(|g| !org_group_ids.contains(g)) {
            err!("Invalid group", format!("Group {} does not belong to organization {}!", e, org_id))
        }

        Ok(())
    }
}

#[post("/organizations/<org_id>/users/invite", data = "<data>")]
async fn send_invite(
    org_id: OrganizationId,
    data: Json<InviteData>,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: InviteData = data.into_inner();
    data.validate(&org_id, &conn).await?;

    let raw_type = &data.r#type.into_string();
    let Some(new_type) = MembershipType::from_str(raw_type) else {
        err!("Invalid type")
    };

    if !may_provision_member_type(headers.membership_type, new_type) {
        err!("You don't have permission to invite this role")
    }

    // manageAllCollections is a client-only aggregate; its three children are persisted independently.
    // Parsed and type-checked before the loop below creates any user, invitation or membership, so a
    // malformed value leaves nothing behind. Reaching every collection decides whether the individual
    // per-collection assignments below are skipped.
    let custom_permissions = CustomRolePermissions::from_request(new_type, &data.permissions)?;
    let grants_full_access = custom_permissions.grants_full_collection_access(new_type);

    if !may_grant_custom_permissions(&headers.membership, new_type, Some(custom_permissions)) {
        err!("Custom users can only grant the same custom permissions that they have")
    }

    if headers.membership_type == MembershipType::Custom {
        for group_id in &data.groups {
            if Group::find_by_uuid_and_org(group_id, &org_id, &conn).await.is_some_and(|group| group.access_all) {
                err!("Only Admins and Owners can add a member to a legacy access-all group")
            }
        }
    }

    for email in &data.emails {
        let mut member_status = MembershipStatus::Invited as i32;
        // Scoped to this iteration on purpose. A single flag hoisted out of the loop stays `true`
        // for every later recipient once any account has been created, so a failing invite mail to
        // an address that already had an account would delete that *existing* global user -- their
        // personal ciphers, devices, 2FA, emergency access and memberships in unrelated
        // organizations -- instead of only the membership this request just made.
        let mut user_created: bool = false;
        let user = match User::find_by_mail(email, &conn).await {
            None => {
                if !CONFIG.invitations_allowed() {
                    err!(format!("User does not exist: {email}"))
                }

                if !CONFIG.is_email_domain_allowed(email) {
                    err!("Email domain not eligible for invitations")
                }

                if !CONFIG.mail_enabled() {
                    Invitation::new(email).save(&conn).await?;
                }

                let mut new_user = User::new(email, None);
                new_user.save(&conn).await?;
                user_created = true;
                new_user
            }
            Some(user) => {
                if Membership::find_by_user_and_org(&user.uuid, &org_id, &conn).await.is_some() {
                    err!(format!("User already in organization: {email}"))
                }

                if !CONFIG.mail_enabled() {
                    if user.password_hash.is_empty() {
                        Invitation::new(email).save(&conn).await?;
                    } else {
                        // automatically accept existing users if mail is disabled
                        member_status = MembershipStatus::Accepted as i32;
                    }
                }
                user
            }
        };

        let mut new_member = Membership::new(user.uuid.clone(), org_id.clone(), Some(headers.user.email.clone()));
        new_member.atype = new_type as i32;
        custom_permissions.apply_to(&mut new_member);
        new_member.status = member_status;
        new_member.save(&conn).await?;

        if CONFIG.mail_enabled() {
            let org_name = if let Some(org) = Organization::find_by_uuid(&org_id, &conn).await {
                org.name
            } else {
                err!("Error looking up organization")
            };

            if let Err(e) = mail::send_invite(
                &user,
                org_id.clone(),
                new_member.uuid.clone(),
                &org_name,
                Some(headers.user.email.clone()),
            )
            .await
            {
                // Upon error delete the user, invite and org member records when needed
                if user_created {
                    user.delete(&conn).await?;
                } else {
                    new_member.delete(&conn).await?;
                }

                err!(format!("Error sending invite: {e:?} "));
            }
        }

        log_event(
            EventType::OrganizationUserInvited,
            &new_member.uuid,
            &org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &conn,
        )
        .await;

        // If the member does not already reach every collection, add the collections received
        if !grants_full_access {
            for col in data.collections.iter().flatten() {
                match Collection::find_by_uuid_and_org(&col.id, &org_id, &conn).await {
                    None => err!("Collection not found in Organization"),
                    Some(collection) => {
                        CollectionUser::save(
                            &user.uuid,
                            &collection.uuid,
                            col.read_only,
                            col.hide_passwords,
                            col.manage,
                            &conn,
                        )
                        .await?;
                    }
                }
            }
        }

        for group_id in &data.groups {
            let mut group_entry = GroupUser::new(group_id.clone(), new_member.uuid.clone());
            group_entry.save(&conn).await?;
        }
    }

    Ok(())
}

#[post("/organizations/<org_id>/users/reinvite", data = "<data>")]
async fn bulk_reinvite_members(
    org_id: OrganizationId,
    data: Json<BulkMembershipIds>,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: BulkMembershipIds = data.into_inner();

    let mut bulk_response = Vec::new();
    for member_id in data.ids {
        let err_msg = match reinvite_member_impl(&org_id, &member_id, &headers, &conn).await {
            Ok(()) => String::new(),
            Err(e) => format!("{e:?}"),
        };

        bulk_response.push(json!(
            {
                "object": "OrganizationBulkConfirmResponseModel",
                "id": member_id,
                "error": err_msg
            }
        ));
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

#[post("/organizations/<org_id>/users/<member_id>/reinvite")]
async fn reinvite_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    reinvite_member_impl(&org_id, &member_id, &headers, &conn).await
}

async fn reinvite_member_impl(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    headers: &ManageUsersHeaders,
    conn: &DbConn,
) -> EmptyResult {
    let Some(member) = Membership::find_by_uuid_and_org(member_id, org_id, conn).await else {
        err!("The user hasn't been invited to the organization.")
    };

    if !may_manage_stored_member_type(headers.membership_type, member.atype) {
        err!("You don't have permission to reinvite this user")
    }

    if member.status != MembershipStatus::Invited as i32 {
        err!("The user is already accepted or confirmed to the organization")
    }

    let Some(user) = User::find_by_uuid(&member.user_uuid, conn).await else {
        err!("User not found.")
    };

    if !CONFIG.invitations_allowed() && user.password_hash.is_empty() {
        err!("Invitations are not allowed.")
    }

    let org_name = if let Some(org) = Organization::find_by_uuid(org_id, conn).await {
        org.name
    } else {
        err!("Error looking up organization.")
    };

    if CONFIG.mail_enabled() {
        mail::send_invite(&user, org_id.clone(), member.uuid, &org_name, Some(headers.user.email.clone())).await?;
    } else if user.password_hash.is_empty() {
        let invitation = Invitation::new(&user.email);
        invitation.save(conn).await?;
    } else {
        Invitation::take(&user.email, conn).await;
        let mut member = member;
        member.status = MembershipStatus::Accepted as i32;
        member.save(conn).await?;
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcceptData {
    token: String,
    reset_password_key: Option<String>,
}

#[post("/organizations/<org_id>/users/<member_id>/accept", data = "<data>")]
async fn accept_invite(
    org_id: OrganizationId,
    member_id: MembershipId,
    data: Json<AcceptData>,
    headers: Headers,
    conn: DbConn,
) -> EmptyResult {
    // The web-vault passes org_id and member_id in the URL, but we are just reading them from the JWT instead
    let data: AcceptData = data.into_inner();
    let claims = decode_invite(&data.token)?;

    // Don't allow other users from accepting an invitation.
    if !claims.email.eq(&headers.user.email) {
        err!("Invitation was issued to a different account", "Claim does not match user_id")
    }

    // If a claim org_id does not match the one in from the URI, something is wrong.
    if !claims.org_id.eq(&org_id) {
        err!("Error accepting the invitation", "Claim does not match the org_id")
    }

    // If a claim does not have a member_id or it does not match the one in from the URI, something is wrong.
    if !claims.member_id.eq(&member_id) {
        err!("Error accepting the invitation", "Claim does not match the member_id")
    }

    let member_id = &claims.member_id;
    Invitation::take(&claims.email, &conn).await;

    // skip invitation logic when we were invited via the /admin panel
    if **member_id != FAKE_ADMIN_UUID {
        let Some(mut membership) = Membership::find_by_uuid_and_org(member_id, &claims.org_id, &conn).await else {
            err!("Error accepting the invitation")
        };

        let reset_password_key = match OrgPolicy::org_is_reset_password_auto_enroll(&membership.org_uuid, &conn).await {
            true if data.reset_password_key.is_none() => err!("Reset password key is required, but not provided."),
            true => data.reset_password_key,
            false => None,
        };

        // In case the user was invited before the mail was saved in db.
        membership.invited_by_email = membership.invited_by_email.or(claims.invited_by_email);

        accept_org_invite(&headers.user, membership, reset_password_key, &conn).await?;
    } else if CONFIG.mail_enabled() {
        // User was invited from /admin, so they are automatically confirmed
        let org_name = CONFIG.invitation_org_name();
        mail::send_invite_confirmed(&claims.email, &org_name).await?;
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfirmData {
    id: Option<MembershipId>,
    key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkConfirmData {
    keys: Option<Vec<ConfirmData>>,
}

#[post("/organizations/<org_id>/users/confirm", data = "<data>")]
async fn bulk_confirm_invite(
    org_id: OrganizationId,
    data: Json<BulkConfirmData>,
    headers: ManageUsersHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();

    let mut bulk_response = Vec::new();
    match data.keys {
        Some(keys) => {
            for invite in keys {
                // The id is request-controlled and optional. Unwrapping it aborted the worker with a 500 and, because
                // the panic unwound mid-loop, discarded the response for every entry already confirmed in the same
                // batch. Report it as a per-entry error, like an id that is present but empty.
                let Some(member_id) = invite.id else {
                    bulk_response.push(json!(
                        {
                            "object": "OrganizationBulkConfirmResponseModel",
                            "id": null,
                            "error": "Key or UserId is not set, unable to process request"
                        }
                    ));
                    continue;
                };
                let user_key = invite.key.unwrap_or_default();
                let err_msg = match confirm_invite_impl(&org_id, &member_id, &user_key, &headers, &conn, &nt).await {
                    Ok(()) => String::new(),
                    Err(e) => format!("{e:?}"),
                };

                bulk_response.push(json!(
                    {
                        "object": "OrganizationBulkConfirmResponseModel",
                        "id": member_id,
                        "error": err_msg
                    }
                ));
            }
        }
        None => error!("No keys to confirm"),
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

#[post("/organizations/<org_id>/users/<member_id>/confirm", data = "<data>")]
async fn confirm_invite(
    org_id: OrganizationId,
    member_id: MembershipId,
    data: Json<ConfirmData>,
    headers: ManageUsersHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let data = data.into_inner();
    let user_key = data.key.unwrap_or_default();
    confirm_invite_impl(&org_id, &member_id, &user_key, &headers, &conn, &nt).await
}

async fn confirm_invite_impl(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    key: &str,
    headers: &ManageUsersHeaders,
    conn: &DbConn,
    nt: &Notify<'_>,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if key.is_empty() || member_id.is_empty() {
        err!("Key or UserId is not set, unable to process request");
    }

    let Some(mut member_to_confirm) = Membership::find_by_uuid_and_org(member_id, org_id, conn).await else {
        err!("The specified user isn't a member of the organization")
    };

    if !may_provision_stored_member_type(headers.membership_type, member_to_confirm.atype) {
        err!("You don't have permission to confirm this user")
    }

    if member_to_confirm.status != MembershipStatus::Accepted as i32 {
        err!("User in invalid state")
    }

    member_to_confirm.status = MembershipStatus::Confirmed as i32;
    member_to_confirm.akey = key.to_owned();

    // This check is also done at accept_invite, _confirm_invite, _activate_member, edit_member, admin::update_membership_type
    OrgPolicy::check_user_allowed(&member_to_confirm, "confirm", conn).await?;

    log_event(
        EventType::OrganizationUserConfirmed,
        &member_to_confirm.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;

    if CONFIG.mail_enabled() {
        let org_name = if let Some(org) = Organization::find_by_uuid(org_id, conn).await {
            org.name
        } else {
            err!("Error looking up organization.")
        };
        let address = if let Some(user) = User::find_by_uuid(&member_to_confirm.user_uuid, conn).await {
            user.email
        } else {
            err!("Error looking up user.")
        };
        mail::send_invite_confirmed(&address, &org_name).await?;
    }

    let save_result = member_to_confirm.save(conn).await;

    if let Some(user) = User::find_by_uuid(&member_to_confirm.user_uuid, conn).await {
        nt.send_user_update(UpdateType::SyncOrgKeys, &user, headers.device.push_uuid.as_ref(), conn).await;
    }

    save_result
}

#[get("/organizations/<org_id>/users/mini-details", rank = 1)]
async fn get_org_user_mini_details(org_id: OrganizationId, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }

    let mut members_json = Vec::new();
    for m in Membership::find_by_org(&org_id, &conn).await {
        members_json.push(m.to_json_mini_details(&conn).await);
    }

    Ok(Json(json!({
        "data": members_json,
        "object": "list",
        "continuationToken": null,
    })))
}

#[get("/organizations/<org_id>/users/<member_id>?<data..>", rank = 2)]
async fn get_user(
    org_id: OrganizationId,
    member_id: MembershipId,
    data: GetOrgUserData,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(user) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err!("The specified user isn't a member of the organization")
    };

    // In this case, when groups are requested we also need to include collections.
    // Else these will not be shown in the interface, and could lead to missing collections when saved.
    let include_groups = data.include_groups.unwrap_or(false);
    Ok(Json(user.to_json_user_details(data.include_collections.unwrap_or(include_groups), include_groups, &conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EditUserData {
    r#type: NumberOrString,
    collections: Option<Vec<CollectionData>>,
    groups: Option<Vec<GroupId>>,
    permissions: Option<HashMap<String, Value>>,
}

#[put("/organizations/<org_id>/users/<member_id>", data = "<data>", rank = 1)]
async fn put_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    data: Json<EditUserData>,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> EmptyResult {
    edit_member(org_id, member_id, data, headers, conn).await
}

#[post("/organizations/<org_id>/users/<member_id>", data = "<data>", rank = 1)]
async fn edit_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    data: Json<EditUserData>,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: EditUserData = data.into_inner();
    for collection in data.collections.iter().flatten() {
        validate_collection_access(collection.manage, collection.read_only, collection.hide_passwords)?;
    }

    let raw_type = &data.r#type.into_string();
    let Some(new_type) = MembershipType::from_str(raw_type) else {
        err!("Invalid type")
    };

    let Some(mut member_to_edit) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err!("The specified user isn't member of the organization")
    };

    // Parsed (and type-checked) here, long before the write phase further down, so a malformed
    // permission value leaves the role, the permission flags, the collection assignments and the
    // group memberships exactly as they were.
    let custom_permissions =
        CustomRolePermissions::from_edit_request(new_type, data.permissions.as_ref(), &member_to_edit)?;
    let requested_custom_permissions = data.permissions.as_ref().map(|_| custom_permissions);
    let grants_full_access = custom_permissions.grants_full_collection_access(new_type);

    if !may_change_member_type(headers.membership_type, member_to_edit.atype, new_type) {
        err!("You don't have permission to manage the current or requested member role")
    }

    if member_to_edit.atype == MembershipType::Owner
        && new_type != MembershipType::Owner
        && member_to_edit.status == MembershipStatus::Confirmed as i32
    {
        // Removing owner permission, check that there is at least one other confirmed owner
        if Membership::count_confirmed_by_org_and_type(&org_id, MembershipType::Owner, &conn).await <= 1 {
            err!("Can't delete the last owner")
        }
    }

    if !may_grant_custom_permissions(&headers.membership, new_type, requested_custom_permissions) {
        err!("Custom users can only grant the same custom permissions that they have")
    }

    custom_permissions.apply_to(&mut member_to_edit);
    member_to_edit.atype = new_type as i32;

    // This check is also done at accept_invite, _confirm_invite, _activate_member, edit_member, admin::update_membership_type
    // We need to perform the check after changing the type since `admin` is exempt.
    OrgPolicy::check_user_allowed(&member_to_edit, "modify", &conn).await?;

    let mut collection_assignments: Vec<(CollectionId, bool, bool, bool)> = Vec::new();
    if !grants_full_access {
        for col in data.collections.iter().flatten() {
            let Some(collection) = Collection::find_by_uuid_and_org(&col.id, &org_id, &conn).await else {
                err!("Collection not found in Organization")
            };
            collection_assignments.push((collection.uuid, col.read_only, col.hide_passwords, col.manage));
        }
    }

    for group_id in data.groups.iter().flatten() {
        if Group::find_by_uuid_and_org(group_id, &org_id, &conn).await.is_none() {
            err!("Group not found in this organization")
        }
    }

    if headers.membership_type == MembershipType::Custom {
        let current_groups: HashSet<GroupId> = GroupUser::find_by_member(&member_to_edit.uuid, &conn)
            .await
            .into_iter()
            .map(|group_user| group_user.groups_uuid)
            .collect();
        for group_id in data.groups.iter().flatten().filter(|group_id| !current_groups.contains(*group_id)) {
            if Group::find_by_uuid_and_org(group_id, &org_id, &conn).await.is_some_and(|group| group.access_all) {
                err!("Only Admins and Owners can add a member to a legacy access-all group")
            }
        }
    }

    for c in CollectionUser::find_by_organization_and_user_uuid(&org_id, &member_to_edit.user_uuid, &conn).await {
        c.delete(&conn).await?;
    }
    for (collection_uuid, read_only, hide_passwords, manage) in collection_assignments {
        CollectionUser::save(&member_to_edit.user_uuid, &collection_uuid, read_only, hide_passwords, manage, &conn)
            .await?;
    }

    GroupUser::delete_all_by_member(&member_to_edit.uuid, &conn).await?;
    for group_id in data.groups.iter().flatten() {
        let mut group_entry = GroupUser::new(group_id.clone(), member_to_edit.uuid.clone());
        group_entry.save(&conn).await?;
    }

    log_event(
        EventType::OrganizationUserUpdated,
        &member_to_edit.uuid,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    member_to_edit.save(&conn).await
}

#[delete("/organizations/<org_id>/users", data = "<data>")]
async fn bulk_delete_member(
    org_id: OrganizationId,
    data: Json<BulkMembershipIds>,
    headers: ManageUsersHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: BulkMembershipIds = data.into_inner();

    let mut bulk_response = Vec::new();
    for member_id in data.ids {
        let err_msg = match delete_member_impl(&org_id, &member_id, &headers, &conn, &nt).await {
            Ok(()) => String::new(),
            Err(e) => format!("{e:?}"),
        };

        bulk_response.push(json!(
            {
                "object": "OrganizationBulkConfirmResponseModel",
                "id": member_id,
                "error": err_msg
            }
        ));
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

#[delete("/organizations/<org_id>/users/<member_id>")]
async fn delete_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: ManageUsersHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    delete_member_impl(&org_id, &member_id, &headers, &conn, &nt).await
}

async fn delete_member_impl(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    headers: &ManageUsersHeaders,
    conn: &DbConn,
    nt: &Notify<'_>,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(member_to_delete) = Membership::find_by_uuid_and_org(member_id, org_id, conn).await else {
        err!("User to delete isn't member of the organization")
    };

    if !may_delete_stored_member_type(headers.membership_type, member_to_delete.atype) {
        err!("You don't have permission to delete this user")
    }

    if member_to_delete.atype == MembershipType::Owner && member_to_delete.status == MembershipStatus::Confirmed as i32
    {
        // Removing owner, check that there is at least one other confirmed owner
        if Membership::count_confirmed_by_org_and_type(org_id, MembershipType::Owner, conn).await <= 1 {
            err!("Can't delete the last owner")
        }
    }

    log_event(
        EventType::OrganizationUserRemoved,
        &member_to_delete.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;

    if let Some(user) = User::find_by_uuid(&member_to_delete.user_uuid, conn).await {
        nt.send_user_update(UpdateType::SyncOrgKeys, &user, headers.device.push_uuid.as_ref(), conn).await;

        if !CONFIG.mail_enabled()
            && !Membership::find_invited_by_user(&user.uuid, conn)
                .await
                .into_iter()
                .any(|m| m.uuid != member_to_delete.uuid)
        {
            Invitation::take(&user.email, conn).await;
        }
    }

    member_to_delete.delete(conn).await
}

#[post("/organizations/<org_id>/users/public-keys", data = "<data>")]
async fn bulk_public_keys(
    org_id: OrganizationId,
    data: Json<BulkMembershipIds>,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: BulkMembershipIds = data.into_inner();

    let mut bulk_response = Vec::new();
    // Check all received Membership UUID's and find the matching User to retrieve the public-key.
    // If the user does not exists, just ignore it, and do not return any information regarding that Membership UUID.
    // The web-vault will then ignore that user for the following steps.
    for member_id in data.ids {
        match Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await {
            Some(member) => match User::find_by_uuid(&member.user_uuid, &conn).await {
                Some(user) => bulk_response.push(json!(
                    {
                        "object": "organizationUserPublicKeyResponseModel",
                        "id": member_id,
                        "userId": user.uuid,
                        "key": user.public_key
                    }
                )),
                None => debug!("User doesn't exist"),
            },
            None => debug!("Membership doesn't exist"),
        }
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

use super::ciphers::{CipherData, CipherUpdateAuthorization, update_cipher_from_data};

// The import endpoint only ever uses the name/id/external_id of a collection.
// Bitwarden's own server ignores `groups`/`users` here too, so do not make them
// mandatory: clients are free to leave them out.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportCollectionData {
    name: String,
    id: Option<CollectionId>,
    external_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportData {
    ciphers: Vec<CipherData>,
    collections: Vec<ImportCollectionData>,
    collection_relationships: Vec<RelationsData>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RelationsData {
    // Cipher index
    key: usize,
    // Collection index
    value: usize,
}

// https://github.com/bitwarden/server/blob/e8afc9eb63901402fd160198e70eb865e011144a/src/Api/Tools/Controllers/ImportCiphersController.cs
#[post("/ciphers/import-organization?<query..>", data = "<data>")]
async fn post_org_import(
    query: OrgIdData,
    data: Json<ImportData>,
    headers: OrgMemberHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let org_id = query.organization_id;
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }

    // AccessImportExport authorizes the complete organization import. Other confirmed members keep
    // the regular per-target Create/Update authorization.
    if !headers.membership.has_status(MembershipStatus::Confirmed) {
        err!("You need to be a confirmed member of this organization to import into it")
    }
    let organization_write_authorized =
        headers.membership.atype >= MembershipType::Admin || headers.membership.has_access_import_export();

    let data: ImportData = data.into_inner();
    if data.collections.is_empty() && !organization_write_authorized {
        err!("Not enough privileges to import into this organization")
    }

    // Validate the import before continuing
    // Bitwarden does not process the import if there is one item invalid.
    // Since we check for the size of the encrypted note length, we need to do that here to pre-validate it.
    // TODO: See if we can optimize the whole cipher adding/importing and prevent duplicate code and checks.
    Cipher::validate_cipher_data(&data.ciphers)?;

    // Robustness: validate every collection<->cipher relationship index against the payload *before*
    // creating anything. `key` indexes into `ciphers` and `value` into `collections`, and an out-of-range
    // index would otherwise panic when the relations are applied — after rows have already been written.
    let import_cipher_count = data.ciphers.len();
    let import_collection_count = data.collections.len();
    for relation in &data.collection_relationships {
        if relation.key >= import_cipher_count || relation.value >= import_collection_count {
            err!(
                "Invalid collection relationship",
                "A collection relationship references a non-existent cipher or collection"
            )
        }
    }

    // Security (audit F8/upstream): index the existing collections by id so the per-collection
    // authorization below can use the *write* predicate `is_writable_by_user`. A read-only
    // assignment must not let an importer plant ciphers into a shared collection.
    let existing_collections: HashMap<CollectionId, Collection> =
        Collection::find_by_organization(&org_id, &conn).await.into_iter().map(|c| (c.uuid.clone(), c)).collect();

    // Finish every request-controlled collection authorization check before the first new collection
    // is written. This matters for the PR's create-only Custom role: a payload may name a new
    // collection first and an existing, non-writable collection later. Rejecting the latter only in
    // the write loop left the former behind even though the request failed.
    for col in &data.collections {
        if let Some(collection) = col.id.as_ref().and_then(|col_id| existing_collections.get(col_id)) {
            let writable = collection.is_writable_by_user(&headers.membership.user_uuid, &conn).await;
            if !may_import_to_collection(
                &headers.membership,
                OrganizationImportTarget::Existing {
                    writable,
                },
            ) {
                err!(Compact, "The current user isn't allowed to manage this collection")
            }
        } else if !may_import_to_collection(&headers.membership, OrganizationImportTarget::New) {
            err!(Compact, "The current user isn't allowed to create new collections")
        }
    }

    let mut collections: Vec<CollectionId> = Vec::with_capacity(data.collections.len());
    for col in data.collections {
        let existing = col.id.as_ref().and_then(|col_id| existing_collections.get(col_id));
        let collection_uuid = if let Some(collection) = existing {
            collection.uuid.clone()
        } else {
            let new_collection = Collection::new(org_id.clone(), col.name, col.external_id);
            new_collection.save(&conn).await?;
            // Import-created collections do not carry the regular create endpoint's user access
            // selections. Give a create-only importer Manage access to the collection they just
            // created, matching Bitwarden's organization-import behavior.
            if !headers.membership.has_full_access() {
                CollectionUser::save(&headers.membership.user_uuid, &new_collection.uuid, false, false, true, &conn)
                    .await?;
            }
            new_collection.uuid
        };

        collections.push(collection_uuid);
    }

    // Read the relations between collections and ciphers
    // Ciphers can be in multiple collections at the same time
    let mut relations = Vec::with_capacity(data.collection_relationships.len());
    for relation in data.collection_relationships {
        relations.push((relation.key, relation.value));
    }

    let headers: Headers = headers.into();

    let mut ciphers: Vec<CipherId> = Vec::with_capacity(data.ciphers.len());
    for mut cipher_data in data.ciphers {
        // Always clear folder_id's via an organization import
        cipher_data.folder_id = None;
        // Replace the client-provided, unvalidated organizationId with the real target org
        cipher_data.organization_id = Some(org_id.clone());
        let mut cipher = Cipher::new(cipher_data.r#type, cipher_data.name.clone());
        update_cipher_from_data(
            &mut cipher,
            cipher_data,
            &headers,
            CipherUpdateAuthorization::organization_import(collections.clone(), organization_write_authorized),
            &conn,
            &nt,
            UpdateType::None,
        )
        .await
        .ok();
        ciphers.push(cipher.uuid);
    }

    // Assign the collections. Indices were bounds-validated above, but use `.get()` here as well so
    // any future drift fails closed with an error instead of panicking.
    for (cipher_index, col_index) in relations {
        let (Some(cipher_id), Some(col_id)) = (ciphers.get(cipher_index), collections.get(col_index)) else {
            err!(Compact, "Invalid collection relationship")
        };
        CollectionCipher::save(cipher_id, col_id, &conn).await?;
    }

    let mut user = headers.user;
    user.update_revision(&conn).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkCollectionsData {
    organization_id: OrganizationId,
    cipher_ids: Vec<CipherId>,
    collection_ids: HashSet<CollectionId>,
    remove_collections: bool,
}

// This endpoint is only reachable via the organization view, therefore this endpoint is located here
// Also Bitwarden does not send out Notifications for these changes, it only does this for individual cipher collection updates
#[post("/ciphers/bulk-collections", data = "<data>")]
async fn post_bulk_collections(data: Json<BulkCollectionsData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data: BulkCollectionsData = data.into_inner();

    if Membership::find_confirmed_by_user_and_org(&headers.user.uuid, &data.organization_id, &conn).await.is_none() {
        err!("You need to be a Member of the Organization to call this endpoint")
    }

    // Get all the collection available to the user in one query
    // Also filter based upon the provided collections
    let user_collections: HashMap<CollectionId, Collection> =
        Collection::find_by_organization_and_user_uuid(&data.organization_id, &headers.user.uuid, &conn)
            .await
            .into_iter()
            .filter_map(|c| {
                if data.collection_ids.contains(&c.uuid) {
                    Some((c.uuid.clone(), c))
                } else {
                    None
                }
            })
            .collect();

    // Verify if all the collections requested exists and are writable for the user, else abort
    for collection_uuid in &data.collection_ids {
        match user_collections.get(collection_uuid) {
            Some(collection) if collection.is_writable_by_user(&headers.user.uuid, &conn).await => (),
            _ => err_code!("Resource not found", "User does not have access to a collection", 404),
        }
    }

    for cipher_id in &data.cipher_ids {
        // Only act on existing cipher uuid's
        // Do not abort the operation just ignore it, it could be a cipher was just deleted for example
        if let Some(cipher) = Cipher::find_by_uuid_and_org(cipher_id, &data.organization_id, &conn).await
            && cipher.is_write_accessible_to_user(&headers.user.uuid, &conn).await
        {
            // When selecting a specific collection from the left filter list, and use the bulk option, you can remove an item from that collection
            // In these cases the client will call this endpoint twice, once for adding the new collections and a second for deleting.
            if data.remove_collections {
                for collection in &data.collection_ids {
                    CollectionCipher::delete(&cipher.uuid, collection, &conn).await?;
                }
            } else {
                for collection in &data.collection_ids {
                    CollectionCipher::save(&cipher.uuid, collection, &conn).await?;
                }
            }
        }
    }

    Ok(())
}

#[get("/organizations/<org_id>/policies")]
async fn list_policies(org_id: OrganizationId, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }

    // Security: only Admins/Owners, or Custom members holding the manage_policies permission,
    // may see the actual policy configuration. Other Managers/Custom members (e.g. manage_users
    // or manage_groups only) are still allowed to call this endpoint so the Admin Console can
    // load, but they receive an empty list instead of the policy contents.
    let can_view_policies =
        headers.membership.atype >= MembershipType::Admin || headers.membership.has_manage_policies();

    let policies_json: Vec<Value> = if can_view_policies {
        OrgPolicy::find_by_org(&org_id, &conn).await.iter().map(OrgPolicy::to_json).collect()
    } else {
        Vec::new()
    };

    Ok(Json(json!({
        "data": policies_json,
        "object": "list",
        "continuationToken": null
    })))
}

#[get("/organizations/<org_id>/policies/token?<token>")]
async fn list_policies_token(org_id: OrganizationId, token: &str, conn: DbConn) -> JsonResult {
    let invite = decode_invite(token)?;

    if invite.org_id != org_id {
        err!("Token doesn't match request organization");
    }

    // exit early when we have been invited via /admin panel
    if org_id.as_ref() == FAKE_ADMIN_UUID {
        return Ok(Json(json!({})));
    }

    // TODO: We receive the invite token as ?token=<>, validate it contains the org id
    let policies = OrgPolicy::find_by_org(&org_id, &conn).await;
    let policies_json: Vec<Value> = policies.iter().map(OrgPolicy::to_json).collect();

    Ok(Json(json!({
        "data": policies_json,
        "object": "list",
        "continuationToken": null
    })))
}

// Called during the SSO enrollment return the default policy
#[get("/organizations/00000000-01DC-01DC-01DC-000000000000/policies/master-password", rank = 1)]
fn get_dummy_master_password_policy() -> JsonResult {
    let (enabled, data) = match CONFIG.sso_master_password_policy_value() {
        Some(policy) if CONFIG.sso_enabled() => (true, policy.to_string()),
        _ => (false, "null".to_owned()),
    };
    let policy = OrgPolicy::new(FAKE_SSO_IDENTIFIER.into(), OrgPolicyType::MasterPassword, enabled, data);
    Ok(Json(policy.to_json()))
}

// Called during the SSO enrollment return the org policy if it exists
#[get("/organizations/<org_id>/policies/master-password", rank = 2)]
async fn get_master_password_policy(org_id: OrganizationId, _headers: OrgMemberHeaders, conn: DbConn) -> JsonResult {
    let policy =
        OrgPolicy::find_by_org_and_type(&org_id, OrgPolicyType::MasterPassword, &conn).await.unwrap_or_else(|| {
            let (enabled, data) = match CONFIG.sso_master_password_policy_value() {
                Some(policy) if CONFIG.sso_enabled() => (true, policy.to_string()),
                _ => (false, "null".to_owned()),
            };

            OrgPolicy::new(org_id, OrgPolicyType::MasterPassword, enabled, data)
        });

    Ok(Json(policy.to_json()))
}

#[get("/organizations/<org_id>/policies/<pol_type>", rank = 3)]
async fn get_policy(org_id: OrganizationId, pol_type: i32, headers: ManagePoliciesHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let Some(pol_type_enum) = OrgPolicyType::from_i32(pol_type) else {
        err!("Invalid or unsupported policy type")
    };

    let policy = match OrgPolicy::find_by_org_and_type(&org_id, pol_type_enum, &conn).await {
        Some(p) => p,
        None => OrgPolicy::new(org_id.clone(), pol_type_enum, false, "null".to_owned()),
    };

    Ok(Json(policy.to_json()))
}

#[derive(Deserialize)]
struct PolicyData {
    enabled: bool,
    data: Option<Value>,
}

#[derive(Deserialize)]
struct PutPolicy {
    policy: PolicyData,
    // Ignore metadata for now as we do not yet support this
    // "metadata": {
    //     "defaultUserCollectionName": "2.xx|xx==|xx="
    // }
}

#[put("/organizations/<org_id>/policies/<pol_type>", data = "<data>")]
async fn put_policy(
    org_id: OrganizationId,
    pol_type: i32,
    data: Json<PutPolicy>,
    headers: ManagePoliciesHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: PolicyData = data.into_inner().policy;

    let Some(pol_type_enum) = OrgPolicyType::from_i32(pol_type) else {
        err!("Invalid or unsupported policy type")
    };

    // Bitwarden only allows the Reset Password policy when Single Org policy is enabled
    // Vaultwarden encouraged to use multiple orgs instead of groups because groups were not available in the past
    // Now that groups are available we can enforce this option when wanted.
    // We put this behind a config option to prevent breaking current installation.
    // Maybe we want to enable this by default in the future, but currently it is disabled by default.
    if CONFIG.enforce_single_org_with_reset_pw_policy() {
        if pol_type_enum == OrgPolicyType::ResetPassword && data.enabled {
            let single_org_policy_enabled =
                match OrgPolicy::find_by_org_and_type(&org_id, OrgPolicyType::SingleOrg, &conn).await {
                    Some(p) => p.enabled,
                    None => false,
                };

            if !single_org_policy_enabled {
                err!("Single Organization policy is not enabled. It is mandatory for this policy to be enabled.")
            }
        }

        // Also prevent the Single Org Policy to be disabled if the Reset Password policy is enabled
        if pol_type_enum == OrgPolicyType::SingleOrg && !data.enabled {
            let reset_pw_policy_enabled =
                match OrgPolicy::find_by_org_and_type(&org_id, OrgPolicyType::ResetPassword, &conn).await {
                    Some(p) => p.enabled,
                    None => false,
                };

            if reset_pw_policy_enabled {
                err!("Account recovery policy is enabled. It is not allowed to disable this policy.")
            }
        }
    }

    // When enabling the TwoFactorAuthentication policy, revoke all members that do not have 2FA
    if pol_type_enum == OrgPolicyType::TwoFactorAuthentication && data.enabled {
        two_factor::enforce_2fa_policy_for_org(
            &org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &conn,
        )
        .await?;
    }

    // When enabling the SingleOrg policy, remove this org's members that are members of other orgs
    if pol_type_enum == OrgPolicyType::SingleOrg && data.enabled {
        for mut member in Membership::find_by_org(&org_id, &conn).await {
            // Policy only applies to non-Owner/non-Admin members who have accepted joining the org,
            // and never to the member enabling it -- see `Membership::is_policy_enforcement_target`.
            // Exclude invited and revoked users when checking for this policy.
            // Those users will not be allowed to accept or be activated because of the policy checks done there.
            if member.is_policy_enforcement_target(&headers.user.uuid)
                && member.status != MembershipStatus::Invited as i32
                && Membership::count_accepted_and_confirmed_by_user(&member.user_uuid, &member.org_uuid, &conn).await
                    > 0
            {
                if CONFIG.mail_enabled() {
                    let org = Organization::find_by_uuid(&member.org_uuid, &conn).await.unwrap();
                    let user = User::find_by_uuid(&member.user_uuid, &conn).await.unwrap();

                    mail::send_single_org_removed_from_org(&user.email, &org.name).await?;
                }

                log_event(
                    EventType::OrganizationUserRemoved,
                    &member.uuid,
                    &org_id,
                    &headers.user.uuid,
                    headers.device.atype,
                    &headers.ip.ip,
                    &conn,
                )
                .await;

                member.revoke();
                member.save(&conn).await?;
            }
        }
    }

    let mut policy = match OrgPolicy::find_by_org_and_type(&org_id, pol_type_enum, &conn).await {
        Some(p) => p,
        None => OrgPolicy::new(org_id.clone(), pol_type_enum, false, "{}".to_owned()),
    };

    policy.enabled = data.enabled;
    policy.data = serde_json::to_string(&data.data)?;
    policy.save(&conn).await?;

    log_event(
        EventType::PolicyUpdated,
        policy.uuid.as_ref(),
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    Ok(Json(policy.to_json()))
}

// Deprecated with client v2026.5.0
#[put("/organizations/<org_id>/policies/<pol_type>/vnext", data = "<data>")]
async fn put_policy_vnext(
    org_id: OrganizationId,
    pol_type: i32,
    data: Json<PutPolicy>,
    headers: ManagePoliciesHeaders,
    conn: DbConn,
) -> JsonResult {
    put_policy(org_id, pol_type, data, headers, conn).await
}

#[get("/plans")]
fn get_plans() -> Json<Value> {
    // Respond with a minimal json just enough to allow the creation of an new organization.
    Json(json!({
        "object": "list",
        "data": [{
            "object": "plan",
            "type": 0,
            "product": 0,
            "name": "Free",
            "nameLocalizationKey": "planNameFree",
            "bitwardenProduct": 0,
            "maxUsers": 0,
            "descriptionLocalizationKey": "planDescFree"
        },{
            "object": "plan",
            "type": 0,
            "product": 1,
            "name": "Free",
            "nameLocalizationKey": "planNameFree",
            "bitwardenProduct": 1,
            "maxUsers": 0,
            "descriptionLocalizationKey": "planDescFree"
        }],
        "continuationToken": null
    }))
}

#[get("/organizations/<_org_id>/billing/metadata")]
fn get_billing_metadata(_org_id: OrganizationId, _headers: OrgMemberHeaders) -> Json<Value> {
    // Prevent a 404 error, which also causes Javascript errors.
    Json(empty_data_json())
}

#[get("/organizations/<_org_id>/billing/vnext/warnings")]
fn get_billing_warnings(_org_id: OrganizationId, _headers: OrgMemberHeaders) -> Json<Value> {
    Json(json!({
        "freeTrial":null,
        "inactiveSubscription":null,
        "resellerRenewal":null,
        "taxId":null,
    }))
}

#[get("/organizations/<_org_id>/billing/vnext/self-host/metadata")]
fn get_self_host_billing_metadata(_org_id: OrganizationId, _headers: OrgMemberHeaders) -> Json<Value> {
    // Prevent a 404 error, which also causes Javascript errors.
    Json(json!({
        "isOnSecretsManagerStandalone": false, // Secrets Manager is not supported by Vaultwarden
        "organizationOccupiedSeats": 0 // Vaultwarden does not count seats
    }))
}

fn empty_data_json() -> Value {
    json!({
        "object": "list",
        "data": [],
        "continuationToken": null
    })
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BulkRevokeMembershipIds {
    ids: Option<Vec<MembershipId>>,
}

#[put("/organizations/<org_id>/users/<member_id>/revoke")]
async fn revoke_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> EmptyResult {
    revoke_member_impl(&org_id, &member_id, &headers, &conn).await
}

#[put("/organizations/<org_id>/users/revoke", data = "<data>")]
async fn bulk_revoke_members(
    org_id: OrganizationId,
    data: Json<BulkRevokeMembershipIds>,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();

    let mut bulk_response = Vec::new();
    match data.ids {
        Some(members) => {
            for member_id in members {
                let err_msg = match revoke_member_impl(&org_id, &member_id, &headers, &conn).await {
                    Ok(()) => String::new(),
                    Err(e) => format!("{e:?}"),
                };

                bulk_response.push(json!(
                    {
                        "object": "OrganizationUserBulkResponseModel",
                        "id": member_id,
                        "error": err_msg
                    }
                ));
            }
        }
        None => error!("No users to revoke"),
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

async fn revoke_member_impl(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    headers: &ManageUsersHeaders,
    conn: &DbConn,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    match Membership::find_by_uuid_and_org(member_id, org_id, conn).await {
        Some(mut member) if member.status > MembershipStatus::Revoked as i32 => {
            if member.user_uuid == headers.user.uuid {
                err!("You cannot revoke yourself")
            }
            if !may_revoke_stored_member_type(headers.membership_type, member.atype) {
                err!("You don't have permission to revoke this user")
            }
            if member.atype == MembershipType::Owner
                && Membership::count_confirmed_by_org_and_type(org_id, MembershipType::Owner, conn).await <= 1
            {
                err!("Organization must have at least one confirmed owner")
            }

            member.revoke();
            member.save(conn).await?;

            log_event(
                EventType::OrganizationUserRevoked,
                &member.uuid,
                org_id,
                &headers.user.uuid,
                headers.device.atype,
                &headers.ip.ip,
                conn,
            )
            .await;
        }
        Some(_) => err!("User is already revoked"),
        None => err!("User not found in organization"),
    }
    Ok(())
}

#[put("/organizations/<org_id>/users/<member_id>/restore/vnext")]
async fn restore_member_vnext(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> EmptyResult {
    // Vaultwarden does not (yet) support the per User Collection linked to the `Enforce organization data ownership` policy.
    // Therefor we ignore the `defaultUserCollectionName` data sent and just call restore_member
    restore_member_impl(&org_id, &member_id, &headers, &conn).await
}

#[put("/organizations/<org_id>/users/<member_id>/restore")]
async fn restore_member(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> EmptyResult {
    restore_member_impl(&org_id, &member_id, &headers, &conn).await
}

#[put("/organizations/<org_id>/users/restore", data = "<data>")]
async fn bulk_restore_members(
    org_id: OrganizationId,
    data: Json<BulkMembershipIds>,
    headers: ManageUsersHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();

    let mut bulk_response = Vec::new();
    for member_id in data.ids {
        let err_msg = match restore_member_impl(&org_id, &member_id, &headers, &conn).await {
            Ok(()) => String::new(),
            Err(e) => format!("{e:?}"),
        };

        bulk_response.push(json!(
            {
                "object": "OrganizationUserBulkResponseModel",
                "id": member_id,
                "error": err_msg
            }
        ));
    }

    Ok(Json(json!({
        "data": bulk_response,
        "object": "list",
        "continuationToken": null
    })))
}

async fn restore_member_impl(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    headers: &ManageUsersHeaders,
    conn: &DbConn,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    match Membership::find_by_uuid_and_org(member_id, org_id, conn).await {
        Some(mut member) if member.status < MembershipStatus::Accepted as i32 => {
            if member.user_uuid == headers.user.uuid {
                err!("You cannot restore yourself")
            }
            if !may_manage_stored_member_type(headers.membership_type, member.atype) {
                err!("You don't have permission to restore this user")
            }

            member.restore();
            // This check is also done at accept_invite, _confirm_invite, _activate_member, edit_member, admin::update_membership_type
            // This check need to be done after restoring to work with the correct status
            OrgPolicy::check_user_allowed(&member, "restore", conn).await?;
            member.save(conn).await?;

            log_event(
                EventType::OrganizationUserRestored,
                &member.uuid,
                org_id,
                &headers.user.uuid,
                headers.device.atype,
                &headers.ip.ip,
                conn,
            )
            .await;
        }
        Some(_) => err!("User is already active"),
        None => err!("User not found in organization"),
    }
    Ok(())
}

/// Whether `membership` may read group->collection/user mappings.
///
/// Two independent routes to the same data: the Manage Users / Manage Groups permissions, which is what
/// Bitwarden gates ReadAll on, and organization-wide collection reach, which is what released Vaultwarden
/// gated it on. Both are kept so a legacy Manager with "Manage all collections" still reads these
/// mappings after the migration. The single-group view returns exactly this data and asks the same.
async fn can_read_group_details(org_id: &OrganizationId, membership: &Membership, conn: &DbConn) -> bool {
    membership.has_manage_users()
        || membership.has_manage_groups()
        || membership.has_full_access()
        || (CONFIG.org_groups_enabled() && GroupUser::has_full_access_by_member(org_id, &membership.uuid, conn).await)
}

fn may_read_basic_directory(membership: &Membership) -> bool {
    membership.has_full_access()
        || membership.has_manage_users()
        || membership.has_manage_groups()
        || membership.can_create_new_collections()
        || membership.has_access_reports()
}

async fn can_read_basic_directory(org_id: &OrganizationId, membership: &Membership, conn: &DbConn) -> bool {
    may_read_basic_directory(membership)
        || (CONFIG.org_groups_enabled() && GroupUser::has_full_access_by_member(org_id, &membership.uuid, conn).await)
        || Collection::has_manageable_collection_by_user(org_id, &membership.user_uuid, conn).await
}

async fn get_groups_data(details: bool, org_id: OrganizationId, membership: &Membership, conn: DbConn) -> JsonResult {
    let can_read_details = can_read_group_details(&org_id, membership, &conn).await;
    // The plain list carries no access mappings. Collection creators/managers and report users need
    // this basic directory data in the corresponding web-vault flows.
    let allowed = if details {
        can_read_details
    } else {
        can_read_basic_directory(&org_id, membership, &conn).await
    };
    if !allowed {
        err_code!("Resource not found.", "User does not have access", Status::NotFound.code);
    }

    let groups: Vec<Value> = if CONFIG.org_groups_enabled() {
        let groups = Group::find_by_organization(&org_id, &conn).await;
        let mut groups_json = Vec::with_capacity(groups.len());

        if details {
            for g in groups {
                groups_json.push(g.to_json_details(&conn).await);
            }
        } else {
            for g in groups {
                groups_json.push(g.to_json());
            }
        }
        groups_json
    } else {
        // The Bitwarden clients seem to call this API regardless of whether groups are enabled,
        // so just act as if there are no groups.
        Vec::new()
    };

    Ok(Json(json!({
        "data": groups,
        "object": "list",
        "continuationToken": null,
    })))
}

// The plain group list (id, name, externalId) exposes no access mappings, so it stays readable for
// members who have a reason to see it — the web vault needs it to render group names. The exact
// condition is enforced in `get_groups_data`.
#[get("/organizations/<org_id>/groups")]
async fn get_groups(org_id: OrganizationId, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    get_groups_data(false, org_id, &headers.membership, conn).await
}

// Group *details* expose accessAll, external IDs and collection mappings. The condition is
// `can_read_group_details`, enforced in `get_groups_data`; keeping the guard loose and the condition
// in one place is what stops the list and single-group views from drifting apart, as they had.
#[get("/organizations/<org_id>/groups/details", rank = 1)]
async fn get_groups_details(org_id: OrganizationId, headers: ManagerHeadersLoose, conn: DbConn) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    get_groups_data(true, org_id, &headers.membership, conn).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupRequest {
    name: String,
    #[serde(default)]
    access_all: bool,
    external_id: Option<String>,
    collections: Vec<CollectionData>,
    users: Vec<MembershipId>,
}

impl GroupRequest {
    pub fn to_group(&self, org_uuid: &OrganizationId) -> Group {
        Group::new(org_uuid.clone(), self.name.clone(), self.access_all, self.external_id.clone())
    }

    pub fn update_group(&self, mut group: Group) -> Group {
        group.name.clone_from(&self.name);
        group.access_all = self.access_all;
        // Group Updates do not support changing the external_id
        // These input fields are in a disabled state, and can only be updated/added via ldap_import

        group
    }

    /// Validate if all the collections and members belong to the provided organization
    pub async fn validate(&self, org_id: &OrganizationId, conn: &DbConn) -> EmptyResult {
        for collection in &self.collections {
            validate_collection_access(collection.manage, collection.read_only, collection.hide_passwords)?;
        }

        let org_collections = Collection::find_by_organization(org_id, conn).await;
        let org_collection_ids: HashSet<&CollectionId> = org_collections.iter().map(|c| &c.uuid).collect();
        if let Some(e) = self.collections.iter().find(|c| !org_collection_ids.contains(&c.id)) {
            err!("Invalid collection", format!("Collection {} does not belong to organization {}!", e.id, org_id))
        }

        let org_memberships = Membership::find_by_org(org_id, conn).await;
        let org_membership_ids: HashSet<&MembershipId> = org_memberships.iter().map(|m| &m.uuid).collect();
        if let Some(e) = self.users.iter().find(|m| !org_membership_ids.contains(m)) {
            err!("Invalid member", format!("Member {} does not belong to organization {}!", e, org_id))
        }

        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CollectionData {
    id: CollectionId,
    read_only: bool,
    hide_passwords: bool,
    manage: bool,
}

impl CollectionData {
    pub fn to_collection_group(&self, groups_uuid: GroupId) -> CollectionGroup {
        CollectionGroup::new(self.id.clone(), groups_uuid, self.read_only, self.hide_passwords, self.manage)
    }
}

#[post("/organizations/<org_id>/groups/<group_id>", data = "<data>")]
async fn post_group(
    org_id: OrganizationId,
    group_id: GroupId,
    data: Json<GroupRequest>,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> JsonResult {
    put_group(org_id, group_id, data, headers, conn).await
}

#[post("/organizations/<org_id>/groups", data = "<data>")]
async fn post_groups(
    org_id: OrganizationId,
    headers: ManageGroupsHeaders,
    data: Json<GroupRequest>,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let group_request = data.into_inner();
    group_request.validate(&org_id, &conn).await?;
    if group_request.access_all && headers.membership_type == MembershipType::Custom {
        err!("Only Admins and Owners can create a legacy access-all group")
    }

    let group = group_request.to_group(&org_id);

    log_event(
        EventType::GroupCreated,
        &group.uuid,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    add_update_group(group, group_request.collections, group_request.users, org_id, &headers, &conn).await
}

#[put("/organizations/<org_id>/groups/<group_id>", data = "<data>")]
async fn put_group(
    org_id: OrganizationId,
    group_id: GroupId,
    data: Json<GroupRequest>,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let Some(group) = Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await else {
        err!("Group not found", "Group uuid is invalid or does not belong to the organization")
    };

    let group_request = data.into_inner();
    group_request.validate(&org_id, &conn).await?;
    if group_request.access_all && !group.access_all && headers.membership_type == MembershipType::Custom {
        err!("Only Admins and Owners can enable legacy access-all group access")
    }
    if group_request.access_all && headers.membership_type == MembershipType::Custom {
        let current_members: HashSet<MembershipId> = GroupUser::find_by_group(&group_id, &org_id, &conn)
            .await
            .into_iter()
            .map(|group_user| group_user.users_organizations_uuid)
            .collect();
        if group_request.users.iter().any(|member_id| !current_members.contains(member_id)) {
            err!("Only Admins and Owners can add a member to a legacy access-all group")
        }
    }

    let updated_group = group_request.update_group(group);
    let response = add_update_group(
        updated_group,
        group_request.collections,
        group_request.users,
        org_id.clone(),
        &headers,
        &conn,
    )
    .await?;

    log_event(
        EventType::GroupUpdated,
        &group_id,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    Ok(response)
}

fn may_change_member_type(caller_type: MembershipType, current_atype: i32, new_type: MembershipType) -> bool {
    MembershipType::from_i32(current_atype).is_some_and(|current_type| {
        may_manage_member_type(caller_type, current_type) && may_manage_member_type(caller_type, new_type)
    })
}

/// Whether a caller with user-management access may perform lifecycle actions on a target role.
///
/// Owners may manage every role. Admins may manage Admin, Custom, and User memberships, but never
/// Owners. Custom members holding `manage_users` may manage Users and other Custom members.
fn may_manage_member_type(caller_type: MembershipType, target_type: MembershipType) -> bool {
    match caller_type {
        MembershipType::Owner => true,
        MembershipType::Admin => target_type != MembershipType::Owner,
        MembershipType::Custom => matches!(target_type, MembershipType::User | MembershipType::Custom),
        MembershipType::User => false,
    }
}

fn may_manage_stored_member_type(caller_type: MembershipType, target_atype: i32) -> bool {
    MembershipType::from_i32(target_atype).is_some_and(|target_type| may_manage_member_type(caller_type, target_type))
}

fn may_provision_member_type(caller_type: MembershipType, target_type: MembershipType) -> bool {
    may_manage_member_type(caller_type, target_type)
}

fn may_provision_stored_member_type(caller_type: MembershipType, target_atype: i32) -> bool {
    MembershipType::from_i32(target_atype)
        .is_some_and(|target_type| may_provision_member_type(caller_type, target_type))
}

/// Whether a caller may act on a membership whose stored `atype` this build cannot interpret.
///
/// Such a row (a future build, a partial rollback, a hand edit) holds no authority -- `OrgHeaders`
/// refuses it and every permission flag on it is inert -- but the helpers above fail closed on the
/// unknown value, which left nobody able to remove it either, unlike Vaultwarden. So: an Owner only, and
/// only for the two actions that reduce what the row can become. Editing, confirming, restoring and
/// reinviting keep refusing, because they preserve or reactivate a role the server cannot reason about.
fn may_act_on_unknown_stored_member_type(caller_type: MembershipType) -> bool {
    caller_type == MembershipType::Owner
}

/// Whether a caller may delete `target_atype`. Provisioning rules for a role this build knows;
/// Owner-only for one it does not (see [`may_act_on_unknown_stored_member_type`]).
fn may_delete_stored_member_type(caller_type: MembershipType, target_atype: i32) -> bool {
    match MembershipType::from_i32(target_atype) {
        Some(role) => may_provision_member_type(caller_type, role),
        None => may_act_on_unknown_stored_member_type(caller_type),
    }
}

/// Whether a caller may revoke `target_atype`. Management rules for a role this build knows;
/// Owner-only for one it does not.
fn may_revoke_stored_member_type(caller_type: MembershipType, target_atype: i32) -> bool {
    match MembershipType::from_i32(target_atype) {
        Some(role) => may_manage_member_type(caller_type, role),
        None => may_act_on_unknown_stored_member_type(caller_type),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OrganizationImportTarget {
    Existing {
        writable: bool,
    },
    New,
}

fn may_import_to_collection(caller: &Membership, target: OrganizationImportTarget) -> bool {
    if !caller.has_status(MembershipStatus::Confirmed) {
        return false;
    }
    if caller.atype >= MembershipType::Admin || caller.has_access_import_export() {
        return true;
    }

    match target {
        OrganizationImportTarget::Existing {
            writable,
        } => writable,
        OrganizationImportTarget::New => caller.can_create_new_collections(),
    }
}

fn may_grant_custom_permissions(
    caller: &Membership,
    target_type: MembershipType,
    requested: Option<CustomRolePermissions>,
) -> bool {
    !caller.has_type(MembershipType::Custom)
        || target_type != MembershipType::Custom
        || requested.is_none_or(|permissions| permissions.is_subset_of(caller))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OrganizationReportScope {
    Complete,
    Denied,
}

fn organization_report_scope(caller: &Membership) -> OrganizationReportScope {
    if caller.has_status(MembershipStatus::Confirmed)
        && (caller.has_full_access() || caller.has_access_import_export() || caller.has_access_reports())
    {
        OrganizationReportScope::Complete
    } else {
        OrganizationReportScope::Denied
    }
}

async fn add_update_group(
    mut group: Group,
    collections: Vec<CollectionData>,
    members: Vec<MembershipId>,
    org_id: OrganizationId,
    headers: &ManageGroupsHeaders,
    conn: &DbConn,
) -> JsonResult {
    group.save(conn).await?;

    CollectionGroup::delete_all_by_group(&group.uuid, &org_id, conn).await?;
    for col_selection in collections {
        col_selection.to_collection_group(group.uuid.clone()).save(&org_id, conn).await?;
    }

    GroupUser::delete_all_by_group(&group.uuid, &org_id, conn).await?;
    for assigned_member in members {
        let mut user_entry = GroupUser::new(group.uuid.clone(), assigned_member.clone());
        user_entry.save(conn).await?;

        log_event(
            EventType::OrganizationUserUpdatedGroups,
            &assigned_member,
            &org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            conn,
        )
        .await;
    }

    Ok(Json(json!({
        "id": group.uuid,
        "organizationId": group.organizations_uuid,
        "name": group.name,
        "accessAll": group.access_all,
        "externalId": group.external_id,
        "object": "group"
    })))
}

// Reads a single group's details (accessAll, externalId, collection mappings). This is the same data
// the `/groups/details` list endpoint returns, so it asks the same question — `can_read_group_details`.
// Any divergence would let a member read every group's details in bulk but be denied the single-group
// view of the same data, or the reverse.
#[get("/organizations/<org_id>/groups/<group_id>/details")]
async fn get_group_details(
    org_id: OrganizationId,
    group_id: GroupId,
    headers: ManagerHeadersLoose,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }
    if !can_read_group_details(&org_id, &headers.membership, &conn).await {
        err_code!("Resource not found.", "User does not have access", Status::NotFound.code);
    }

    let Some(group) = Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await else {
        err!("Group not found", "Group uuid is invalid or does not belong to the organization")
    };

    Ok(Json(group.to_json_details(&conn).await))
}

#[post("/organizations/<org_id>/groups/<group_id>/delete")]
async fn post_delete_group(
    org_id: OrganizationId,
    group_id: GroupId,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_group_impl(&org_id, &group_id, &headers, &conn).await
}

#[delete("/organizations/<org_id>/groups/<group_id>")]
async fn delete_group(
    org_id: OrganizationId,
    group_id: GroupId,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_group_impl(&org_id, &group_id, &headers, &conn).await
}

async fn delete_group_impl(
    org_id: &OrganizationId,
    group_id: &GroupId,
    headers: &ManageGroupsHeaders,
    conn: &DbConn,
) -> EmptyResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let group = find_group_in_organization(group_id, org_id, conn).await?;
    delete_authorized_group(&group, org_id, headers, conn).await
}

async fn find_group_in_organization(
    group_id: &GroupId,
    org_id: &OrganizationId,
    conn: &DbConn,
) -> Result<Group, crate::Error> {
    let Some(group) = Group::find_by_uuid_and_org(group_id, org_id, conn).await else {
        err!("Group not found", "Group uuid is invalid or does not belong to the organization")
    };
    Ok(group)
}

async fn delete_authorized_group(
    group: &Group,
    org_id: &OrganizationId,
    headers: &ManageGroupsHeaders,
    conn: &DbConn,
) -> EmptyResult {
    log_event(
        EventType::GroupDeleted,
        &group.uuid,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;

    group.delete(org_id, conn).await
}

#[delete("/organizations/<org_id>/groups", data = "<data>")]
async fn bulk_delete_groups(
    org_id: OrganizationId,
    data: Json<BulkGroupIds>,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let data: BulkGroupIds = data.into_inner();

    // Resolve the complete request before the first event or deletion so a foreign id cannot leave a
    // valid prefix already deleted.
    let mut groups = Vec::with_capacity(data.ids.len());
    let mut seen_group_ids = HashSet::with_capacity(data.ids.len());
    for group_id in data.ids {
        if !seen_group_ids.insert(group_id.clone()) {
            err!("Duplicate group id in bulk delete request")
        }
        groups.push(find_group_in_organization(&group_id, &org_id, &conn).await?);
    }

    for group in &groups {
        delete_authorized_group(group, &org_id, &headers, &conn).await?;
    }
    Ok(())
}

#[get("/organizations/<org_id>/groups/<group_id>", rank = 2)]
async fn get_group(
    org_id: OrganizationId,
    group_id: GroupId,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let Some(group) = Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await else {
        err!("Group not found", "Group uuid is invalid or does not belong to the organization")
    };

    Ok(Json(group.to_json()))
}

#[get("/organizations/<org_id>/groups/<group_id>/users")]
async fn get_group_members(
    org_id: OrganizationId,
    group_id: GroupId,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    if Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await.is_none() {
        err!("Group could not be found!", "Group uuid is invalid or does not belong to the organization")
    }

    let group_members: Vec<MembershipId> = GroupUser::find_by_group(&group_id, &org_id, &conn)
        .await
        .iter()
        .map(|entry| entry.users_organizations_uuid.clone())
        .collect();

    Ok(Json(json!(group_members)))
}

#[put("/organizations/<org_id>/groups/<group_id>/users", data = "<data>")]
async fn put_group_members(
    org_id: OrganizationId,
    group_id: GroupId,
    headers: ManageGroupsHeaders,
    data: Json<Vec<MembershipId>>,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    let Some(group) = Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await else {
        err!("Group could not be found!", "Group uuid is invalid or does not belong to the organization")
    };

    let assigned_members = data.into_inner();

    let org_memberships = Membership::find_by_org(&org_id, &conn).await;
    let org_membership_ids: HashSet<&MembershipId> = org_memberships.iter().map(|m| &m.uuid).collect();
    if let Some(e) = assigned_members.iter().find(|m| !org_membership_ids.contains(m)) {
        err!("Invalid member", format!("Member {} does not belong to organization {}!", e, org_id))
    }

    if group.access_all && headers.membership_type == MembershipType::Custom {
        let current_members: HashSet<MembershipId> = GroupUser::find_by_group(&group_id, &org_id, &conn)
            .await
            .into_iter()
            .map(|group_user| group_user.users_organizations_uuid)
            .collect();
        if assigned_members.iter().any(|member_id| !current_members.contains(member_id)) {
            err!("Only Admins and Owners can add a member to a legacy access-all group")
        }
    }

    GroupUser::delete_all_by_group(&group_id, &org_id, &conn).await?;
    for assigned_member in assigned_members {
        let mut user_entry = GroupUser::new(group_id.clone(), assigned_member.clone());
        user_entry.save(&conn).await?;

        log_event(
            EventType::OrganizationUserUpdatedGroups,
            &assigned_member,
            &org_id,
            &headers.user.uuid,
            headers.device.atype,
            &headers.ip.ip,
            &conn,
        )
        .await;
    }

    Ok(())
}

#[post("/organizations/<org_id>/groups/<group_id>/delete-user/<member_id>")]
async fn post_delete_group_member(
    org_id: OrganizationId,
    group_id: GroupId,
    member_id: MembershipId,
    headers: ManageGroupsHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    if !CONFIG.org_groups_enabled() {
        err!("Group support is disabled");
    }

    if Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await.is_none() {
        err!("User could not be found or does not belong to the organization.");
    }

    if Group::find_by_uuid_and_org(&group_id, &org_id, &conn).await.is_none() {
        err!("Group could not be found or does not belong to the organization.");
    }

    log_event(
        EventType::OrganizationUserUpdatedGroups,
        &member_id,
        &org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    GroupUser::delete_by_group_and_member(&group_id, &member_id, &conn).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationUserResetPasswordEnrollmentRequest {
    reset_password_key: Option<String>,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationUserRecoverAccountRequest {
    new_master_password_hash: Option<String>,
    key: Option<String>,

    #[serde(default)]
    reset_master_password: bool,
    #[serde(default)]
    reset_two_factor: bool,
}

// Upstream reports this is the renamed endpoint instead of `/keys`
// But the clients do not seem to use this at all
// Just add it here in case they will
#[get("/organizations/<org_id>/public-key")]
async fn get_organization_public_key(org_id: OrganizationId, headers: OrgMemberHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.membership.org_uuid {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err!("Organization not found")
    };

    Ok(Json(json!({
        "object": "organizationPublicKey",
        "publicKey": org.public_key,
    })))
}

// Obsolete - Renamed to public-key (2023.8), left for backwards compatibility with older clients
// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/AdminConsole/Controllers/OrganizationsController.cs#L487-L492
#[get("/organizations/<org_id>/keys")]
async fn get_organization_keys(org_id: OrganizationId, headers: OrgMemberHeaders, conn: DbConn) -> JsonResult {
    get_organization_public_key(org_id, headers, conn).await
}

// Will allow to reset 2FA too
// https://github.com/bitwarden/clients/blob/web-v2026.4.2/libs/admin-console/src/common/organization-user/models/requests/organization-user-reset-password.request.ts
#[put("/organizations/<org_id>/users/<member_id>/recover-account", data = "<data>")]
async fn put_recover_account(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: AdminHeaders,
    data: Json<OrganizationUserRecoverAccountRequest>,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    recover_account(org_id, member_id, headers, data.into_inner(), conn, nt).await
}

// Deprecated since `v2026.4.2`
#[put("/organizations/<org_id>/users/<member_id>/reset-password", data = "<data>")]
async fn put_reset_password(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: AdminHeaders,
    data: Json<OrganizationUserRecoverAccountRequest>,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    recover_account(org_id, member_id, headers, data.into_inner(), conn, nt).await
}

async fn recover_account(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: AdminHeaders,
    req: OrganizationUserRecoverAccountRequest,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err!("Required organization not found")
    };

    let Some(member) = Membership::find_by_uuid_and_org(&member_id, &org.uuid, &conn).await else {
        err!("User to reset isn't member of required organization")
    };

    let Some(mut user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
        err!("User not found")
    };

    check_reset_password_applicable_and_permissions(&org_id, &member_id, &headers, &conn).await?;

    if member.reset_password_key.is_none() {
        err!("Password reset not or not correctly enrolled");
    }
    if member.status != (MembershipStatus::Confirmed as i32) {
        err!("Organization user must be confirmed for password reset functionality");
    }

    let fallback_2fa_email = if req.reset_two_factor && CONFIG.email_2fa_auto_fallback() {
        TwoFactor::find_by_user_and_type(&user.uuid, TwoFactorType::Email as i32, &conn).await.is_none()
    } else {
        false
    };

    // Sending email first ensure working email configuration and the resulting user notification.
    // Also this might add some protection against security flaws and misuse
    if let Err(e) = mail::send_admin_account_recovery(
        &user.email,
        user.display_name(),
        &org.name,
        req.reset_master_password,
        req.reset_two_factor,
        fallback_2fa_email,
    )
    .await
    {
        err!(format!("Error sending user reset password email: {e:#?}"));
    }

    if req.reset_master_password {
        if let Some(key) = req.key
            && let Some(hash) = req.new_master_password_hash
        {
            user.set_password(hash.as_str(), Some(key), true, None, &conn).await?;
        } else {
            err_code!("Unprocessable request", "Missing fields to reset password", Status::UnprocessableEntity.code);
        }
    }

    if req.reset_two_factor {
        TwoFactor::delete_all_by_user(&user.uuid, &conn).await?;
        if !fallback_2fa_email || two_factor::email::find_and_activate_email_2fa(&user.uuid, &conn).await.is_err() {
            two_factor::enforce_2fa_policy(&user, &headers.user.uuid, headers.device.atype, &headers.ip.ip, &conn)
                .await?;
        }
    }

    user.save(&conn).await?;

    nt.send_logout(&user, None, &conn).await;

    if req.reset_master_password {
        headers.log_event(EventType::OrganizationUserAdminResetPassword, &member_id, &org_id, &conn).await;
    }

    if req.reset_two_factor {
        headers.log_event(EventType::OrganizationUserAdminResetTwoFactor, &member_id, &org_id, &conn).await;
    }

    Ok(())
}

#[get("/organizations/<org_id>/users/<member_id>/reset-password-details")]
async fn get_reset_password_details(
    org_id: OrganizationId,
    member_id: MembershipId,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let Some(org) = Organization::find_by_uuid(&org_id, &conn).await else {
        err!("Required organization not found")
    };

    let Some(member) = Membership::find_by_uuid_and_org(&member_id, &org_id, &conn).await else {
        err!("User to reset isn't member of required organization")
    };

    let Some(user) = User::find_by_uuid(&member.user_uuid, &conn).await else {
        err!("User not found")
    };

    check_reset_password_applicable_and_permissions(&org_id, &member_id, &headers, &conn).await?;

    // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/AdminConsole/Models/Response/Organizations/OrganizationUserResponseModel.cs#L190
    Ok(Json(json!({
        "object": "organizationUserResetPasswordDetails",
        "organizationUserId": member_id,
        "kdf": user.client_kdf_type,
        "kdfIterations": user.client_kdf_iter,
        "kdfMemory": user.client_kdf_memory,
        "kdfParallelism": user.client_kdf_parallelism,
        "resetPasswordKey": member.reset_password_key,
        "encryptedPrivateKey": org.private_key,
    })))
}

async fn check_reset_password_applicable_and_permissions(
    org_id: &OrganizationId,
    member_id: &MembershipId,
    headers: &AdminHeaders,
    conn: &DbConn,
) -> EmptyResult {
    check_reset_password_applicable(org_id, conn).await?;

    let Some(target_user) = Membership::find_by_uuid_and_org(member_id, org_id, conn).await else {
        err!("Reset target user not found")
    };

    // Resetting user must be higher/equal to user to reset
    match headers.membership_type {
        MembershipType::Owner => Ok(()),
        MembershipType::Admin if target_user.atype <= MembershipType::Admin => Ok(()),
        _ => err!("No permission to reset this user's password"),
    }
}

async fn check_reset_password_applicable(org_id: &OrganizationId, conn: &DbConn) -> EmptyResult {
    if !CONFIG.mail_enabled() {
        err!("Password reset is not supported on an email-disabled instance.");
    }

    let Some(policy) = OrgPolicy::find_by_org_and_type(org_id, OrgPolicyType::ResetPassword, conn).await else {
        err!("Policy not found")
    };

    if !policy.enabled {
        err!("Reset password policy not enabled");
    }

    Ok(())
}

#[put("/organizations/<org_id>/users/<user_id>/reset-password-enrollment", data = "<data>")]
async fn put_reset_password_enrollment(
    org_id: OrganizationId,
    user_id: UserId,
    headers: OrgMemberHeaders,
    data: Json<OrganizationUserResetPasswordEnrollmentRequest>,
    conn: DbConn,
) -> EmptyResult {
    if user_id != headers.user.uuid {
        err!("User to enroll isn't member of required organization", "The user_id and acting user do not match");
    }

    let mut membership = headers.membership;

    check_reset_password_applicable(&org_id, &conn).await?;

    let reset_request = data.into_inner();

    let reset_password_key = match reset_request.reset_password_key {
        None => None,
        Some(ref key) if key.is_empty() => None,
        Some(key) => Some(key),
    };

    if reset_password_key.is_none() && OrgPolicy::org_is_reset_password_auto_enroll(&org_id, &conn).await {
        err!("Reset password can't be withdrawn due to an enterprise policy");
    }

    if reset_password_key.is_some() {
        PasswordOrOtpData {
            master_password_hash: reset_request.master_password_hash,
            otp: reset_request.otp,
        }
        .validate(&headers.user, true, &conn)
        .await?;
    }

    membership.reset_password_key = reset_password_key;
    membership.save(&conn).await?;

    let event_type = if membership.reset_password_key.is_some() {
        EventType::OrganizationUserResetPasswordEnroll
    } else {
        EventType::OrganizationUserResetPasswordWithdraw
    };

    log_event(event_type, &membership.uuid, &org_id, &headers.user.uuid, headers.device.atype, &headers.ip.ip, &conn)
        .await;

    Ok(())
}

// NOTE: It seems clients can't handle uppercase-first keys!!
//       We need to convert all keys so they have the first character to be a lowercase.
//       Else the export will be just an empty JSON file.
// https://github.com/bitwarden/server/blob/e8afc9eb63901402fd160198e70eb865e011144a/src/Api/Tools/Controllers/OrganizationExportController.cs
#[get("/organizations/<org_id>/export")]
async fn get_org_export(org_id: OrganizationId, headers: AccessImportExportHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let collections = Collection::find_by_organization(&org_id, &conn).await;
    let ciphers = Cipher::find_by_org(&org_id, &conn).await;

    let collections_json: Value = collections.iter().map(Collection::to_json).collect();

    Ok(Json(json!({
        "collections": convert_json_key_lcase_first(collections_json),
        "ciphers": convert_json_key_lcase_first(ciphers_to_org_json(ciphers, &org_id, &headers.host, &headers.user.uuid, &conn).await?),
    })))
}

async fn api_key(
    org_id: &OrganizationId,
    data: Json<PasswordOrOtpData>,
    rotate: bool,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != &headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data: PasswordOrOtpData = data.into_inner();
    let user = headers.user;

    // Validate the admin users password/otp
    data.validate(&user, true, &conn).await?;

    let org_api_key = if let Some(mut org_api_key) = OrganizationApiKey::find_by_org_uuid(org_id, &conn).await {
        if rotate {
            org_api_key.api_key = crate::crypto::generate_api_key();
            org_api_key.revision_date = chrono::Utc::now().naive_utc();
            org_api_key.save(&conn).await.expect("Error rotating organization API Key");
        }
        org_api_key
    } else {
        let api_key = crate::crypto::generate_api_key();
        let new_org_api_key = OrganizationApiKey::new(org_id.clone(), api_key);
        new_org_api_key.save(&conn).await.expect("Error creating organization API Key");
        new_org_api_key
    };

    Ok(Json(json!({
      "apiKey": org_api_key.api_key,
      "revisionDate": crate::util::format_date(&org_api_key.revision_date),
      "object": "apiKey",
    })))
}

#[post("/organizations/<org_id>/api-key", data = "<data>")]
async fn post_api_key(
    org_id: OrganizationId,
    data: Json<PasswordOrOtpData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    api_key(&org_id, data, false, headers, conn).await
}

#[post("/organizations/<org_id>/rotate-api-key", data = "<data>")]
async fn rotate_api_key(
    org_id: OrganizationId,
    data: Json<PasswordOrOtpData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    api_key(&org_id, data, true, headers, conn).await
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::{Value, json};

    use super::{
        CustomRolePermissions, ImportData, OrganizationImportTarget, OrganizationReportScope,
        filter_ciphers_for_organization, index_cipher_collections, may_change_member_type,
        may_delete_stored_member_type, may_grant_custom_permissions, may_import_to_collection, may_manage_member_type,
        may_manage_stored_member_type, may_provision_member_type, may_provision_stored_member_type,
        may_read_all_collections, may_read_all_collections_with_access, may_read_basic_directory,
        may_revoke_stored_member_type, organization_report_scope, validate_collection_access,
    };
    use crate::db::models::{
        Cipher, CipherId, CollectionId, Membership, MembershipStatus, MembershipType, OrganizationId,
    };

    fn confirmed_member(member_type: MembershipType) -> Membership {
        let mut m = Membership::new("test-user".to_owned().into(), "test-org".to_owned().into(), None);
        m.atype = member_type as i32;
        m.status = MembershipStatus::Confirmed as i32;
        m
    }

    /// An unparsable stored role holds no authority but still has to be removable: an Owner may delete
    /// or revoke it, nobody else may touch it, and no reactivating action opens up for anyone.
    #[test]
    fn an_owner_may_remove_a_membership_with_an_unknown_stored_role() {
        // 3 is the retired Manager wire value, which this build never persists; the rest are values
        // no Vaultwarden release writes at all.
        for unknown in [3, 5, -1, i32::MAX, i32::MIN] {
            // 0, 1, 2 and 4 are the only values `MembershipType::from_i32` accepts.
            assert!(![0, 1, 2, 4].contains(&unknown), "{unknown} must not be a known role");

            assert!(may_delete_stored_member_type(MembershipType::Owner, unknown), "{unknown}");
            assert!(may_revoke_stored_member_type(MembershipType::Owner, unknown), "{unknown}");

            for caller in [MembershipType::Admin, MembershipType::Custom, MembershipType::User] {
                assert!(!may_delete_stored_member_type(caller, unknown), "caller={} target={unknown}", caller as i32);
                assert!(!may_revoke_stored_member_type(caller, unknown), "caller={} target={unknown}", caller as i32);
            }

            // Editing, confirming, restoring and reinviting all still refuse, for every caller.
            for caller in [MembershipType::Owner, MembershipType::Admin, MembershipType::Custom, MembershipType::User] {
                assert!(!may_manage_stored_member_type(caller, unknown), "caller={} target={unknown}", caller as i32);
                assert!(
                    !may_provision_stored_member_type(caller, unknown),
                    "caller={} target={unknown}",
                    caller as i32
                );
            }
        }
    }

    #[test]
    fn collection_lists_use_bitwardens_distinct_read_operations() {
        let assert_access = |member: &Membership, read_all: bool, read_all_with_access: bool| {
            assert_eq!(may_read_all_collections(member), read_all);
            assert_eq!(may_read_all_collections_with_access(member), read_all_with_access);
        };

        assert_access(&confirmed_member(MembershipType::Custom), false, false);

        let mut manage_users = confirmed_member(MembershipType::Custom);
        manage_users.manage_users = true;
        assert_access(&manage_users, false, true);

        let mut manage_groups = confirmed_member(MembershipType::Custom);
        manage_groups.manage_groups = true;
        assert_access(&manage_groups, true, true);

        let mut create = confirmed_member(MembershipType::Custom);
        create.create_new_collections = true;
        assert_access(&create, false, false);

        let mut import_export = confirmed_member(MembershipType::Custom);
        import_export.access_import_export = true;
        assert_access(&import_export, true, false);

        let mut reports = confirmed_member(MembershipType::Custom);
        reports.access_reports = true;
        assert_access(&reports, false, false);

        let mut edit_any = confirmed_member(MembershipType::Custom);
        edit_any.edit_any_collection = true;
        assert_access(&edit_any, true, true);

        let mut delete_any = confirmed_member(MembershipType::Custom);
        delete_any.delete_any_collection = true;
        assert_access(&delete_any, true, true);

        assert_access(&confirmed_member(MembershipType::Admin), true, true);
        assert_access(&confirmed_member(MembershipType::Owner), true, true);
    }

    #[test]
    fn access_import_export_authorizes_every_organization_import_target() {
        let mut import_export = confirmed_member(MembershipType::Custom);
        import_export.access_import_export = true;
        assert!(may_import_to_collection(
            &import_export,
            OrganizationImportTarget::Existing {
                writable: false
            }
        ));
        assert!(may_import_to_collection(&import_export, OrganizationImportTarget::New));

        assert!(may_import_to_collection(
            &import_export,
            OrganizationImportTarget::Existing {
                writable: true
            }
        ));

        let mut create = confirmed_member(MembershipType::Custom);
        create.create_new_collections = true;
        assert!(may_import_to_collection(&create, OrganizationImportTarget::New));

        let mut edit_any = confirmed_member(MembershipType::Custom);
        edit_any.edit_any_collection = true;
        assert!(!may_import_to_collection(&edit_any, OrganizationImportTarget::New));

        assert!(may_import_to_collection(
            &confirmed_member(MembershipType::User),
            OrganizationImportTarget::Existing {
                writable: true
            }
        ));

        assert!(may_import_to_collection(
            &confirmed_member(MembershipType::Admin),
            OrganizationImportTarget::Existing {
                writable: false
            }
        ));
        assert!(may_import_to_collection(&confirmed_member(MembershipType::Owner), OrganizationImportTarget::New));

        import_export.status = MembershipStatus::Accepted as i32;
        assert!(!may_import_to_collection(
            &import_export,
            OrganizationImportTarget::Existing {
                writable: true
            }
        ));
    }

    #[test]
    fn organization_import_accepts_missing_or_empty_collection_groups() {
        for collection in [json!({ "name": "missing groups" }), json!({ "name": "empty groups", "groups": [] })] {
            let import: ImportData = serde_json::from_value(json!({
                "ciphers": [],
                "collections": [collection],
                "collectionRelationships": [],
            }))
            .expect("organization import collection groups are optional and ignored");

            assert_eq!(import.collections.len(), 1);
            assert!(import.collections[0].id.is_none());
        }
    }

    #[test]
    fn reports_and_import_export_receive_complete_organization_cipher_scope() {
        let mut reports = confirmed_member(MembershipType::Custom);
        reports.access_reports = true;
        assert_eq!(organization_report_scope(&reports), OrganizationReportScope::Complete);

        let mut import_export = confirmed_member(MembershipType::Custom);
        import_export.access_import_export = true;
        assert_eq!(organization_report_scope(&import_export), OrganizationReportScope::Complete);

        assert_eq!(
            organization_report_scope(&confirmed_member(MembershipType::Custom)),
            OrganizationReportScope::Denied
        );
        assert_eq!(
            organization_report_scope(&confirmed_member(MembershipType::Admin)),
            OrganizationReportScope::Complete
        );
        assert_eq!(
            organization_report_scope(&confirmed_member(MembershipType::Owner)),
            OrganizationReportScope::Complete
        );

        reports.edit_any_collection = true;
        assert_eq!(organization_report_scope(&reports), OrganizationReportScope::Complete);
        reports.edit_any_collection = false;

        reports.status = MembershipStatus::Accepted as i32;
        assert_eq!(organization_report_scope(&reports), OrganizationReportScope::Denied);

        import_export.status = MembershipStatus::Accepted as i32;
        assert_eq!(organization_report_scope(&import_export), OrganizationReportScope::Denied);

        let mut stale_user = confirmed_member(MembershipType::User);
        stale_user.access_reports = true;
        assert_eq!(organization_report_scope(&stale_user), OrganizationReportScope::Denied);
    }

    #[test]
    fn assigned_cipher_response_is_scoped_to_requested_organization() {
        let requested_org: OrganizationId = "requested-org".to_owned().into();
        let other_org: OrganizationId = "other-org".to_owned().into();

        let mut requested_cipher = Cipher::new(1, "requested".to_owned());
        requested_cipher.organization_uuid = Some(requested_org.clone());
        let requested_cipher_id = requested_cipher.uuid.clone();

        let mut other_cipher = Cipher::new(1, "other".to_owned());
        other_cipher.organization_uuid = Some(other_org);

        let personal_cipher = Cipher::new(1, "personal".to_owned());

        let filtered =
            filter_ciphers_for_organization(vec![other_cipher, personal_cipher, requested_cipher], &requested_org);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].uuid, requested_cipher_id);
        assert_eq!(filtered[0].organization_uuid.as_ref(), Some(&requested_org));
    }

    #[test]
    fn manage_users_role_changes_follow_bitwardens_actor_target_matrix() {
        let user = MembershipType::User as i32;
        let custom = MembershipType::Custom as i32;

        // Admins and Owners may change a member's role.
        assert!(may_change_member_type(MembershipType::Owner, user, MembershipType::Custom));
        assert!(may_change_member_type(MembershipType::Admin, user, MembershipType::Custom));

        assert!(may_change_member_type(MembershipType::Admin, user, MembershipType::Admin));
        assert!(!may_change_member_type(MembershipType::Admin, MembershipType::Owner as i32, MembershipType::Admin));

        assert!(may_change_member_type(MembershipType::Custom, user, MembershipType::Custom));
        assert!(may_change_member_type(MembershipType::Custom, custom, MembershipType::User));
        assert!(may_change_member_type(MembershipType::Custom, custom, MembershipType::Custom));
        assert!(!may_change_member_type(MembershipType::Custom, MembershipType::Admin as i32, MembershipType::Custom));
        assert!(!may_change_member_type(MembershipType::Custom, custom, MembershipType::Admin));
    }

    #[test]
    fn member_lifecycle_permissions_follow_the_role_hierarchy() {
        let roles = [MembershipType::Owner, MembershipType::Admin, MembershipType::Custom, MembershipType::User];
        let manage = [
            [true, true, true, true],
            [false, true, true, true],
            [false, false, true, true],
            [false, false, false, false],
        ];
        let provision = manage;

        for (caller_index, caller) in roles.into_iter().enumerate() {
            for (target_index, target) in roles.into_iter().enumerate() {
                let label = format!("caller={} target={}", caller as i32, target as i32);
                assert_eq!(may_manage_member_type(caller, target), manage[caller_index][target_index], "{label}");
                assert_eq!(may_provision_member_type(caller, target), provision[caller_index][target_index], "{label}");
                assert_eq!(
                    may_revoke_stored_member_type(caller, target as i32),
                    manage[caller_index][target_index],
                    "revoke {label}"
                );
                assert_eq!(
                    may_delete_stored_member_type(caller, target as i32),
                    provision[caller_index][target_index],
                    "delete {label}"
                );
                assert_eq!(
                    may_manage_stored_member_type(caller, target as i32),
                    manage[caller_index][target_index],
                    "stored manage {label}"
                );
                assert_eq!(
                    may_provision_stored_member_type(caller, target as i32),
                    provision[caller_index][target_index],
                    "stored provision {label}"
                );
            }
        }
    }

    #[test]
    fn collection_permission_request_combinations_remain_independent() {
        for mask in 0_u8..8 {
            let create = mask & 0b001 != 0;
            let edit = mask & 0b010 != 0;
            let delete = mask & 0b100 != 0;
            let permissions = HashMap::from([
                ("createNewCollections".to_owned(), json!(create)),
                ("editAnyCollection".to_owned(), json!(edit)),
                ("deleteAnyCollection".to_owned(), json!(delete)),
            ]);

            let parsed = CustomRolePermissions::from_request(MembershipType::Custom, &permissions).unwrap();
            assert_eq!(parsed.create_new_collections, create, "mask={mask:03b}");
            assert_eq!(parsed.edit_any_collection, edit, "mask={mask:03b}");
            assert_eq!(parsed.delete_any_collection, delete, "mask={mask:03b}");
            // Only Edit any collection maps to all-collection access. Create/Delete must never do so.
            assert_eq!(parsed.grants_full_collection_access(MembershipType::Custom), edit, "mask={mask:03b}");
        }
    }

    const KNOWN_PERMISSION_KEYS: [&str; 9] = [
        "manageUsers",
        "manageGroups",
        "managePolicies",
        "createNewCollections",
        "editAnyCollection",
        "deleteAnyCollection",
        "accessEventLogs",
        "accessImportExport",
        "accessReports",
    ];

    #[test]
    fn custom_users_can_delegate_only_permissions_they_hold() {
        let requested_map: HashMap<String, Value> =
            KNOWN_PERMISSION_KEYS.iter().map(|key| ((*key).to_owned(), json!(true))).collect();
        let requested = CustomRolePermissions::from_request(MembershipType::Custom, &requested_map).unwrap();

        let mut caller = confirmed_member(MembershipType::Custom);
        requested.apply_to(&mut caller);
        assert!(requested.is_subset_of(&caller));

        for missing in KNOWN_PERMISSION_KEYS {
            let mut caller_map = requested_map.clone();
            caller_map.insert(missing.to_owned(), json!(false));
            let caller_permissions = CustomRolePermissions::from_request(MembershipType::Custom, &caller_map).unwrap();
            caller_permissions.apply_to(&mut caller);
            assert!(!requested.is_subset_of(&caller), "missing permission {missing} must reject delegation");
        }

        let mut stale_user = confirmed_member(MembershipType::User);
        requested.apply_to(&mut stale_user);
        assert!(!requested.is_subset_of(&stale_user));

        requested.apply_to(&mut caller);
        assert!(may_grant_custom_permissions(&caller, MembershipType::Custom, None));
        assert!(may_grant_custom_permissions(&caller, MembershipType::Custom, Some(requested)));

        let mut excessive = requested;
        excessive.access_reports = true;
        caller.access_reports = false;
        assert!(!may_grant_custom_permissions(&caller, MembershipType::Custom, Some(excessive)));
    }

    #[test]
    fn basic_group_directory_matches_bitwardens_collection_management_inputs() {
        let mut member = confirmed_member(MembershipType::Custom);
        assert!(!may_read_basic_directory(&member));

        member.manage_users = true;
        assert!(may_read_basic_directory(&member));
        member.manage_users = false;
        member.manage_groups = true;
        assert!(may_read_basic_directory(&member));
        member.manage_groups = false;
        member.create_new_collections = true;
        assert!(may_read_basic_directory(&member));
        member.create_new_collections = false;
        member.access_reports = true;
        assert!(may_read_basic_directory(&member));
        member.access_reports = false;
        member.access_import_export = true;
        assert!(!may_read_basic_directory(&member));

        assert!(may_read_basic_directory(&confirmed_member(MembershipType::Admin)));
    }

    #[test]
    fn complete_organization_scope_keeps_every_cipher_collection_relationship() {
        let cipher_a = CipherId::from("cipher-a".to_owned());
        let cipher_b = CipherId::from("cipher-b".to_owned());
        let collection_a = CollectionId::from("collection-a".to_owned());
        let collection_b = CollectionId::from("collection-b".to_owned());

        let indexed = index_cipher_collections(vec![
            (cipher_a.clone(), collection_a.clone()),
            (cipher_a.clone(), collection_b.clone()),
            (cipher_b.clone(), collection_b.clone()),
        ]);

        assert_eq!(indexed.get(&cipher_a), Some(&vec![collection_a, collection_b.clone()]));
        assert_eq!(indexed.get(&cipher_b), Some(&vec![collection_b]));
    }

    #[test]
    fn manage_collection_permission_is_mutually_exclusive_with_restrictions() {
        assert!(validate_collection_access(false, false, false).is_ok());
        assert!(validate_collection_access(false, true, true).is_ok());
        assert!(validate_collection_access(true, false, false).is_ok());
        assert!(validate_collection_access(true, true, false).is_err());
        assert!(validate_collection_access(true, false, true).is_err());
        assert!(validate_collection_access(true, true, true).is_err());
    }

    #[test]
    fn custom_permission_parser_accepts_only_booleans_and_non_custom_roles_are_fail_closed() {
        let all_true: HashMap<String, Value> =
            KNOWN_PERMISSION_KEYS.iter().map(|key| ((*key).to_owned(), json!(true))).collect();

        let custom = CustomRolePermissions::from_request(MembershipType::Custom, &all_true).unwrap();
        assert!(custom.manage_users);
        assert!(custom.manage_groups);
        assert!(custom.manage_policies);
        assert!(custom.create_new_collections);
        assert!(custom.edit_any_collection);
        assert!(custom.delete_any_collection);
        assert!(custom.access_event_logs);
        assert!(custom.access_import_export);
        assert!(custom.access_reports);

        let user = CustomRolePermissions::from_request(MembershipType::User, &all_true).unwrap();
        assert_eq!(user, CustomRolePermissions::default());
        assert!(!user.grants_full_collection_access(MembershipType::User));

        let admin = CustomRolePermissions::from_request(MembershipType::Admin, &all_true).unwrap();
        assert_eq!(admin, CustomRolePermissions::default());
        assert!(admin.grants_full_collection_access(MembershipType::Admin));
    }

    /// A known key carrying anything other than a JSON boolean is a malformed request. It used to be
    /// read as `false`, which turned a client bug into a silent permission removal.
    #[test]
    fn a_known_permission_with_a_non_boolean_value_is_rejected() {
        let bad_values = [
            json!("true"),
            json!("false"),
            json!(""),
            json!(1),
            json!(0),
            json!(1.5),
            Value::Null,
            json!({}),
            json!([]),
            json!(["manageUsers"]),
        ];

        for key in KNOWN_PERMISSION_KEYS {
            for value in &bad_values {
                let permissions = HashMap::from([(key.to_owned(), value.clone())]);
                for member_type in
                    [MembershipType::Custom, MembershipType::User, MembershipType::Admin, MembershipType::Owner]
                {
                    assert!(
                        CustomRolePermissions::from_request(member_type, &permissions).is_err(),
                        "{key} = {value} must be rejected for {}",
                        member_type as i32
                    );
                }

                let membership = confirmed_member(MembershipType::Custom);
                assert!(
                    CustomRolePermissions::from_edit_request(MembershipType::Custom, Some(&permissions), &membership)
                        .is_err(),
                    "{key} = {value} must be rejected on the edit path"
                );
            }

            // ... while both booleans stay valid for the same key.
            for value in [true, false] {
                let permissions = HashMap::from([(key.to_owned(), json!(value))]);
                let parsed = CustomRolePermissions::from_request(MembershipType::Custom, &permissions)
                    .expect("a boolean is always valid");
                assert_eq!(parsed != CustomRolePermissions::default(), value, "{key} = {value}");
            }
        }
    }

    /// Bitwarden already sends permission keys Vaultwarden does not implement (`manageSso`,
    /// `manageScim`, `manageResetPassword`) and may add more. Unknown keys stay ignored, whatever
    /// they contain, so the strictness above cannot break a newer client.
    #[test]
    fn unknown_permission_keys_are_ignored_whatever_they_contain() {
        let permissions = HashMap::from([
            ("manageUsers".to_owned(), json!(true)),
            ("manageSso".to_owned(), Value::String("yes".to_owned())),
            ("manageScim".to_owned(), Value::Null),
            ("manageResetPassword".to_owned(), json!(0)),
            ("someFuturePermission".to_owned(), json!({"nested": true})),
        ]);

        let parsed = CustomRolePermissions::from_request(MembershipType::Custom, &permissions)
            .expect("unknown keys must not make a request invalid");
        assert!(parsed.manage_users);
        assert!(!parsed.manage_groups);
        assert!(!parsed.edit_any_collection);
    }

    #[test]
    fn custom_permission_application_covers_every_supported_flag() {
        let mut membership = Membership::new("test-user".to_owned().into(), "test-org".to_owned().into(), None);
        membership.atype = MembershipType::Custom as i32;
        membership.status = MembershipStatus::Confirmed as i32;

        let requested = CustomRolePermissions {
            create_new_collections: true,
            edit_any_collection: true,
            delete_any_collection: true,
            access_event_logs: true,
            access_import_export: true,
            access_reports: true,
            ..CustomRolePermissions::default()
        };

        requested.apply_to(&mut membership);
        assert_eq!(
            CustomRolePermissions::from_edit_request(MembershipType::Custom, None, &membership).unwrap(),
            requested
        );
        assert!(membership.create_new_collections);
        assert!(membership.edit_any_collection);
        assert!(membership.delete_any_collection);
        assert!(membership.access_event_logs);
        assert!(membership.access_import_export);
        assert!(membership.access_reports);
    }

    #[test]
    fn omitted_edit_permissions_preserve_supported_custom_grants() {
        let mut membership = confirmed_member(MembershipType::Custom);
        membership.manage_users = true;
        membership.manage_groups = true;
        membership.manage_policies = true;
        membership.create_new_collections = true;
        membership.edit_any_collection = true;
        membership.delete_any_collection = true;
        membership.access_event_logs = true;
        membership.access_import_export = true;
        membership.access_reports = true;

        let preserved = CustomRolePermissions::from_edit_request(MembershipType::Custom, None, &membership).unwrap();
        assert!(preserved.manage_users);
        assert!(preserved.manage_groups);
        assert!(preserved.manage_policies);
        assert!(preserved.create_new_collections);
        assert!(preserved.edit_any_collection);
        assert!(preserved.delete_any_collection);
        assert!(preserved.access_event_logs);
        assert!(preserved.access_import_export);
        assert!(preserved.access_reports);

        let explicit_reset = HashMap::new();
        assert_eq!(
            CustomRolePermissions::from_edit_request(MembershipType::Custom, Some(&explicit_reset), &membership)
                .unwrap(),
            CustomRolePermissions::default()
        );
        assert_eq!(
            CustomRolePermissions::from_edit_request(MembershipType::User, None, &membership).unwrap(),
            CustomRolePermissions::default()
        );
    }

    #[test]
    fn stale_permission_bits_on_non_custom_members_are_not_authority_changes() {
        let mut membership = confirmed_member(MembershipType::User);
        membership.manage_users = true;
        membership.manage_groups = true;
        membership.manage_policies = true;
        membership.create_new_collections = true;
        membership.edit_any_collection = true;
        membership.delete_any_collection = true;
        membership.access_event_logs = true;
        membership.access_import_export = true;
        membership.access_reports = true;

        let requested = CustomRolePermissions::from_edit_request(MembershipType::User, None, &membership).unwrap();
        assert_eq!(requested, CustomRolePermissions::default());
        // Applying the effective request opportunistically clears the inert historical data.
        requested.apply_to(&mut membership);
        assert!(!membership.manage_users);
        assert!(!membership.manage_groups);
        assert!(!membership.manage_policies);
        assert!(!membership.create_new_collections);
        assert!(!membership.edit_any_collection);
        assert!(!membership.delete_any_collection);
        assert!(!membership.access_event_logs);
        assert!(!membership.access_import_export);
        assert!(!membership.access_reports);
    }
}
