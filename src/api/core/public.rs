use std::collections::HashSet;

use chrono::Utc;
use rocket::{
    Request, Route,
    request::{FromRequest, Outcome},
    serde::json::Json,
};

use crate::{
    CONFIG,
    api::{
        EmptyResult,
        core::organizations::{ProvisionState, provision_org_member, try_restore_member, try_revoke_member},
    },
    auth,
    db::{
        DbConn,
        models::{Group, GroupUser, Membership, MembershipStatus, MembershipType, OrganizationApiKey, OrganizationId},
    },
};

pub fn routes() -> Vec<Route> {
    routes![ldap_import]
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportGroupData {
    name: String,
    external_id: String,
    member_external_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportUserData {
    email: String,
    external_id: String,
    deleted: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportData {
    groups: Vec<OrgImportGroupData>,
    members: Vec<OrgImportUserData>,
    overwrite_existing: bool,
    // largeImport: bool, // For now this will not be used, upstream uses this to prevent syncs of more then 2000 users or groups without the flag set.
}

#[post("/public/organization/import", data = "<data>")]
async fn ldap_import(data: Json<OrgImportData>, token: PublicToken, conn: DbConn) -> EmptyResult {
    // Most of the logic for this function can be found here
    // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/AdminConsole/Services/Implementations/OrganizationService.cs#L1203

    let org_id = token.0;
    let data = data.into_inner();

    for user_data in &data.members {
        if user_data.deleted {
            // If user is marked for deletion and it exists, revoke it
            if let Some(mut member) = Membership::find_by_email_and_org(&user_data.email, &org_id, &conn).await {
                // Only revoke a user if it is not the last confirmed owner
                let revoked = match try_revoke_member(&mut member, &conn).await {
                    Ok(revoked) => revoked,
                    Err(e) => {
                        warn!("{e:?}");
                        false
                    }
                };

                let ext_modified = member.set_external_id(Some(user_data.external_id.clone()));
                if revoked || ext_modified {
                    member.save(&conn).await?;
                }
            }
        // If user is part of the organization, restore it
        } else if let Some(mut member) = Membership::find_by_email_and_org(&user_data.email, &org_id, &conn).await {
            // Enforce org policies as every other restore path does.
            // If the user is not allowed, try_restore_member revokes again and we continue so the
            // external_id is still updated.
            let restored = match try_restore_member(&mut member, &conn).await {
                Ok(restored) => restored,
                Err(e) => {
                    warn!("Not restoring {}: {e:?}", user_data.email);
                    false
                }
            };

            let ext_modified = member.set_external_id(Some(user_data.external_id.clone()));
            if restored || ext_modified {
                member.save(&conn).await?;
            }
        } else {
            // If user is not part of the organization, create the account and membership
            // The Directory Connector import carries no display name, so accounts it creates keep
            // getting their email as their name, and it always provisions active members, exactly
            // as before.
            provision_org_member(
                &org_id,
                &user_data.email,
                None,
                Some(user_data.external_id.clone()),
                ProvisionState::Active,
                &conn,
            )
            .await?;
        }
    }

    if CONFIG.org_groups_enabled() {
        for group_data in &data.groups {
            let group_uuid = if let Some(group) =
                Group::find_by_external_id_and_org(&group_data.external_id, &org_id, &conn).await
            {
                group.uuid
            } else {
                let mut group =
                    Group::new(org_id.clone(), group_data.name.clone(), false, Some(group_data.external_id.clone()));
                group.save(&conn).await?;
                group.uuid
            };

            GroupUser::delete_all_by_group(&group_uuid, &org_id, &conn).await?;

            for ext_id in &group_data.member_external_ids {
                if let Some(member) = Membership::find_by_external_id_and_org(ext_id, &org_id, &conn).await {
                    let mut group_user = GroupUser::new(group_uuid.clone(), member.uuid.clone());
                    group_user.save(&conn).await?;
                }
            }
        }
    } else {
        warn!("Group support is disabled, groups will not be imported!");
    }

    // If this flag is enabled, any user that isn't provided in the Users list will be removed (by default they will be kept unless they have Deleted == true)
    if data.overwrite_existing {
        // Generate a HashSet to quickly verify if a member is listed or not.
        let sync_members: HashSet<String> = data.members.into_iter().map(|m| m.external_id).collect();
        for member in Membership::find_by_org(&org_id, &conn).await {
            if let Some(ref user_external_id) = member.external_id
                && !sync_members.contains(user_external_id)
            {
                if member.atype == MembershipType::Owner && member.status == MembershipStatus::Confirmed as i32 {
                    // Removing owner, check that there is at least one other confirmed owner
                    if Membership::count_confirmed_by_org_and_type(&org_id, MembershipType::Owner, &conn).await <= 1 {
                        warn!("Can't delete the last owner");
                        continue;
                    }
                }
                member.delete(&conn).await?;
            }
        }
    }

    Ok(())
}

pub struct PublicToken(OrganizationId);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for PublicToken {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let headers = request.headers();
        // Get access_token
        let access_token: &str = if let Some(a) = headers.get_one("Authorization") {
            if let Some(split) = a.rsplit("Bearer ").next() {
                split
            } else {
                err_handler!("No access token provided")
            }
        } else {
            err_handler!("No access token provided")
        };
        // Check JWT token is valid and get device and user from it
        let Ok(claims) = auth::decode_api_org(access_token) else {
            err_handler!("Invalid claim")
        };
        // Check if time is between claims.nbf and claims.exp
        let time_now = Utc::now().timestamp();
        if time_now < claims.nbf {
            err_handler!("Token issued in the future");
        }
        if time_now > claims.exp {
            err_handler!("Token expired");
        }
        // Check if claims.iss is domain|claims.scope[0]
        let complete_host = format!("{}|{}", CONFIG.domain_origin(), claims.scope[0]);
        if complete_host != claims.iss {
            err_handler!("Token not issued by this server");
        }

        // Check if claims.sub is org_api_key.uuid
        // Check if claims.client_sub is org_api_key.org_uuid
        let Outcome::Success(conn) = DbConn::from_request(request).await else {
            err_handler!("Error getting DB")
        };
        let Some(org_id) = claims.client_id.strip_prefix("organization.") else {
            err_handler!("Malformed client_id")
        };
        let org_id: OrganizationId = org_id.to_owned().into();
        let Some(org_api_key) = OrganizationApiKey::find_by_org_uuid(&org_id, &conn).await else {
            err_handler!("Invalid client_id")
        };
        if org_api_key.org_uuid != claims.client_sub {
            err_handler!("Token not issued for this org");
        }
        if org_api_key.uuid != claims.sub {
            err_handler!("Token not issued for this client");
        }

        Outcome::Success(PublicToken(claims.client_sub))
    }
}
