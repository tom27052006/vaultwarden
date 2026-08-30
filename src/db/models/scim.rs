use chrono::{NaiveDateTime, Utc};
use derive_more::{AsRef, Deref, Display, From};
use diesel::prelude::*;

use crate::{
    api::EmptyResult,
    crypto,
    db::{DbConn, schema::organization_scim_key},
    error::MapResult,
};

use super::OrganizationId;

/// The bearer credential an identity provider uses to talk to an organization's SCIM endpoint.
///
/// Only a hash of the secret is stored. The plaintext token exists exactly once, in the response
/// to the `/admin` call that created or rotated it, and is never recoverable afterwards.
///
/// There is at most one key per organization (`UNIQUE(org_uuid)` in the schema), so rotating or
/// deleting a key invalidates the previous secret immediately, with no window in which two
/// secrets are accepted.
#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = organization_scim_key)]
#[diesel(treat_none_as_null = true)]
#[diesel(primary_key(uuid))]
pub struct OrganizationScimKey {
    pub uuid: ScimKeyId,
    pub org_uuid: OrganizationId,
    /// Hex-encoded SHA-256 of the token secret.
    pub key_hash: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub last_used_at: Option<NaiveDateTime>,
}

/// The version tag every SCIM token starts with.
pub const SCIM_TOKEN_PREFIX: &str = "scim_v1";

/// Number of random bytes in the token secret. 32 bytes is 256 bits of entropy, which is why a
/// plain SHA-256 (rather than a slow password KDF) is an appropriate way to store it.
const SCIM_SECRET_BYTES: usize = 32;

/// A freshly generated key, together with the one and only copy of its plaintext token.
pub struct NewScimKey {
    pub key: OrganizationScimKey,
    pub token: String,
}

impl OrganizationScimKey {
    /// Generate a new key for `org_uuid`.
    ///
    /// The returned `token` is the only copy of the secret; the returned `key` holds just its
    /// hash and is what gets persisted.
    pub fn generate(org_uuid: OrganizationId) -> NewScimKey {
        let now = Utc::now().naive_utc();
        let uuid = ScimKeyId(crate::util::get_uuid());

        // base64url without padding keeps the token copy/pasteable into IdP config fields.
        let secret = crypto::encode_random_bytes::<SCIM_SECRET_BYTES>(&data_encoding::BASE64URL_NOPAD);
        let token = format!("{SCIM_TOKEN_PREFIX}.{uuid}.{secret}");

        NewScimKey {
            key: Self {
                uuid,
                org_uuid,
                key_hash: crypto::sha256_hex(secret.as_bytes()),
                created_at: now,
                updated_at: now,
                last_used_at: None,
            },
            token,
        }
    }

    /// Constant-time check of a presented secret against the stored hash.
    pub fn matches_secret(&self, secret: &str) -> bool {
        crypto::ct_eq(&self.key_hash, crypto::sha256_hex(secret.as_bytes()))
    }
}

/// Database methods
impl OrganizationScimKey {
    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(organization_scim_key::table)
                    .values(self)
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        diesel::update(organization_scim_key::table)
                            .filter(organization_scim_key::uuid.eq(&self.uuid))
                            .set(self)
                            .execute(conn)
                            .map_res("Error saving SCIM key")
                    }
                    Err(e) => Err(e.into()),
                }.map_res("Error saving SCIM key")
            }
            postgresql {
                diesel::insert_into(organization_scim_key::table)
                    .values(self)
                    .on_conflict(organization_scim_key::uuid)
                    .do_update()
                    .set(self)
                    .execute(conn)
                    .map_res("Error saving SCIM key")
            }
        }
    }

    /// Look up a key by its public key id *and* the organization it must belong to.
    ///
    /// Binding both in the same query is what keeps a token from one organization from ever
    /// resolving under another organization's SCIM base path.
    pub async fn find_by_uuid_and_org(uuid: &ScimKeyId, org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            organization_scim_key::table
                .filter(organization_scim_key::uuid.eq(uuid))
                .filter(organization_scim_key::org_uuid.eq(org_uuid))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            organization_scim_key::table.filter(organization_scim_key::org_uuid.eq(org_uuid)).first::<Self>(conn).ok()
        })
        .await
    }

    /// Best-effort "last seen" bookkeeping for the admin panel. Failures are logged, not
    /// propagated: a write error here must never turn a valid SCIM request into a 401.
    pub async fn touch_last_used(&self, conn: &DbConn) {
        let now = Utc::now().naive_utc();
        let res: EmptyResult = conn
            .run(move |conn| {
                diesel::update(organization_scim_key::table.filter(organization_scim_key::uuid.eq(&self.uuid)))
                    .set(organization_scim_key::last_used_at.eq(now))
                    .execute(conn)
                    .map_res("Error updating SCIM key usage")
            })
            .await;

        if let Err(e) = res {
            warn!("Failed to record SCIM key usage: {e:#?}");
        }
    }

    /// Replace any existing key for this organization with a freshly generated one.
    ///
    /// Deleting first (rather than updating in place) means the previous key id stops resolving
    /// as well as the previous secret.
    pub async fn rotate_for_org(org_uuid: &OrganizationId, conn: &DbConn) -> Result<String, crate::Error> {
        Self::delete_all_by_organization(org_uuid, conn).await?;

        let new_key = Self::generate(org_uuid.clone());
        new_key.key.save(conn).await?;
        Ok(new_key.token)
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(organization_scim_key::table.filter(organization_scim_key::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error removing SCIM key from organization")
        })
        .await
    }
}

#[derive(
    Clone, Debug, AsRef, Deref, DieselNewType, Display, From, FromForm, Hash, PartialEq, Eq, Serialize, Deserialize,
)]
pub struct ScimKeyId(String);

#[cfg(test)]
mod tests {
    use super::*;

    fn org() -> OrganizationId {
        OrganizationId::from(crate::util::get_uuid())
    }

    #[test]
    fn generated_token_has_the_documented_shape() {
        let generated = OrganizationScimKey::generate(org());
        let parts: Vec<&str> = generated.token.split('.').collect();

        assert_eq!(parts.len(), 3, "token must be prefix.keyid.secret");
        assert_eq!(parts[0], SCIM_TOKEN_PREFIX);
        assert_eq!(parts[1], *generated.key.uuid, "the middle part is the public key id");
        // 32 bytes base64url without padding is 43 characters.
        assert_eq!(parts[2].len(), 43);
    }

    #[test]
    fn secret_is_not_stored_in_plaintext() {
        let generated = OrganizationScimKey::generate(org());
        let secret = generated.token.rsplit('.').next().unwrap();

        assert_ne!(generated.key.key_hash, secret);
        assert_eq!(generated.key.key_hash.len(), 64, "hex sha256");
        assert!(!generated.token.contains(&generated.key.key_hash));
    }

    #[test]
    fn matches_only_the_correct_secret() {
        let generated = OrganizationScimKey::generate(org());
        let secret = generated.token.rsplit('.').next().unwrap().to_owned();

        assert!(generated.key.matches_secret(&secret));
        assert!(!generated.key.matches_secret(""));
        assert!(!generated.key.matches_secret(&secret[..secret.len() - 1]));
        assert!(!generated.key.matches_secret(&format!("{secret}x")));
        assert!(!generated.key.matches_secret(&generated.key.key_hash));
    }

    #[test]
    fn generated_keys_are_unique() {
        let a = OrganizationScimKey::generate(org());
        let b = OrganizationScimKey::generate(org());

        assert_ne!(a.key.uuid, b.key.uuid);
        assert_ne!(a.token, b.token);
        assert_ne!(a.key.key_hash, b.key.key_hash);
    }
}
