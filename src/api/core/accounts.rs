use std::collections::HashSet;

use chrono::Utc;
use num_traits::FromPrimitive;
use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
    serde::json::Json,
};
use serde_json::Value;

use crate::{
    CONFIG,
    api::{
        AnonymousNotify, ApiResult, EmptyResult, JsonResult, LogOutReason, Notify, PasswordOrOtpData,
        core::{
            accept_org_invite, log_event, log_user_event, log_user_event_including_accepted_orgs, two_factor::email,
        },
        master_password_policy, push_logout_to_relay, register_push_device, unregister_push_device,
    },
    auth::{ClientHeaders, ClientIp, Headers, decode_delete, decode_invite, decode_verify_email},
    crypto,
    db::{
        DbConn, DbPool,
        models::{
            AuthRequest, AuthRequestId, AuthRequestType, Cipher, CipherId, Device, DeviceId, DeviceType,
            DeviceWithAuthRequest, EmergencyAccess, EmergencyAccessId, EventType, Folder, FolderId, Invitation, KeyId,
            Membership, MembershipId, MembershipStatus, OrgPolicy, OrgPolicyType, Organization, OrganizationId, Send,
            SendId, SignatureAlgorithm, SsoUser, User, UserId, UserKdfType, UserSignatureKeyPair,
        },
    },
    mail,
    util::{NumberOrString, deser_opt_nonempty_str, format_date, validate_enc_string},
};

use super::{
    ciphers::{CipherData, rotate_cipher_data, validate_rotated_cipher},
    sends::SendData,
};

pub fn routes() -> Vec<rocket::Route> {
    routes![
        profile,
        put_profile,
        post_profile,
        put_avatar,
        get_public_keys,
        get_account_public_keys,
        get_keys,
        post_keys,
        post_password,
        post_set_password,
        put_update_tde_offboarding_password,
        post_kdf,
        get_key_rotation_data,
        post_rotatekey,
        post_user_key,
        post_rotate_user_keys,
        post_sstamp,
        post_email_token,
        post_email,
        post_verify_email,
        post_verify_email_token,
        post_delete_recover,
        post_delete_recover_token,
        post_delete_account,
        delete_account,
        revision_date,
        password_hint,
        verify_password,
        post_api_key,
        rotate_api_key,
        get_known_device,
        get_all_devices,
        get_device,
        post_device_token,
        put_device_token,
        put_clear_device_token,
        post_clear_device_token,
        put_device_keys,
        post_device_keys,
        post_device_retrieve_keys,
        post_devices_untrust,
        post_devices_lost_trust,
        delete_device,
        post_deactivate_device,
        get_tasks,
        post_auth_request,
        post_admin_auth_request,
        get_auth_request,
        put_auth_request,
        get_auth_request_response,
        get_auth_requests,
        get_auth_requests_pending,
    ]
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct KDFData {
    #[serde(alias = "kdfType")]
    kdf: i32,
    #[serde(alias = "iterations")]
    kdf_iterations: i32,
    #[serde(alias = "memory")]
    kdf_memory: Option<i32>,
    #[serde(alias = "parallelism")]
    kdf_parallelism: Option<i32>,
}

impl KDFData {
    pub(super) fn matches_user(&self, user: &User) -> bool {
        self.kdf == user.client_kdf_type
            && self.kdf_iterations == user.client_kdf_iter
            && self.kdf_memory == user.client_kdf_memory
            && self.kdf_parallelism == user.client_kdf_parallelism
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterData {
    email: String,

    #[serde(flatten)]
    compat: RegisterDataCompat,

    #[serde(alias = "userAsymmetricKeys")]
    keys: Option<KeysData>,

    // Supersedes `keys`, and the only way a v2 account can be registered.
    account_keys: Option<AccountKeysData>,

    master_password_hint: Option<String>,

    organization_user_id: Option<MembershipId>,

    email_verification_token: Option<String>,
    accept_emergency_access_id: Option<EmergencyAccessId>,
    accept_emergency_access_invite_token: Option<String>,
    #[serde(alias = "token")]
    org_invite_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegisterDataOld {
    #[serde(flatten)]
    kdf: KDFData,

    #[serde(alias = "userSymmetricKey")]
    key: String,

    #[serde(alias = "masterPasswordHash")]
    master_password_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterDataCur {
    #[serde(alias = "MasterPasswordAuthentication")]
    master_password_authentication: MasterPasswordAuthentication,
    #[serde(alias = "MasterPasswordUnlock")]
    master_password_unlock: MasterPasswordUnlock,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RegisterDataCompat {
    RegisterDataOld(RegisterDataOld),
    RegisterDataCur(RegisterDataCur),
}

impl RegisterDataCompat {
    fn fold<'a, T>(
        &'a self,
        fct: impl FnOnce(&'a RegisterDataOld) -> &'a T,
        fcu: impl FnOnce(&'a RegisterDataCur) -> &'a T,
    ) -> &'a T {
        match self {
            Self::RegisterDataOld(rdc) => fct(rdc),
            Self::RegisterDataCur(rdcu) => fcu(rdcu),
        }
    }

    fn hash(&self) -> String {
        self.fold(|rdc| &rdc.master_password_hash, |rdcu| &rdcu.master_password_authentication.hash).to_owned()
    }

    fn kdf(&self) -> &KDFData {
        self.fold(|rdc| &rdc.kdf, |rdcu| &rdcu.master_password_authentication.kdf)
    }

    fn key(&self) -> String {
        self.fold(|rdc| &rdc.key, |rdcu| &rdcu.master_password_unlock.key).to_owned()
    }

    /// The id of the user key, which only the current format carries.
    fn key_id(&self) -> Option<KeyId> {
        match self {
            Self::RegisterDataOld(_) => None,
            Self::RegisterDataCur(rdcu) => rdcu.master_password_unlock.contained_key_id.clone(),
        }
    }

    // When comparing with salt, email need to be normalized:
    //  - https://github.com/bitwarden/clients/blob/web-v2026.5.0/libs/common/src/key-management/master-password/services/master-password.service.ts#L171
    fn unprocessable(&self, email: &str) -> bool {
        let mut unprocessable = false;
        *self.fold(
            |_| &false,
            |rdcu| {
                let email = email.trim().to_lowercase();
                unprocessable = rdcu.master_password_authentication.kdf != rdcu.master_password_unlock.kdf
                    || rdcu.master_password_authentication.salt != email
                    || rdcu.master_password_unlock.salt != email;
                &unprocessable
            },
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeysData {
    encrypted_private_key: String,
    public_key: String,
}

/// Upstream's implicit `[Required]` on a non-nullable string: present and not blank.
fn required(value: Option<String>, field: &str) -> ApiResult<String> {
    match value {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => err!(format!("The {field} field is required.")),
    }
}

/// The `accountKeys` payload: a v1 key pair, or v2 with a signature key pair and security state.
///
/// Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Core/KeyManagement/Models/Api/Request/AccountKeysRequestModel.cs#L6-L50>
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountKeysData {
    // Required like upstream, but only used without `public_key_encryption_key_pair`
    user_key_encrypted_account_private_key: Option<String>,
    account_public_key: Option<String>,

    public_key_encryption_key_pair: Option<PublicKeyEncryptionKeyPairData>,
    signature_key_pair: Option<SignatureKeyPairData>,
    security_state: Option<SecurityStateData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyEncryptionKeyPairData {
    wrapped_private_key: String,
    public_key: String,
    signed_public_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureKeyPairData {
    signature_algorithm: String,
    wrapped_signing_key: String,
    verifying_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecurityStateData {
    security_state: String,
    security_version: i32,
}

struct ValidatedAccountKeys {
    private_key: String,
    public_key: String,
    v2: Option<ValidatedV2AccountKeys>,
}

struct ValidatedV2AccountKeys {
    signed_public_key: String,
    signing_key: String,
    verifying_key: String,
    signature_algorithm: SignatureAlgorithm,
    security_state: String,
    security_version: i32,
}

impl AccountKeysData {
    /// Upstream's model checks, plus the v2 fields all or none: no client can unlock a partial v2 state.
    fn validate(self) -> ApiResult<ValidatedAccountKeys> {
        let top_private_key =
            required(self.user_key_encrypted_account_private_key, "UserKeyEncryptedAccountPrivateKey")?;
        let top_public_key = required(self.account_public_key, "AccountPublicKey")?;
        let (private_key, public_key, signed_public_key) = match self.public_key_encryption_key_pair {
            Some(key_pair) => (
                required(Some(key_pair.wrapped_private_key), "WrappedPrivateKey")?,
                required(Some(key_pair.public_key), "PublicKey")?,
                key_pair.signed_public_key,
            ),
            // Older clients only send the top-level fields, which are always v1
            None => (top_private_key, top_public_key, None),
        };

        if let Some(signature_key_pair) = &self.signature_key_pair {
            required(Some(signature_key_pair.signature_algorithm.clone()), "SignatureAlgorithm")?;
            required(Some(signature_key_pair.wrapped_signing_key.clone()), "WrappedSigningKey")?;
            required(Some(signature_key_pair.verifying_key.clone()), "VerifyingKey")?;
        }
        if let Some(security_state) = &self.security_state {
            required(Some(security_state.security_state.clone()), "SecurityState")?;
            if security_state.security_state.encode_utf16().nth(10_000).is_some() {
                err!("The field SecurityState must be a string with a maximum length of 10000.")
            }
        }

        let v2 = match (signed_public_key, self.signature_key_pair, self.security_state) {
            (Some(signed_public_key), Some(signature_key_pair), Some(security_state)) => {
                // Upstream fails on a null one, but takes an empty one that no client can unlock with
                let signed_public_key = required(Some(signed_public_key), "SignedPublicKey")?;
                let Some(signature_algorithm) = SignatureAlgorithm::parse(&signature_key_pair.signature_algorithm)
                else {
                    err!(format!(
                        "Unsupported signature algorithm: {}",
                        signature_key_pair.signature_algorithm.escape_debug()
                    ))
                };

                Some(ValidatedV2AccountKeys {
                    signed_public_key,
                    signing_key: signature_key_pair.wrapped_signing_key,
                    verifying_key: signature_key_pair.verifying_key,
                    signature_algorithm,
                    security_state: security_state.security_state,
                    security_version: security_state.security_version,
                })
            }
            (None, None, None) => None,
            _ => err!(
                "Invalid account keys: the signed public key, signature key pair and security state must either all be present or all be absent"
            ),
        };

        Ok(ValidatedAccountKeys {
            private_key,
            public_key,
            v2,
        })
    }
}

impl WrappedAccountCryptographicState {
    /// v2-only: the nested pair stands in for the top-level keys, so a partial state can't pass as v1.
    fn validate(self) -> ApiResult<ValidatedAccountKeys> {
        let key_pair = self.public_key_encryption_key_pair;
        AccountKeysData {
            user_key_encrypted_account_private_key: Some(key_pair.wrapped_private_key.clone()),
            account_public_key: Some(key_pair.public_key.clone()),
            public_key_encryption_key_pair: Some(key_pair),
            signature_key_pair: Some(self.signature_key_pair),
            security_state: Some(self.security_state),
        }
        .validate()
    }
}

impl From<KeysData> for ValidatedAccountKeys {
    fn from(keys: KeysData) -> Self {
        Self {
            private_key: keys.encrypted_private_key,
            public_key: keys.public_key,
            v2: None,
        }
    }
}

impl ValidatedAccountKeys {
    /// The keys of a registration: `accountKeys` only for a v2 account, like upstream.
    ///
    /// Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Core/Auth/Models/Api/Request/Accounts/RegisterFinishRequestModel.cs#L77-L100>
    fn for_registration(account_keys: Option<AccountKeysData>, keys: Option<KeysData>) -> ApiResult<Self> {
        if let Some(account_keys) = account_keys {
            let account_keys = account_keys.validate()?;
            if account_keys.is_v2() {
                return Ok(account_keys);
            }
        }
        let Some(keys) = keys else {
            err!("PublicKey and WrappedPrivateKey not found in RequestModel")
        };
        Ok(keys.into())
    }

    fn is_v2(&self) -> bool {
        self.v2.is_some()
    }

    /// Sets the keys on the user. Save [`Self::save_signature_key_pair`] before the user: a v2 user without its key
    /// pair can't unlock, while a key pair saved for a user who isn't v2 yet is ignored until it is, and replaced on
    /// the next try. A rotation of a v2 account replaces its key pair, see `rotate_account`.
    fn apply(&self, user: &mut User) -> EmptyResult {
        user.private_key = Some(self.private_key.clone());
        user.public_key = Some(self.public_key.clone());

        user.signed_public_key = self.v2.as_ref().map(|v2| v2.signed_public_key.clone());
        user.security_state = self.v2.as_ref().map(|v2| v2.security_state.clone());
        user.security_version = self.v2.as_ref().map(|v2| v2.security_version);

        Ok(())
    }

    /// Saves the signature key pair, which needs the user to exist for its foreign key.
    async fn save_signature_key_pair(&self, user_id: &UserId, conn: &DbConn) -> EmptyResult {
        // Skip if the account is v1, since v1 accounts don't have a signature key pair.
        let Some(v2) = &self.v2 else {
            return Ok(());
        };

        let mut key_pair = match UserSignatureKeyPair::find_by_user(user_id, conn).await {
            Some(mut key_pair) => {
                key_pair.signature_algorithm = v2.signature_algorithm as i32;
                key_pair.signing_key.clone_from(&v2.signing_key);
                key_pair.verifying_key.clone_from(&v2.verifying_key);
                key_pair
            }
            None => UserSignatureKeyPair::new(
                user_id.clone(),
                v2.signature_algorithm,
                v2.signing_key.clone(),
                v2.verifying_key.clone(),
            ),
        };
        key_pair.save(conn).await
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordAuthentication {
    #[serde(alias = "Kdf")]
    kdf: KDFData,
    #[serde(alias = "Salt")]
    salt: String,

    #[serde(alias = "masterPasswordAuthenticationHash", alias = "MasterPasswordAuthenticationHash")]
    hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterPasswordUnlock {
    kdf: KDFData,
    salt: String,

    #[serde(alias = "masterKeyWrappedUserKey")]
    key: String,
    contained_key_id: Option<KeyId>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordData {
    #[serde(flatten)]
    compat: RegisterDataCompat,

    keys: Option<KeysData>,
    // Supersedes `keys`, and the only way a v2 account can be initialized here.
    account_keys: Option<AccountKeysData>,

    master_password_hint: Option<String>,
    org_identifier: Option<String>,
}

/// Trims whitespace from password hints, and converts blank password hints to `None`.
fn clean_password_hint(password_hint: Option<&String>) -> Option<String> {
    match password_hint {
        None => None,
        Some(h) => match h.trim() {
            "" => None,
            ht => Some(ht.to_owned()),
        },
    }
}

fn enforce_password_hint_setting(password_hint: Option<&String>) -> EmptyResult {
    if password_hint.is_some() && !CONFIG.password_hints_allowed() {
        err!("Password hints have been disabled by the administrator. Remove the hint and try again.");
    }
    Ok(())
}
async fn is_email_2fa_required(member_id: Option<MembershipId>, conn: &DbConn) -> bool {
    if !CONFIG._enable_email_2fa() {
        return false;
    }
    if CONFIG.email_2fa_enforce_on_verified_invite() {
        return true;
    }
    if let Some(member_id) = member_id {
        return OrgPolicy::is_enabled_for_member(&member_id, OrgPolicyType::TwoFactorAuthentication, conn).await;
    }
    false
}

pub async fn register(data: Json<RegisterData>, conn: DbConn) -> JsonResult {
    let data: RegisterData = data.into_inner();
    let email = data.email.to_lowercase();

    let mut name = None;
    let mut pending_emergency_access = None;

    if data.compat.unprocessable(&data.email) {
        err_code!("Unexpected RegisterData format", Status::UnprocessableEntity.code);
    }

    // First, validate the provided verification tokens
    let mut email_verified = match (
        &data.email_verification_token,
        &data.accept_emergency_access_id,
        &data.accept_emergency_access_invite_token,
        &data.organization_user_id,
        &data.org_invite_token,
    ) {
        // Normal user registration, when email verification is required
        (Some(email_verification_token), None, None, None, None) => {
            let claims = crate::auth::decode_register_verify(email_verification_token)?;
            if claims.sub != data.email {
                err!("Email verification token does not match email");
            }

            // During this call we don't get the name, so extract it from the claims
            name = claims.name;
            claims.verified
        }
        // Emergency access registration
        (None, Some(accept_emergency_access_id), Some(accept_emergency_access_invite_token), None, None) => {
            if !CONFIG.emergency_access_allowed() {
                err!("Emergency access is not enabled.")
            }

            let claims = crate::auth::decode_emergency_access_invite(accept_emergency_access_invite_token)?;

            if claims.email != data.email {
                err!("Claim email does not match email")
            }
            if &claims.emer_id != accept_emergency_access_id {
                err!("Claim emer_id does not match accept_emergency_access_id")
            }

            pending_emergency_access = Some((accept_emergency_access_id, claims));
            true
        }
        // Org invite
        (None, None, None, Some(organization_user_id), Some(org_invite_token)) => {
            let claims = decode_invite(org_invite_token)?;

            if claims.email != data.email {
                err!("Claim email does not match email")
            }

            if &claims.member_id != organization_user_id {
                err!("Claim org_user_id does not match organization_user_id")
            }

            true
        }

        _ => {
            err!("Registration is missing required parameters")
        }
    };

    // Check if the length of the username exceeds 50 characters (Same is Upstream Bitwarden)
    // This also prevents issues with very long usernames causing to large JWT's. See #2419
    if let Some(ref name) = name
        && name.len() > 50
    {
        err!("The field Name must be a string with a maximum length of 50.");
    }

    // Check against the password hint setting and the keys here so if they fail,
    // the user can retry without losing their invitation below.
    let password_hint = clean_password_hint(data.master_password_hint.as_ref());
    enforce_password_hint_setting(password_hint.as_ref())?;
    let account_keys = ValidatedAccountKeys::for_registration(data.account_keys, data.keys)?;

    let existing_user = User::find_by_mail(&email, &conn).await;
    let is_new_user = existing_user.is_none();
    let mut user = match existing_user {
        Some(user) => {
            // Only an invited or SSO provisioned stub registers. A trusted device account has keys but no master
            // password, and registering would replace both. Like upstream, which never registers an existing user.
            if !user.password_hash.is_empty() || user.private_key.is_some() || user.public_key.is_some() {
                err!("Registration not allowed or user already exists")
            }

            if let Some(token) = data.org_invite_token.as_ref() {
                let claims = decode_invite(token)?;
                if claims.email == email {
                    // Verify the email address when signing up via a valid invite token
                    email_verified = true;
                    user
                } else {
                    err!("Registration email does not match invite email")
                }
            } else if Invitation::take(&email, &conn).await {
                Membership::accept_user_invitations(&user.uuid, &conn).await?;
                user
            } else if CONFIG.is_signup_allowed(&email)
                || (CONFIG.emergency_access_allowed()
                    && EmergencyAccess::find_invited_by_grantee_email(&email, &conn).await.is_some())
            {
                user
            } else {
                err!("Registration not allowed or user already exists")
            }
        }
        None => {
            // Order is important here; the invitation check must come first
            // because the vaultwarden admin can invite anyone, regardless
            // of other signup restrictions.
            if Invitation::take(&email, &conn).await
                || CONFIG.is_signup_allowed(&email)
                || pending_emergency_access.is_some()
            {
                User::new(&email, None)
            } else {
                err!("Registration not allowed or user already exists")
            }
        }
    };

    // Make sure we don't leave a lingering invitation.
    Invitation::take(&email, &conn).await;

    set_kdf_data(&mut user, data.compat.kdf())?;

    user.set_password(&data.compat.hash(), Some(data.compat.key()), true, None, &conn).await?;
    user.password_hint = password_hint;

    // Add extra fields if present
    if let Some(name) = name {
        user.name = name;
    }

    account_keys.apply(&mut user)?;
    // Like upstream, only a v2 registration records the key id; v1 accounts report it through `user-key-id`
    if account_keys.is_v2() {
        user.key_id = data.compat.key_id();
    }

    if email_verified {
        user.verified_at = Some(Utc::now().naive_utc());
    }

    if CONFIG.mail_enabled() {
        if CONFIG.signups_verify() && !email_verified {
            if let Err(e) = mail::send_welcome_must_verify(&user.email, &user.uuid).await {
                error!("Error sending welcome email: {e:#?}");
            }
            user.last_verifying_at = Some(user.created_at);
        } else if let Err(e) = mail::send_welcome(&user.email).await {
            error!("Error sending welcome email: {e:#?}");
        }

        if email_verified && is_email_2fa_required(data.organization_user_id, &conn).await {
            email::activate_email_2fa(&user, &conn).await.ok();
        }
    }

    // The key pair first, as in a rotation, but its foreign key needs the user: a new one is saved before without a
    // password or keys, like an invited user, so a failure in between leaves a registration that can be retried.
    if is_new_user && account_keys.is_v2() {
        let mut unregistered = User::new(&user.email, None);
        unregistered.uuid.clone_from(&user.uuid);
        unregistered.save(&conn).await?;
    }
    account_keys.save_signature_key_pair(&user.uuid, &conn).await?;
    user.save(&conn).await?;

    // accept any open emergency access invitations
    if !CONFIG.mail_enabled() && CONFIG.emergency_access_allowed() {
        for mut emergency_invite in EmergencyAccess::find_all_invited_by_grantee_email(&user.email, &conn).await {
            emergency_invite.accept_invite(&user.uuid, &user.email, &conn).await.ok();
        }
    }

    Ok(Json(json!({
      "object": "registerFinish",
    })))
}

/// Upstream's shape checks of the set-password body, on the raw JSON that the untagged compat would hide.
///
/// Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Api/Auth/Models/Request/Accounts/SetInitialPasswordRequestModel.cs#L75-L106>
fn validate_set_password_shape(body: &Value) -> EmptyResult {
    let has = |name: &str| {
        body.as_object().is_some_and(|o| o.iter().any(|(k, v)| k.eq_ignore_ascii_case(name) && !v.is_null()))
    };

    if has("accountKeys") && has("keys") {
        err!("Cannot specify both AccountKeys and Keys. Provide exactly one keypair.")
    }
    let (authentication, unlock) = (has("masterPasswordAuthentication"), has("masterPasswordUnlock"));
    if authentication != unlock {
        err!(
            "Must provide both MasterPasswordAuthentication and MasterPasswordUnlock together. Cannot provide one without the other."
        )
    }
    if authentication && (has("masterPasswordHash") || has("key") || has("kdf")) {
        err!(
            "Cannot mix modern (MasterPasswordAuthentication/MasterPasswordUnlock) and legacy (MasterPasswordHash/Key/Kdf) fields. Provide one shape or the other."
        )
    }
    Ok(())
}

#[post("/accounts/set-password", data = "<data>")]
async fn post_set_password(data: Json<Value>, headers: Headers, conn: DbConn) -> JsonResult {
    let data = data.into_inner();
    validate_set_password_shape(&data)?;
    let Ok(data) = serde_json::from_value::<SetPasswordData>(data) else {
        err_code!("Unexpected SetPasswordData format", Status::UnprocessableEntity.code)
    };
    if data.master_password_hint.as_ref().is_some_and(|h| h.encode_utf16().nth(50).is_some()) {
        err!("The field MasterPasswordHint must be a string with a maximum length of 50.")
    }
    let mut user = headers.user;

    // A trusted device account has its keys but no master password yet
    if !user.password_hash.is_empty() {
        err!("User already has a master password set.")
    }

    if data.compat.unprocessable(&user.email) {
        err_code!("Unexpected SetPasswordData format", Status::UnprocessableEntity.code);
    }

    // Check against the password hint setting here so if it fails,
    // the user can retry without losing their invitation below.
    let password_hint = clean_password_hint(data.master_password_hint.as_ref());
    enforce_password_hint_setting(password_hint.as_ref())?;

    // Like upstream, `accountKeys` only through the v2 JIT flow
    // Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Api/Auth/Controllers/AccountsController.cs#L314-L359>
    let mut account_keys = match data.account_keys {
        Some(account_keys) => {
            if !matches!(data.compat, RegisterDataCompat::RegisterDataCur(_))
                || !crate::util::is_client_feature_flag_enabled(
                    "enable-account-encryption-v2-jit-password-registration",
                )
            {
                err!("Request includes V2 AccountKeys but V2 encryption is not enabled.")
            }
            let account_keys = account_keys.validate()?;
            if !account_keys.is_v2() {
                err!("AccountKeys are only supported for V2 encryption.")
            }
            Some(account_keys)
        }
        None => data.keys.map(ValidatedAccountKeys::from),
    };

    // A trusted device account, which has its keys already
    let has_keys = user.private_key.is_some() || user.public_key.is_some();
    if has_keys {
        // Like upstream's `KeysRequestModel.ToUser`, the account keeps the keys it has, so only the same key pair may come
        // along. Never V2 keys, which upstream's V2 path would write over the existing ones.
        if let Some(keys) = account_keys.take()
            && (keys.is_v2()
                || user.private_key.as_ref() != Some(&keys.private_key)
                || user.public_key.as_ref() != Some(&keys.public_key))
        {
            err!("Cannot replace existing key(s) with new key(s).")
        }

        // Not upstream: the clients ask a trusted device account for a master password only for the account recovery
        // permission. Upstream turns on its Require SSO policy together with trusted devices, so that a password
        // doesn't log in past SSO for anyone else; here only `SSO_ONLY` would prevent that.
        if !Membership::find_by_user(&user.uuid, &conn)
            .await
            .iter()
            .any(|membership| membership.is_not_revoked() && membership.has_manage_reset_password_role())
        {
            err!(
                "Only a member with the account recovery permission sets a master password on a trusted device account."
            )
        }
    }

    set_kdf_data(&mut user, data.compat.kdf())?;

    user.set_password(
        &data.compat.hash(),
        Some(data.compat.key()),
        false,
        Some(vec![String::from("revision_date")]), // We need to allow revision-date to use the old security_timestamp
        &conn,
    )
    .await?;
    user.password_hint = password_hint;

    if let Some(ref account_keys) = account_keys {
        account_keys.apply(&mut user)?;
        // As in `register`, only a v2 account records the user key id here
        if account_keys.is_v2() {
            user.key_id = data.compat.key_id();
        }
    }

    if let Some(identifier) = data.org_identifier
        && identifier != crate::sso::FAKE_SSO_IDENTIFIER
        && identifier != crate::api::admin::FAKE_ADMIN_UUID
    {
        let Some(org) = Organization::find_by_uuid(&identifier.into(), &conn).await else {
            err!("Failed to retrieve the associated organization")
        };

        let Some(membership) = Membership::find_by_user_and_org(&user.uuid, &org.uuid, &conn).await else {
            err!("Failed to retrieve the invitation")
        };

        // Like upstream's `TdeSetPasswordCommand`, a trusted device account keeps its membership as it is
        if !has_keys {
            accept_org_invite(&user, membership, None, &conn).await?;
        }
    }

    // A trusted device account was set up before, upstream neither welcomes it nor accepts anything for it
    if !has_keys {
        if CONFIG.mail_enabled() {
            mail::send_welcome(&user.email.to_lowercase()).await?;
        } else {
            Membership::accept_user_invitations(&user.uuid, &conn).await?;
        }
    }

    log_user_event(EventType::UserChangedPassword, &user.uuid, headers.device.atype, &headers.ip.ip, &conn).await;

    // The key pair first, as in a rotation: if saving the user then fails, the password isn't set either
    if let Some(account_keys) = account_keys {
        account_keys.save_signature_key_pair(&user.uuid, &conn).await?;
    }
    user.save(&conn).await?;

    Ok(Json(json!({
      "object": "set-password",
    })))
}

/// Upstream's `UpdateTdeOffboardingPasswordRequestModel`, shaped like `ChangePassData`
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateTdeOffboardingPasswordData {
    master_password_hint: Option<String>,
    authentication_data: Option<AuthenticationData>,
    unlock_data: Option<UnlockData>,

    // Outdated values, might still be used by older clients
    new_master_password_hash: Option<String>,
    key: Option<String>,
}

/// The master password of a trusted device account once trusted devices are switched off. Upstream asks for the SSO
/// organization's member decryption to be the master password, here that is `SSO_ENABLED` without
/// `SSO_TRUSTED_DEVICE_ENCRYPTION`.
/// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Core/Auth/UserFeatures/TdeOffboardingPassword/TdeOffboardingPasswordCommand.cs>
#[put("/accounts/update-tde-offboarding-password", data = "<data>")]
async fn put_update_tde_offboarding_password(
    data: Json<UpdateTdeOffboardingPasswordData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let data = data.into_inner();
    let mut user = headers.user;

    if data.master_password_hint.as_ref().is_some_and(|hint| hint.encode_utf16().count() > 50) {
        err!("The field MasterPasswordHint must be a string with a maximum length of 50.")
    }
    if data.new_master_password_hash.as_ref().is_some_and(|hash| hash.encode_utf16().count() > 300) {
        err!("The field NewMasterPasswordHash must be a string with a maximum length of 300.")
    }

    // Like upstream, the current fields win over the outdated ones
    let (password_hash, key) = if let (Some(authentication), Some(unlock)) =
        (data.authentication_data, data.unlock_data)
    {
        required(Some(authentication.master_password_authentication_hash.clone()), "MasterPasswordAuthenticationHash")?;
        authentication.check(&user, &unlock)?;
        // Like upstream's `KdfSettingsValidator.ValidateAuthenticationAndUnlockData`, the first master password has to
        // meet the current KDF ranges, `set_kdf_data` below only knows the lower ones every other flow still accepts
        unlock.kdf.validate_new_settings()?;
        validate_enc_string("MasterKeyWrappedUserKey", Some(&unlock.master_key_wrapped_user_key))?;
        check_tde_offboarding(&user, &conn).await?;
        if !user.password_hash.is_empty() {
            err!("User already has a master password set.")
        }
        if !user.akey.is_empty() {
            err!("User already has a key set.")
        }
        set_kdf_data(&mut user, &unlock.kdf)?;
        (authentication.master_password_authentication_hash, unlock.master_key_wrapped_user_key)
    } else {
        let (Some(password_hash), Some(key)) = (data.new_master_password_hash, data.key) else {
            err!(
                "Must provide either new payloads (UnlockData/AuthenticationData) or legacy payloads (NewMasterPasswordHash/Key)."
            )
        };
        if password_hash.trim().is_empty() {
            err!("Master password is required.")
        }
        if key.trim().is_empty() {
            err!("Key is required.")
        }
        if !user.password_hash.is_empty() {
            err!("User already has a master password.")
        }
        check_tde_offboarding(&user, &conn).await?;
        (password_hash, key)
    };

    let password_hint = clean_password_hint(data.master_password_hint.as_ref());
    enforce_password_hint_setting(password_hint.as_ref())?;

    user.set_password(&password_hash, Some(key), true, None, &conn).await?;
    user.password_hint = password_hint;
    user.save(&conn).await?;

    log_user_event(EventType::UserTdeOffboardingPasswordSet, &user.uuid, headers.device.atype, &headers.ip.ip, &conn)
        .await;
    nt.send_logout(&user, None, &conn).await;

    Ok(())
}

/// The organization checks of upstream's `TdeOffboardingPasswordCommand`. SSO is configured for the whole server, so
/// every membership counts as one of an organization with SSO, and the user's SSO link is to the only configuration.
async fn check_tde_offboarding(user: &User, conn: &DbConn) -> EmptyResult {
    if Membership::find_by_user(&user.uuid, conn).await.is_empty() {
        err!("User is not part of any organization that has SSO enabled.")
    }
    if SsoUser::find_by_mail(&user.email, conn).await.and_then(|(_, sso_user)| sso_user).is_none() {
        err!("User is part of no or multiple SSO configurations.")
    }
    if !CONFIG.sso_enabled() {
        err!("Organization SSO configuration not found.")
    }
    if CONFIG.sso_trusted_device_encryption() {
        err!("Organization SSO Member Decryption Type is not Master Password.")
    }
    Ok(())
}

#[get("/accounts/profile")]
async fn profile(headers: Headers, conn: DbConn) -> Json<Value> {
    Json(headers.user.to_json(&conn).await)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileData {
    // culture: String, // Ignored, always use en-US
    name: String,
}

#[put("/accounts/profile", data = "<data>")]
async fn put_profile(data: Json<ProfileData>, headers: Headers, conn: DbConn) -> JsonResult {
    post_profile(data, headers, conn).await
}

#[post("/accounts/profile", data = "<data>")]
async fn post_profile(data: Json<ProfileData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: ProfileData = data.into_inner();

    // Check if the length of the username exceeds 50 characters (Same is Upstream Bitwarden)
    // This also prevents issues with very long usernames causing to large JWT's. See #2419
    if data.name.len() > 50 {
        err!("The field Name must be a string with a maximum length of 50.");
    }

    let mut user = headers.user;
    user.name = data.name;

    user.save(&conn).await?;
    Ok(Json(user.to_json(&conn).await))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AvatarData {
    avatar_color: Option<String>,
}

#[put("/accounts/avatar", data = "<data>")]
async fn put_avatar(data: Json<AvatarData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: AvatarData = data.into_inner();

    // It looks like it only supports the 6 hex color format.
    // If you try to add the short value it will not show that color.
    // Check and force 7 chars, including the #.
    if let Some(color) = &data.avatar_color
        && color.len() != 7
    {
        err!("The field AvatarColor must be a HTML/Hex color code with a length of 7 characters")
    }

    let mut user = headers.user;
    user.avatar_color = data.avatar_color;

    user.save(&conn).await?;
    Ok(Json(user.to_json(&conn).await))
}

#[get("/users/<user_id>/public-key")]
async fn get_public_keys(user_id: UserId, _headers: Headers, conn: DbConn) -> JsonResult {
    let user = match User::find_by_uuid(&user_id, &conn).await {
        Some(user) if user.public_key.is_some() => user,
        Some(_) => err_code!("User has no public_key", Status::NotFound.code),
        None => err_code!("User doesn't exist", Status::NotFound.code),
    };

    Ok(Json(json!({
        "userId": user.uuid,
        "publicKey": user.public_key,
        "object":"userKey"
    })))
}

#[get("/users/<user_id>/keys")]
async fn get_account_public_keys(user_id: UserId, _headers: Headers, conn: DbConn) -> JsonResult {
    let user = match User::find_by_uuid(&user_id, &conn).await {
        Some(user) if user.public_key.is_some() => user,
        Some(_) => err_code!("User has no public_key", Status::NotFound.code),
        None => err_code!("User doesn't exist", Status::NotFound.code),
    };

    Ok(Json(user.public_keys_json(&conn).await))
}

#[get("/accounts/keys")]
async fn get_keys(headers: Headers, conn: DbConn) -> JsonResult {
    let user = headers.user;

    // The SDK reads a 404 as the user having no key pair yet
    if user.private_key.is_none() || user.public_key.is_none() {
        err_code!("User has no key pair", Status::NotFound.code)
    }

    Ok(Json(json!({
        "key": (!user.akey.is_empty()).then_some(&user.akey),
        "publicKey": user.public_key,
        "privateKey": user.private_key,
        "accountKeys": user.account_keys_json(&conn).await,
        "object": "keys",
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PostKeysData {
    // Required like upstream, even next to `accountKeys`
    #[serde(alias = "PublicKey")]
    public_key: Option<String>,
    #[serde(alias = "EncryptedPrivateKey")]
    encrypted_private_key: Option<String>,
    account_keys: Option<AccountKeysData>,
    // The id of the user key these account keys belong to, only honored for v2 `accountKeys`
    user_key_id: Option<KeyId>,
}

#[post("/accounts/keys", data = "<data>")]
async fn post_keys(data: Json<PostKeysData>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: PostKeysData = data.into_inner();

    let mut user = headers.user;

    // Only for an account without keys, replacing them is what a key rotation does
    if user.private_key.is_some() || user.public_key.is_some() {
        err!("User has existing keypair")
    }

    // Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Core/Auth/Models/Api/Request/Accounts/KeysRequestModel.cs#L11-L19>
    let public_key = required(data.public_key, "PublicKey")?;
    let encrypted_private_key = required(data.encrypted_private_key, "EncryptedPrivateKey")?;

    // `accountKeys` supersedes the flat keys when both are sent
    let account_keys = match data.account_keys {
        Some(account_keys) => {
            let account_keys = account_keys.validate()?;
            if !account_keys.is_v2() {
                err!("AccountKeys are only supported for V2 encryption.")
            }
            // A client that predates key ids sends none, and reports it later through `user-key-id`
            if data.user_key_id.is_some() {
                user.key_id = data.user_key_id;
            }
            account_keys
        }
        None => KeysData {
            encrypted_private_key,
            public_key,
        }
        .into(),
    };

    save_initial_account_keys(&account_keys, &mut user, &conn).await?;

    Ok(Json(json!({
        "key": (!user.akey.is_empty()).then_some(&user.akey),
        "privateKey": user.private_key,
        "publicKey": user.public_key,
        "accountKeys": user.account_keys_json(&conn).await,
        "object":"keys"
    })))
}

/// Writes the first keys of the account together with its signature key pair, in one transaction like upstream's, and
/// only while the account still has none: of two requests that set up the keys at once, only one lands, and whole.
async fn save_initial_account_keys(account_keys: &ValidatedAccountKeys, user: &mut User, conn: &DbConn) -> EmptyResult {
    account_keys.apply(user)?;

    conn.transaction(async || {
        if !user.save_if_keys_unset(conn).await? {
            err!("User has existing keypair")
        }
        account_keys.save_signature_key_pair(&user.uuid, conn).await
    })
    .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangePassData {
    master_password_hash: String,
    master_password_hint: Option<String>,
    authentication_data: Option<AuthenticationData>,
    unlock_data: Option<UnlockData>,

    // Outdated values, might still be used by older clients
    new_master_password_hash: Option<String>,
    key: Option<String>,
}

#[post("/accounts/password", data = "<data>")]
async fn post_password(data: Json<ChangePassData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: ChangePassData = data.into_inner();
    let user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    log_user_event(EventType::UserChangedPassword, &user.uuid, headers.device.atype, &headers.ip.ip, &conn).await;

    let (new_master_password_hash, new_key) =
        if let (Some(unlock_data), Some(authentication_data)) = (data.unlock_data, data.authentication_data) {
            if authentication_data.kdf != unlock_data.kdf {
                err!("KDF settings must be equal for authentication and unlock")
            }

            let salt = user.master_password_salt();
            if salt != authentication_data.salt || salt != unlock_data.salt {
                err!("Invalid master password salt")
            }

            validate_key_id_unchanged(&user, &unlock_data)?;

            (authentication_data.master_password_authentication_hash, unlock_data.master_key_wrapped_user_key)
        } else if let (Some(new_master_password_hash), Some(new_key)) = (data.new_master_password_hash, data.key) {
            (new_master_password_hash, new_key)
        } else {
            err!("Invalid request!")
        };

    let mut user = user;

    user.password_hint = clean_password_hint(data.master_password_hint.as_ref());
    enforce_password_hint_setting(user.password_hint.as_ref())?;

    user.set_password(
        &new_master_password_hash,
        Some(new_key),
        true,
        Some(vec![
            String::from("post_rotatekey"),
            String::from("get_contacts"),
            String::from("get_public_keys"),
            String::from("get_api_webauthn"),
        ]),
        &conn,
    )
    .await?;

    let save_result = user.save(&conn).await;

    // Prevent logging out the client where the user requested this endpoint from.
    // If you do logout the user it will causes issues at the client side.
    // Adding the device uuid will prevent this.
    nt.send_logout(&user, Some(&headers.device), &conn).await;

    save_result
}

fn set_kdf_data(user: &mut User, data: &KDFData) -> EmptyResult {
    if data.kdf == UserKdfType::Pbkdf2 as i32 && data.kdf_iterations < CONFIG.client_kdf_iter() {
        err!(format!("PBKDF2 KDF iterations must be at least {}.", CONFIG.client_kdf_iter()))
    }

    if data.kdf == UserKdfType::Argon2id as i32 {
        if data.kdf_iterations < 1 {
            err!("Argon2 KDF iterations must be at least 1.")
        }
        if let Some(m) = data.kdf_memory {
            if !(15..=1024).contains(&m) {
                err!("Argon2 memory must be between 15 MB and 1024 MB.")
            }
            user.client_kdf_memory = data.kdf_memory;
        } else {
            err!("Argon2 memory parameter is required.")
        }
        if let Some(p) = data.kdf_parallelism {
            if !(1..=16).contains(&p) {
                err!("Argon2 parallelism must be between 1 and 16.")
            }
            user.client_kdf_parallelism = data.kdf_parallelism;
        } else {
            err!("Argon2 parallelism parameter is required.")
        }
    } else {
        user.client_kdf_memory = None;
        user.client_kdf_parallelism = None;
    }
    user.client_kdf_iter = data.kdf_iterations;
    user.client_kdf_type = data.kdf;

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticationData {
    #[serde(alias = "Salt")]
    salt: String,
    #[serde(alias = "Kdf")]
    pub(super) kdf: KDFData,
    #[serde(alias = "MasterPasswordAuthenticationHash")]
    pub(super) master_password_authentication_hash: String,
}

impl AuthenticationData {
    pub(super) fn check(&self, user: &User, unlock: &UnlockData) -> EmptyResult {
        if self.kdf != unlock.kdf {
            err!("KDF settings must be equal for authentication and unlock")
        }

        if self.salt != user.master_password_salt() || self.salt != unlock.salt {
            err!("Invalid master password salt")
        }

        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UnlockData {
    salt: String,
    kdf: KDFData,
    pub(super) master_key_wrapped_user_key: String,
    contained_key_id: Option<KeyId>,
}

/// A password or KDF change keeps the user key, so its key id must be the current one, when both are known.
///
/// Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Core/KeyManagement/Models/Data/MasterPasswordUnlockData.cs#L27-L47>
fn validate_key_id_unchanged(user: &User, unlock_data: &UnlockData) -> EmptyResult {
    if let (Some(current), Some(contained)) = (&user.key_id, &unlock_data.contained_key_id)
        && current != contained
    {
        err!("Invalid user key sent in master-password unlock data.")
    }
    Ok(())
}

/// A rotation's unlock data has to wrap the new user key. Neither id is sent by clients that predate them.
///
/// Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Core/KeyManagement/Models/Data/MasterPasswordUnlockData.cs#L49-L61>
fn validate_contained_key_id(contained_key_id: Option<&KeyId>, new_user_key_id: Option<&KeyId>) -> EmptyResult {
    match (contained_key_id, new_user_key_id) {
        (None, None) => Ok(()),
        (Some(contained), Some(new)) if contained == new => Ok(()),
        _ => err!("Invalid user key sent in master-password unlock data."),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeKdfData {
    authentication_data: AuthenticationData,
    unlock_data: UnlockData,
    master_password_hash: String,
}

#[post("/accounts/kdf", data = "<data>")]
async fn post_kdf(data: Json<ChangeKdfData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: ChangeKdfData = data.into_inner();

    if !headers.user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    data.authentication_data.check(&headers.user, &data.unlock_data)?;

    validate_key_id_unchanged(&headers.user, &data.unlock_data)?;

    let mut user = headers.user;

    set_kdf_data(&mut user, &data.unlock_data.kdf)?;

    user.set_password(
        &data.authentication_data.master_password_authentication_hash,
        Some(data.unlock_data.master_key_wrapped_user_key),
        true,
        None,
        &conn,
    )
    .await?;
    let save_result = user.save(&conn).await;

    nt.send_logout(&user, Some(&headers.device), &conn).await;

    save_result
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateFolderData {
    // There is a bug in 2024.3.x which adds a `null` item.
    // To bypass this we allow a Option here, but skip it during the updates
    // See: https://github.com/bitwarden/clients/issues/8453
    #[serde(default, deserialize_with = "deser_opt_nonempty_str")]
    id: Option<FolderId>,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateEmergencyAccessData {
    id: EmergencyAccessId,
    key_encrypted: Option<String>,
    // Only validated, upstream doesn't store it either
    wait_time_days: Option<i32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateResetPasswordData {
    organization_id: OrganizationId,
    // Absent in a v1 -> v2 upgrade, which keeps the key the organization already holds
    reset_password_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyData {
    account_unlock_data: RotateAccountUnlockData,
    account_keys: AccountKeysData,
    account_data: RotateAccountData,
    old_master_key_authentication_hash: String,
    old_user_key_id: Option<KeyId>,
    new_user_key_id: Option<KeyId>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateAccountUnlockData {
    master_password_unlock_data: MasterPasswordUnlockData,
    #[serde(flatten)]
    common: CommonUnlockData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateDeviceKeysData {
    device_id: DeviceId,
    encrypted_user_key: String,
    encrypted_public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MasterPasswordUnlockData {
    #[serde(flatten)]
    kdf: KDFData,
    email: String,
    master_key_authentication_hash: String,
    master_key_encrypted_user_key: String,
    master_password_hint: Option<String>,
    master_password_salt: Option<String>,
    contained_key_id: Option<KeyId>,
}

/// The unlock data of both rotation endpoints; passkey keys remain unsupported.
///
/// Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Api/KeyManagement/Models/Requests/CommonUnlockDataRequestModel.cs#L7-L14>
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommonUnlockData {
    emergency_access_unlock_data: Vec<UpdateEmergencyAccessData>,
    organization_account_recovery_unlock_data: Vec<UpdateResetPasswordData>,
    #[expect(dead_code, reason = "Required like upstream, but unused")]
    passkey_unlock_data: Vec<Value>,
    device_key_unlock_data: Vec<UpdateDeviceKeysData>,
    v2_upgrade_token: Option<V2UpgradeTokenData>,
}

/// Lets other sessions with the v1 user key unwrap the v2 one after an upgrade. Opaque to us. Stored on the user and
/// the memberships as this serializes, and read back with it (the account recovery V2 upgrade routes).
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct V2UpgradeTokenData {
    wrapped_user_key1: String,
    wrapped_user_key2: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateAccountData {
    ciphers: Vec<CipherData>,
    folders: Vec<UpdateFolderData>,
    sends: Vec<SendData>,
}

/// The new keys of every trusted device; entries for any other device are ignored, like upstream.
/// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Api/KeyManagement/Validators/DeviceRotationValidator.cs>
fn validate_device_keydata(
    updates: &[UpdateDeviceKeysData],
    existing_devices: &[Device],
) -> ApiResult<Vec<(DeviceId, String, String)>> {
    for update in updates {
        validate_enc_string("EncryptedPublicKey", Some(&update.encrypted_public_key))?;
        validate_enc_string("EncryptedUserKey", Some(&update.encrypted_user_key))?;
    }

    let mut rotated = Vec::new();
    for device in existing_devices.iter().filter(|device| device.is_trusted()) {
        let Some(update) = updates.iter().find(|update| update.device_id == device.uuid) else {
            err!("All existing trusted devices must be included in the rotation.")
        };
        rotated.push((device.uuid.clone(), update.encrypted_user_key.clone(), update.encrypted_public_key.clone()));
    }

    Ok(rotated)
}

/// Body of `rotate-user-keys`, which rotates the keys without touching the master password.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateUserKeysData {
    wrapped_account_cryptographic_state: WrappedAccountCryptographicState,
    unlock_data: CommonUnlockData,
    account_data: RotateAccountData,
    unlock_method_data: UnlockMethodData,
    old_user_key_id: Option<KeyId>,
    new_user_key_id: Option<KeyId>,
}

/// The v2-only account cryptographic state, where all three parts are mandatory.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WrappedAccountCryptographicState {
    public_key_encryption_key_pair: PublicKeyEncryptionKeyPairData,
    signature_key_pair: SignatureKeyPairData,
    security_state: SecurityStateData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnlockMethodData {
    unlock_method: i32,
    master_password_unlock_data: Option<UnlockData>,
    key_connector_key_wrapped_user_key: Option<String>,
}

impl UnlockMethodData {
    fn validate_tde(&self, user: &User) -> EmptyResult {
        if self.master_password_unlock_data.is_some() || self.key_connector_key_wrapped_user_key.is_some() {
            err!(
                "Invalid Tde unlock method request, MasterPasswordUnlockData must be null and KeyConnectorKeyWrappedUserKey must be null"
            )
        }
        if !user.password_hash.is_empty() || !user.akey.is_empty() {
            err!("User is in an invalid state for TDE key rotation.")
        }
        Ok(())
    }
}

/// Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Api/KeyManagement/Enums/UnlockMethod.cs#L3-L8>
#[derive(num_derive::FromPrimitive)]
enum UnlockMethod {
    Tde = 0,
    MasterPassword = 1,
    KeyConnector = 2,
}

/// The rotation checks on the new keys: the public key never changes, nor the verifying key of a v2 account.
///
/// Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Core/KeyManagement/UserKey/Implementations/RotateUserAccountKeysCommand.cs#L192-L287>
async fn validate_rotation_account_keys(keys: &ValidatedAccountKeys, user: &User, conn: &DbConn) -> EmptyResult {
    if user.public_key.as_ref() != Some(&keys.public_key) {
        err!("Changing the asymmetric keypair is not possible during key rotation")
    }

    let Some(v2) = &keys.v2 else {
        if user.is_v2() {
            err!("Cannot downgrade an account from v2 to v1 encryption during key rotation")
        }
        // A v1 rotation: the private key stays wrapped by an AES-CBC-HMAC user key
        if enc_string_type(&keys.private_key) != Some(ENC_TYPE_AES_CBC_256_HMAC_SHA256) {
            err!("The provided account private key was not wrapped with AES-256-CBC-HMAC")
        }
        return Ok(());
    };

    // Both a v2 rotation and the v1 -> v2 upgrade end up with a COSE user key wrapping the private keys
    if enc_string_type(&v2.signing_key) != Some(ENC_TYPE_COSE_ENCRYPT0) {
        err!("The provided signing key data is not wrapped with XChaCha20-Poly1305.")
    }
    if enc_string_type(&keys.private_key) != Some(ENC_TYPE_COSE_ENCRYPT0) {
        err!("The provided private key encryption key is not wrapped with XChaCha20-Poly1305.")
    }
    if v2.verifying_key.is_empty() || v2.signed_public_key.is_empty() || v2.security_state.is_empty() {
        err!("The v2 account keys are missing the verifying key, signed public key or security state")
    }

    if !user.is_v2() {
        // The v1 -> v2 upgrade, which is where the signature key pair comes from
        return Ok(());
    }

    let Some(key_pair) = UserSignatureKeyPair::find_by_user(&user.uuid, conn).await else {
        err!("The account is missing its signature key pair")
    };
    if key_pair.verifying_key != v2.verifying_key {
        err!("Changing the verifying key is not possible during key rotation")
    }

    Ok(())
}

/// `AesCbc256_HmacSha256_B64`, the v1 user key
const ENC_TYPE_AES_CBC_256_HMAC_SHA256: &str = "2";
/// `CoseEncrypt0B64`, the v2 user key
const ENC_TYPE_COSE_ENCRYPT0: &str = "7";

/// The encryption type of an EncString, the number before the first `.`.
fn enc_string_type(enc_string: &str) -> Option<&str> {
    enc_string.split_once('.').map(|(enc_type, _)| enc_type)
}

impl KDFData {
    /// Whether these are the settings the user already has, which a key rotation can't change.
    fn is_unchanged_for(&self, user: &User) -> bool {
        user.client_kdf_type == self.kdf
            && user.client_kdf_iter == self.kdf_iterations
            && user.client_kdf_memory == self.kdf_memory
            && user.client_kdf_parallelism == self.kdf_parallelism
    }
}

/// Every existing item must be in the rotation, or it would be unreadable afterwards.
fn validate_rotation_data(
    data: &RotateData,
    existing_ciphers: &[Cipher],
    existing_folders: &[Folder],
    existing_emergency_access: &[EmergencyAccess],
    existing_memberships: &[Membership],
    existing_sends: &[Send],
) -> EmptyResult {
    // Check that we're correctly rotating all the user's ciphers
    let provided_cipher_ids = data
        .account_data
        .ciphers
        .iter()
        .filter(|c| c.organization_id.is_none())
        .filter_map(|c| c.id.as_ref())
        .collect::<HashSet<&CipherId>>();
    if existing_ciphers.iter().any(|c| !provided_cipher_ids.contains(&c.uuid)) {
        err!("All existing ciphers must be included in the rotation")
    }

    // Check that we're correctly rotating all the user's folders
    let provided_folder_ids =
        data.account_data.folders.iter().filter_map(|f| f.id.as_ref()).collect::<HashSet<&FolderId>>();
    if existing_folders.iter().any(|f| !provided_folder_ids.contains(&f.uuid)) {
        err!("All existing folders must be included in the rotation")
    }

    // Check that we're correctly rotating all the user's emergency access keys
    let provided_emergency_access_ids =
        data.unlock_data.emergency_access_unlock_data.iter().map(|ea| &ea.id).collect::<HashSet<&EmergencyAccessId>>();
    if existing_emergency_access.iter().any(|ea| !provided_emergency_access_ids.contains(&ea.uuid)) {
        err!("All existing emergency access keys must be included in the rotation")
    }

    // Check that we're correctly rotating all the user's reset password keys
    let provided_reset_password_ids = data
        .unlock_data
        .organization_account_recovery_unlock_data
        .iter()
        .map(|rp| &rp.organization_id)
        .collect::<HashSet<&OrganizationId>>();
    if existing_memberships.iter().any(|m| !provided_reset_password_ids.contains(&m.org_uuid)) {
        err!("All existing reset password keys must be included in the rotation")
    }

    // Check that we're correctly rotating all the user's sends
    let provided_send_ids = data.account_data.sends.iter().filter_map(|s| s.id.as_ref()).collect::<HashSet<&SendId>>();
    if existing_sends.iter().any(|s| !provided_send_ids.contains(&s.uuid)) {
        err!("All existing sends must be included in the rotation")
    }

    Ok(())
}

/// The keys a rotation re-shares the new user key with. The SDK needs all four lists, even when empty.
///
/// Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Core/KeyManagement/UserKey/Queries/KeyRotationDataQuery.cs#L14-L122>
#[get("/accounts/key-management/key-rotation-data")]
async fn get_key_rotation_data(headers: Headers, conn: DbConn) -> JsonResult {
    let user_id = &headers.user.uuid;

    let mut organization_data = Vec::new();
    for membership in Membership::find_by_user(user_id, &conn).await {
        // Only memberships actually enrolled in account recovery take part in the rotation.
        if membership.reset_password_key.is_none() {
            continue;
        }
        let Some(org) = Organization::find_by_uuid(&membership.org_uuid, &conn).await else {
            continue;
        };
        let Some(public_key) = org.public_key else {
            continue;
        };
        organization_data.push(json!({
            "organizationId": org.uuid,
            "organizationName": org.name,
            "organizationPublicKey": public_key,
            "object": "organizationPasswordResetKeyData",
        }));
    }

    let mut emergency_access_data = Vec::new();
    for emergency_access in EmergencyAccess::find_all_confirmed_by_grantor_uuid(user_id, &conn).await {
        // Without a stored key there is nothing to re-share.
        if emergency_access.key_encrypted.is_none() {
            continue;
        }
        let Some(grantee_id) = emergency_access.grantee_uuid.clone() else {
            continue;
        };
        let Some(grantee) = User::find_by_uuid(&grantee_id, &conn).await else {
            continue;
        };
        let Some(public_key) = grantee.public_key.clone() else {
            continue;
        };
        emergency_access_data.push(json!({
            "id": emergency_access.uuid,
            "granteeId": grantee_id,
            "granteeName": grantee.name,
            "granteeEmail": grantee.email,
            "publicKey": public_key,
            "object": "emergencyAccessKeyData",
        }));
    }

    let trusted_device_data: Vec<_> = Device::find_by_user(user_id, &conn)
        .await
        .into_iter()
        .filter(Device::is_trusted)
        .map(|device| {
            json!({
                "id": device.uuid,
                "encryptedPublicKey": device.encrypted_public_key,
                "encryptedUserKey": device.encrypted_user_key,
                "object": "trustedDeviceKeyData",
            })
        })
        .collect();

    Ok(Json(json!({
        "organizationPasswordResetKeyData": organization_data,
        "emergencyAccessKeyData": emergency_access_data,
        "trustedDeviceKeyData": trusted_device_data,
        "passkeyKeyData": [],
        "object": "keyRotationData",
    })))
}

/// Everything a rotation replaces, once each endpoint's wrapper has been peeled off.
struct RotateData {
    account_keys: ValidatedAccountKeys,
    account_data: RotateAccountData,
    unlock_data: CommonUnlockData,
    /// The id of the key the client rotates from, `None` from clients that don't send it.
    old_user_key_id: Option<KeyId>,
    /// `None` from clients that predate key ids.
    new_user_key_id: Option<KeyId>,
    /// The new user key, wrapped by the master key.
    wrapped_user_key: String,
    /// Only for `rotate-user-account-keys`: the new password hash and hint.
    new_password: Option<(String, Option<String>)>,
}

/// Upstream's `[StringLength(max)]`, which counts UTF-16 code units.
fn validate_max_length(value: &str, max: usize, field: &str) -> EmptyResult {
    if value.encode_utf16().nth(max).is_some() {
        err!(format!("The field {field} must be a string with a maximum length of {max}."))
    }
    Ok(())
}

impl KDFData {
    /// Upstream's check that the parameters fit the KDF type.
    fn validate_parameters(&self) -> EmptyResult {
        let has_argon2_parameters = (self.kdf_memory.is_some(), self.kdf_parallelism.is_some());
        if self.kdf == UserKdfType::Pbkdf2 as i32 {
            if has_argon2_parameters != (false, false) {
                err!("KdfMemory and KdfParallelism must be null for PBKDF2_SHA256")
            }
        } else if self.kdf == UserKdfType::Argon2id as i32 {
            if has_argon2_parameters != (true, true) {
                err!("KdfMemory and KdfParallelism must have values for Argon2id")
            }
        } else {
            err!("Invalid KdfType")
        }
        Ok(())
    }

    /// Upstream's `KdfSettingsValidator.Validate`, the ranges the KDF of a master password that is being set must be
    /// in. Like upstream, a type it doesn't know isn't checked.
    /// Ref: <https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Core/Utilities/KdfSettingsValidator.cs#L111-L139>
    /// Ref: <https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Core/KeyManagement/Kdf/KdfConstants.cs#L10-L14>
    fn validate_new_settings(&self) -> EmptyResult {
        if self.kdf == UserKdfType::Pbkdf2 as i32 {
            if !(600_000..=2_000_000).contains(&self.kdf_iterations) {
                err!("KDF iterations must be between 600000 and 2000000.")
            }
        } else if self.kdf == UserKdfType::Argon2id as i32 {
            if !(2..=10).contains(&self.kdf_iterations) {
                err!("Argon2 iterations must be between 2 and 10.")
            }
            if !self.kdf_memory.is_some_and(|memory| (15..=1024).contains(&memory)) {
                err!("Argon2 memory must be between 15mb and 1024mb.")
            }
            if !self.kdf_parallelism.is_some_and(|parallelism| (1..=16).contains(&parallelism)) {
                err!("Argon2 parallelism must be between 1 and 16.")
            }
        }
        Ok(())
    }
}

impl MasterPasswordUnlockData {
    /// Upstream's model validation.
    ///
    /// Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Api/KeyManagement/Models/Requests/MasterPasswordUnlockDataAndAuthenticationModel.cs#L8-L48>
    fn validate(&self) -> EmptyResult {
        self.kdf.validate_parameters()?;
        if !crate::util::is_valid_email(&self.email) {
            err!("The Email field is not a supported e-mail address format.")
        }
        validate_max_length(&self.email, 256, "Email")?;
        required(Some(self.master_key_authentication_hash.clone()), "MasterKeyAuthenticationHash")?;
        validate_max_length(&self.master_key_authentication_hash, 300, "MasterKeyAuthenticationHash")?;
        required(Some(self.master_key_encrypted_user_key.clone()), "MasterKeyEncryptedUserKey")?;
        if let Some(hint) = &self.master_password_hint {
            validate_max_length(hint, 50, "MasterPasswordHint")?;
        }
        if self.master_password_salt.as_ref().is_some_and(|salt| salt.encode_utf16().nth(256).is_some()) {
            err!("The field MasterPasswordSalt must be a string or array type with a maximum length of '256'.")
        }
        Ok(())
    }
}

impl CommonUnlockData {
    /// Upstream's model validation.
    fn validate(&self) -> EmptyResult {
        // Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Api/Auth/Models/Request/EmergencyAccessRequestModels.cs#L32-L39>
        for emergency_access in &self.emergency_access_unlock_data {
            if !emergency_access.wait_time_days.is_some_and(|days| (1..=i32::from(i16::MAX)).contains(&days)) {
                err!("The field WaitTimeDays must be between 1 and 32767.")
            }
        }
        if let Some(token) = &self.v2_upgrade_token {
            required(Some(token.wrapped_user_key1.clone()), "WrappedUserKey1")?;
            required(Some(token.wrapped_user_key2.clone()), "WrappedUserKey2")?;
        }
        Ok(())
    }
}

/// The model validation of the parts both rotation endpoints share, which upstream runs before anything else.
fn validate_rotation_request(account_data: &RotateAccountData, unlock_data: &CommonUnlockData) -> EmptyResult {
    unlock_data.validate()?;

    // Validate the import before continuing
    // Bitwarden does not process the import if there is one item invalid.
    // Since we check for the size of the encrypted note length, we need to do that here to pre-validate it.
    // TODO: See if we can optimize the whole cipher adding/importing and prevent duplicate code and checks.
    Cipher::validate_cipher_data(&account_data.ciphers)?;

    if account_data.ciphers.iter().any(|cipher| cipher.id.is_none()) {
        err!("The Id field is required.")
    }
    if account_data.sends.iter().any(|send| send.id.is_none()) {
        err!("The Id field is required.")
    }
    Ok(())
}

#[post("/accounts/key-management/rotate-user-account-keys", data = "<data>")]
async fn post_rotatekey(data: Json<KeyData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: KeyData = data.into_inner();

    let unlock_data = data.account_unlock_data.master_password_unlock_data;
    validate_max_length(&data.old_master_key_authentication_hash, 300, "OldMasterKeyAuthenticationHash")?;
    unlock_data.validate()?;
    validate_rotation_request(&data.account_data, &data.account_unlock_data.common)?;

    if !headers.user.check_valid_password(&data.old_master_key_authentication_hash) {
        err!("Invalid password")
    }

    // Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Core/KeyManagement/UserKey/Models/Data/PasswordChangeAndRotateUserAccountKeysData.cs#L17-L32>
    let salt = unlock_data.master_password_salt.as_ref().unwrap_or(&unlock_data.email);
    if !unlock_data.kdf.is_unchanged_for(&headers.user) || *salt != headers.user.master_password_salt() {
        err!("The provided master password unlock data is not valid for this user.")
    }
    validate_contained_key_id(unlock_data.contained_key_id.as_ref(), data.new_user_key_id.as_ref())?;
    let password_hint = clean_password_hint(unlock_data.master_password_hint.as_ref());
    enforce_password_hint_setting(password_hint.as_ref())?;

    let mut common = data.account_unlock_data.common;
    // Like upstream, this endpoint logs every session out, so an upgrade token is never kept
    // Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Core/KeyManagement/UserKey/Implementations/RotateUserAccountKeysCommand.cs#L94-L96>
    common.v2_upgrade_token = None;

    rotate_account(
        RotateData {
            account_keys: data.account_keys.validate()?,
            account_data: data.account_data,
            unlock_data: common,
            old_user_key_id: data.old_user_key_id,
            new_user_key_id: data.new_user_key_id,
            wrapped_user_key: unlock_data.master_key_encrypted_user_key,
            new_password: Some((unlock_data.master_key_authentication_hash, password_hint)),
        },
        headers,
        conn,
        nt,
    )
    .await
}

/// Both rotation endpoints: every check first, then the re-encrypted data and the new keys are saved.
async fn rotate_account(data: RotateData, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let user_id = &headers.user.uuid;
    let mut existing_ciphers = Cipher::find_owned_by_user(user_id, &conn).await;
    let mut existing_folders = Folder::find_by_user(user_id, &conn).await;
    let mut existing_emergency_access = EmergencyAccess::find_all_confirmed_by_grantor_uuid(user_id, &conn).await;
    // Like upstream, only the ones with a key take part
    existing_emergency_access.retain(|ea| ea.key_encrypted.is_some());
    let mut existing_memberships = Membership::find_by_user(user_id, &conn).await;
    // We only rotate the reset password key if it is set.
    existing_memberships.retain(|m| m.reset_password_key.is_some());
    let mut existing_sends = Send::find_by_user(user_id, &conn).await;
    let existing_devices = Device::find_by_user(user_id, &conn).await;

    validate_rotation_data(
        &data,
        &existing_ciphers,
        &existing_folders,
        &existing_emergency_access,
        &existing_memberships,
        &existing_sends,
    )?;

    let rotated_devices = validate_device_keydata(&data.unlock_data.device_key_unlock_data, &existing_devices)?;

    // Like upstream, a client that rotates a user key that was already replaced has to sync first
    // Ref: <https://github.com/bitwarden/server/blob/15c94ac58bf361a162381749c146d254a21b2098/src/Core/KeyManagement/UserKey/Models/Data/BaseRotateUserAccountKeysData.cs#L34-L46>
    if let (Some(current), Some(old)) = (&headers.user.key_id, &data.old_user_key_id)
        && current != old
    {
        err_code!("The user key being rotated is not the current user key. Sync and try again.", Status::Conflict.code)
    }

    validate_rotation_account_keys(&data.account_keys, &headers.user, &conn).await?;

    // An upgrade keeps the sessions; for an account already on v2 the token means nothing and is dropped
    let is_upgrade = data.unlock_data.v2_upgrade_token.is_some() && !headers.user.is_v2();
    let upgrade_token = match &data.unlock_data.v2_upgrade_token {
        Some(token) if is_upgrade => Some(serde_json::to_string(token)?),
        _ => None,
    };

    // An upgrade can't re-wrap the recovery keys without a trust prompt, so they're kept and get the token
    // Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Api/KeyManagement/Validators/OrganizationUserRotationValidator.cs#L39-L64>
    for membership in &existing_memberships {
        let has_key = data
            .unlock_data
            .organization_account_recovery_unlock_data
            .iter()
            .find(|rp| rp.organization_id == membership.org_uuid)
            .and_then(|rp| rp.reset_password_key.as_deref())
            .is_some_and(|key| !key.trim().is_empty());
        if is_upgrade && has_key {
            err!("Account recovery keys cannot be rotated during a V1 to V2 upgrade rotation.")
        }
        if !is_upgrade && !has_key {
            err!("Account recovery keys cannot be null or empty during rotation.")
        }
    }

    // Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Api/KeyManagement/Validators/EmergencyAccessRotationValidator.cs#L23-L53>
    for emergency_access in &existing_emergency_access {
        if data
            .unlock_data
            .emergency_access_unlock_data
            .iter()
            .find(|ea| ea.id == emergency_access.uuid)
            .is_some_and(|ea| ea.key_encrypted.is_none())
        {
            err!("Emergency access keys cannot be set to null during rotation.")
        }
    }

    // Saving's own checks, so that they can't fail halfway
    for cipher_data in data.account_data.ciphers.iter().filter(|c| c.organization_id.is_none()) {
        if let Some(cipher) = existing_ciphers.iter().find(|c| cipher_data.id.as_ref() == Some(&c.uuid)) {
            validate_rotated_cipher(cipher, cipher_data, &headers, &conn).await?;
        }
    }

    // TODO: Ideally we'd do everything after this point in a single transaction.

    // Update folder data, ignoring ids that aren't the user's, like upstream
    for folder_data in data.account_data.folders {
        // Skip `null` folder id entries.
        // See: https://github.com/bitwarden/clients/issues/8453
        if let Some(saved_folder) = folder_data.id.and_then(|id| existing_folders.iter_mut().find(|f| f.uuid == id)) {
            saved_folder.name = folder_data.name;
            saved_folder.save(&conn).await?;
        }
    }

    // Like upstream, the unlock data below comes from the first entry for each, as checked above
    for saved_emergency_access in &mut existing_emergency_access {
        if let Some(emergency_access_data) =
            data.unlock_data.emergency_access_unlock_data.iter().find(|ea| ea.id == saved_emergency_access.uuid)
        {
            saved_emergency_access.key_encrypted.clone_from(&emergency_access_data.key_encrypted);
            saved_emergency_access.save(&conn).await?;
        }
    }

    for membership in &mut existing_memberships {
        if let Some(reset_password_data) = data
            .unlock_data
            .organization_account_recovery_unlock_data
            .iter()
            .find(|rp| rp.organization_id == membership.org_uuid)
        {
            if !is_upgrade {
                membership.reset_password_key.clone_from(&reset_password_data.reset_password_key);
            }
            membership.v2_upgrade_token.clone_from(&upgrade_token);
            membership.save(&conn).await?;
        }
    }

    // Update send data
    for send_data in data.account_data.sends {
        if let Some(send) = send_data.id.as_ref().and_then(|id| existing_sends.iter_mut().find(|s| &s.uuid == id)) {
            // Like upstream, only the key changes on rotation
            send.akey = send_data.key;
            send.save(&conn).await?;
        }
    }

    // Update cipher data
    for cipher_data in data.account_data.ciphers {
        if cipher_data.organization_id.is_none()
            && let Some(saved_cipher) =
                cipher_data.id.as_ref().and_then(|id| existing_ciphers.iter_mut().find(|c| &c.uuid == id))
        {
            // No cipher pushes: the other sessions still hold the old user key
            rotate_cipher_data(saved_cipher, cipher_data, &headers, &conn, &nt).await?;
        }
    }

    Device::update_keys_for_rotation(&headers.user.uuid, rotated_devices, &conn).await?;

    // Update user data
    let mut user = headers.user;
    user.v2_upgrade_token = upgrade_token;

    data.account_keys.apply(&mut user)?;
    // The old id names a key that no longer exists, so it is replaced even when the new key has none.
    user.key_id = data.new_user_key_id;

    user.akey = data.wrapped_user_key;
    if let Some((new_password_hash, new_password_hint)) = data.new_password {
        // A password change ends every session, as `/accounts/password` does
        user.password_hint = new_password_hint;
        user.set_password(&new_password_hash, None, true, None, &conn).await?;
    } else if !is_upgrade {
        // An upgrade keeps the sessions alive, see `is_upgrade` above
        user.reset_security_stamp_after_key_rotation(&conn).await?;
    }

    // The key pair first, so that a v2 account is never saved without one. The data above is already re-encrypted by
    // now, and for an account that was already v2 so is the signing key saved here, so a failure in either save
    // leaves them under a key that isn't stored (see the TODO before the first write).
    data.account_keys.save_signature_key_pair(&user.uuid, &conn).await?;
    user.save(&conn).await?;

    // Prevent logging out the client where the user requested this endpoint from.
    // If you do logout the user it will causes issues at the client side.
    // Adding the device uuid will prevent this.
    // On an upgrade, the reason lets clients sync instead
    let reason = is_upgrade.then_some(LogOutReason::KeyRotation);
    nt.send_logout_with_reason(&user, Some(&headers.device), reason, &conn).await;

    Ok(())
}

/// Rotates the keys without changing the master password; like upstream, the session is the only proof.
///
/// Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Api/KeyManagement/Controllers/AccountsKeyManagementController.cs#L174-L208>
#[post("/accounts/key-management/rotate-user-keys", data = "<data>")]
async fn post_rotate_user_keys(
    data: Json<RotateUserKeysData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let data: RotateUserKeysData = data.into_inner();
    validate_rotation_request(&data.account_data, &data.unlock_data)?;

    // Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Api/KeyManagement/Models/Requests/UnlockMethodRequestModel.cs#L20-L46>
    let wrapped_user_key = match UnlockMethod::from_i32(data.unlock_method_data.unlock_method) {
        Some(UnlockMethod::MasterPassword) => {
            let (Some(unlock_data), None) = (
                data.unlock_method_data.master_password_unlock_data,
                data.unlock_method_data.key_connector_key_wrapped_user_key,
            ) else {
                err!(
                    "Invalid MasterPassword unlock method request, MasterPasswordUnlockData must be provided and KeyConnectorKeyWrappedUserKey must be null"
                )
            };
            required(Some(unlock_data.master_key_wrapped_user_key.clone()), "MasterKeyWrappedUserKey")?;
            required(Some(unlock_data.salt.clone()), "Salt")?;
            validate_max_length(&unlock_data.salt, 256, "Salt")?;

            // Ref: <https://github.com/bitwarden/server/blob/9030c42bf7d8f9ac2ff9fee85c39588d5eb81499/src/Core/KeyManagement/UserKey/Models/Data/MasterPasswordRotateUserAccountKeysData.cs#L12-L23>
            if headers.user.password_hash.is_empty() || headers.user.akey.is_empty() {
                err!("User is in an invalid state for master password key rotation.")
            }
            if unlock_data.salt != headers.user.master_password_salt() {
                err!("Invalid master password salt.")
            }
            if !unlock_data.kdf.is_unchanged_for(&headers.user) {
                err!("Invalid KDF settings.")
            }
            validate_contained_key_id(unlock_data.contained_key_id.as_ref(), data.new_user_key_id.as_ref())?;
            unlock_data.master_key_wrapped_user_key
        }
        Some(UnlockMethod::Tde) => {
            data.unlock_method_data.validate_tde(&headers.user)?;
            // A passwordless account has no master-key-wrapped user key to replace.
            String::new()
        }
        Some(UnlockMethod::KeyConnector) => err!("Key connector is not supported"),
        None => err!("Unrecognized unlock method"),
    };

    rotate_account(
        RotateData {
            account_keys: data.wrapped_account_cryptographic_state.validate()?,
            account_data: data.account_data,
            unlock_data: data.unlock_data,
            old_user_key_id: data.old_user_key_id,
            new_user_key_id: data.new_user_key_id,
            wrapped_user_key,
            new_password: None,
        },
        headers,
        conn,
        nt,
    )
    .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyIdData {
    user_key_id: KeyId,
}

#[post("/accounts/key-management/user-key-id", data = "<data>")]
async fn post_user_key(data: Json<KeyIdData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let mut user = headers.user;
    // Only a backfill for accounts that have none. Afterwards the id changes with the key, in a rotation.
    if user.key_id.is_some() {
        err!("User key id is already set.")
    }

    user.key_id = Some(data.into_inner().user_key_id);
    user.save(&conn).await
}

#[post("/accounts/security-stamp", data = "<data>")]
async fn post_sstamp(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: PasswordOrOtpData = data.into_inner();
    let mut user = headers.user;

    data.validate(&mut user, true, &conn).await?;

    // Ends the sessions of the devices, which are kept, so that trusted devices still unlock after the next login, as
    // upstream's do
    user.reset_security_stamp(&conn).await?;
    let save_result = user.save(&conn).await;

    nt.send_logout(&user, None, &conn).await;

    save_result
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmailTokenData {
    master_password_hash: String,
    new_email: String,
}

#[post("/accounts/email-token", data = "<data>")]
async fn post_email_token(data: Json<EmailTokenData>, headers: Headers, conn: DbConn) -> EmptyResult {
    if !CONFIG.email_change_allowed() {
        err!("Email change is not allowed.");
    }

    let data: EmailTokenData = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    if let Some(existing_user) = User::find_by_mail(&data.new_email, &conn).await {
        if CONFIG.mail_enabled() {
            // check if existing_user has already registered
            if existing_user.password_hash.is_empty() {
                // inform an invited user about how to delete their temporary account if the
                // request was done intentionally and they want to update their mail address
                if let Err(e) = mail::send_change_email_invited(&data.new_email, &user.email).await {
                    error!("Error sending change-email-invited email: {e:#?}");
                }
            } else {
                // inform existing user about the failed attempt to change their mail address
                if let Err(e) = mail::send_change_email_existing(&data.new_email, &user.email).await {
                    error!("Error sending change-email-existing email: {e:#?}");
                }
            }
        }
        err!("Email already in use");
    }

    if !CONFIG.is_email_domain_allowed(&data.new_email) {
        err!("Email domain not allowed");
    }

    let token = crypto::generate_email_token(6);

    if CONFIG.mail_enabled() {
        if let Err(e) = mail::send_change_email(&data.new_email, &token).await {
            error!("Error sending change-email email: {e:#?}");
        }
    } else {
        debug!(
            "Email change request for user ({}) to email ({}) with token ({token})",
            user.uuid,
            data.new_email.escape_debug()
        );
    }

    user.email_new = Some(data.new_email);
    user.email_new_token = Some(token);
    user.save(&conn).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangeEmailData {
    master_password_hash: String,
    new_email: String,

    key: String,
    new_master_password_hash: String,
    token: NumberOrString,
}

#[post("/accounts/email", data = "<data>")]
async fn post_email(data: Json<ChangeEmailData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    if !CONFIG.email_change_allowed() {
        err!("Email change is not allowed.");
    }

    let data: ChangeEmailData = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    if User::find_by_mail(&data.new_email, &conn).await.is_some() {
        err!("Email already in use");
    }

    if let Some(ref val) = user.email_new {
        if val != &data.new_email {
            err!("Email change mismatch");
        }
    } else {
        err!("No email change pending")
    }

    if CONFIG.mail_enabled() {
        // Only check the token if we sent out an email...
        if let Some(ref val) = user.email_new_token {
            if *val != data.token.into_string() {
                err!("Token mismatch");
            }
        } else {
            err!("No email change pending")
        }
        user.verified_at = Some(Utc::now().naive_utc());
    } else {
        user.verified_at = None;
    }

    user.email = data.new_email;
    user.email_new = None;
    user.email_new_token = None;

    user.set_password(&data.new_master_password_hash, Some(data.key), true, None, &conn).await?;

    let save_result = user.save(&conn).await;

    nt.send_logout(&user, None, &conn).await;

    save_result
}

#[post("/accounts/verify-email")]
async fn post_verify_email(headers: Headers) -> EmptyResult {
    let user = headers.user;

    if !CONFIG.mail_enabled() {
        err!("Cannot verify email address");
    }

    if let Err(e) = mail::send_verify_email(&user.email, &user.uuid).await {
        error!("Error sending verify_email email: {e:#?}");
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyEmailTokenData {
    user_id: UserId,
    token: String,
}

#[post("/accounts/verify-email-token", data = "<data>")]
async fn post_verify_email_token(data: Json<VerifyEmailTokenData>, conn: DbConn) -> EmptyResult {
    let data: VerifyEmailTokenData = data.into_inner();

    let Some(mut user) = User::find_by_uuid(&data.user_id, &conn).await else {
        err!("User doesn't exist")
    };

    let Ok(claims) = decode_verify_email(&data.token) else {
        err!("Invalid claim")
    };
    if claims.sub != *user.uuid {
        err!("Invalid claim");
    }
    user.verified_at = Some(Utc::now().naive_utc());
    user.last_verifying_at = None;
    user.login_verify_count = 0;
    if let Err(e) = user.save(&conn).await {
        error!("Error saving email verification: {e:#?}");
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteRecoverData {
    email: String,
}

#[post("/accounts/delete-recover", data = "<data>")]
async fn post_delete_recover(data: Json<DeleteRecoverData>, ip: ClientIp, conn: DbConn) -> EmptyResult {
    crate::ratelimit::check_limit_unauthenticated(&ip.ip)?;

    let data: DeleteRecoverData = data.into_inner();

    if CONFIG.mail_enabled() {
        if let Some(user) = User::find_by_mail(&data.email, &conn).await
            && let Err(e) = mail::send_delete_account(&user.email, &user.uuid).await
        {
            error!("Error sending delete account email: {e:#?}");
        }
        Ok(())
    } else {
        // We don't support sending emails, but we shouldn't allow anybody
        // to delete accounts without at least logging in... And if the user
        // cannot remember their password then they will need to contact
        // the administrator to delete it...
        err!("Please contact the administrator to delete your account");
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteRecoverTokenData {
    user_id: UserId,
    token: String,
}

#[post("/accounts/delete-recover-token", data = "<data>")]
async fn post_delete_recover_token(data: Json<DeleteRecoverTokenData>, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: DeleteRecoverTokenData = data.into_inner();

    let Ok(claims) = decode_delete(&data.token) else {
        err!("Invalid claim")
    };

    let Some(user) = User::find_by_uuid(&data.user_id, &conn).await else {
        err!("User doesn't exist")
    };

    if claims.sub != *user.uuid {
        err!("Invalid claim");
    }

    // The devices are deleted together with the user, so check for push devices beforehand
    let has_push_device = CONFIG.push_enabled() && Device::check_user_has_push_device(&user.uuid, &conn).await;
    user.delete(&conn).await?;

    nt.send_logout(&user, None, &conn).await;
    if has_push_device {
        push_logout_to_relay(&user, None, None);
    }
    Ok(())
}

#[post("/accounts/delete", data = "<data>")]
async fn post_delete_account(
    data: Json<PasswordOrOtpData>,
    headers: Headers,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    delete_account(data, headers, conn, nt).await
}

#[delete("/accounts", data = "<data>")]
async fn delete_account(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn, nt: Notify<'_>) -> EmptyResult {
    let data: PasswordOrOtpData = data.into_inner();
    let mut user = headers.user;

    data.validate(&mut user, true, &conn).await?;

    // The devices are deleted together with the user, so check for push devices beforehand
    let has_push_device = CONFIG.push_enabled() && Device::check_user_has_push_device(&user.uuid, &conn).await;
    user.delete(&conn).await?;

    nt.send_logout(&user, None, &conn).await;
    if has_push_device {
        push_logout_to_relay(&user, None, None);
    }
    Ok(())
}

#[expect(clippy::needless_pass_by_value, reason = "Not beneficial for Headers")]
#[get("/accounts/revision-date")]
fn revision_date(headers: Headers) -> JsonResult {
    let revision_date = headers.user.updated_at.and_utc().timestamp_millis();
    Ok(Json(json!(revision_date)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordHintData {
    email: String,
}

#[post("/accounts/password-hint", data = "<data>")]
async fn password_hint(data: Json<PasswordHintData>, ip: ClientIp, conn: DbConn) -> EmptyResult {
    const NO_HINT: &str = "Sorry, you have no password hint...";

    crate::ratelimit::check_limit_unauthenticated(&ip.ip)?;

    if !CONFIG.password_hints_allowed() || (!CONFIG.mail_enabled() && !CONFIG.show_password_hint()) {
        err!("This server is not configured to provide password hints.");
    }

    let data: PasswordHintData = data.into_inner();
    let email = &data.email;

    match User::find_by_mail(email, &conn).await {
        None => {
            // To prevent user enumeration, act as if the user exists.
            if CONFIG.mail_enabled() {
                // There is still a timing side channel here in that the code
                // paths that send mail take noticeably longer than ones that
                // don't. Add a randomized sleep to mitigate this somewhat.
                use rand::{RngExt, rngs::SmallRng};
                let mut rng: SmallRng = rand::make_rng();
                let sleep_ms: u64 = rng.random_range(900..=1100);
                tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)).await;
                Ok(())
            } else {
                err!(NO_HINT);
            }
        }
        Some(user) => {
            let hint: Option<String> = user.password_hint;
            if CONFIG.mail_enabled() {
                mail::send_password_hint(email, hint).await?;
                Ok(())
            } else if let Some(hint) = hint {
                err_silent!(format!("Your password hint is: {hint}"));
            } else {
                err!(NO_HINT);
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginData {
    email: String,
}

/// Like upstream, an unknown email gets KDF settings picked from a list of common ones by a keyed hash of the email,
/// so they stay the same between requests. The salt stays null, as for existing users.
fn unknown_email_kdf(email: &str) -> (i32, i32, Option<i32>, Option<i32>) {
    const PBKDF2: i32 = UserKdfType::Pbkdf2 as i32;
    const ARGON2ID: i32 = UserKdfType::Argon2id as i32;
    // Same list as upstream, the default is in it twice to give it more weight
    let kdf_settings: [(i32, i32, Option<i32>, Option<i32>); 6] = [
        (User::CLIENT_KDF_TYPE_DEFAULT, CONFIG.client_kdf_iter(), None, None),
        (User::CLIENT_KDF_TYPE_DEFAULT, CONFIG.client_kdf_iter(), None, None),
        (PBKDF2, 100_000, None, None),
        (PBKDF2, 5_000, None, None),
        (ARGON2ID, 3, Some(64), Some(4)),
        (ARGON2ID, 6, Some(32), Some(4)),
    ];
    kdf_settings[crate::auth::prelogin_kdf_index(email, kdf_settings.len())]
}

pub async fn prelogin(data: Json<PreloginData>, ip: ClientIp, conn: DbConn) -> JsonResult {
    crate::ratelimit::check_limit_unauthenticated(&ip.ip)?;

    let data: PreloginData = data.into_inner();
    // Normalized once, so the lookup and the settings for an unknown email use the same value
    let email = data.email.trim().to_lowercase();

    let (kdf_type, kdf_iter, kdf_mem, kdf_para) = match User::find_by_mail(&email, &conn).await {
        Some(user) => (user.client_kdf_type, user.client_kdf_iter, user.client_kdf_memory, user.client_kdf_parallelism),
        None => unknown_email_kdf(&email),
    };

    Ok(Json(json!({
        "kdf": kdf_type,
        "kdfIterations": kdf_iter,
        "kdfMemory": kdf_mem,
        "kdfParallelism": kdf_para,
        "kdfSettings": {
            "iterations": kdf_iter,
            "kdfType": kdf_type,
            "memory": kdf_mem,
            "parallelism": kdf_para
        },
        "salt": null,
    })))
}

// https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/Auth/Models/Request/Accounts/SecretVerificationRequestModel.cs
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecretVerificationRequest {
    master_password_hash: String,
}

#[post("/accounts/verify-password", data = "<data>")]
async fn verify_password(data: Json<SecretVerificationRequest>, headers: Headers, conn: DbConn) -> JsonResult {
    let data: SecretVerificationRequest = data.into_inner();
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    user.check_persist_kdf_upgrade(&data.master_password_hash, &conn).await?;

    Ok(Json(master_password_policy(&user, &conn).await))
}

async fn update_api_key(data: Json<PasswordOrOtpData>, rotate: bool, headers: Headers, conn: DbConn) -> JsonResult {
    let data: PasswordOrOtpData = data.into_inner();
    let mut user = headers.user;

    data.validate(&mut user, true, &conn).await?;

    if rotate || user.api_key.is_none() {
        user.api_key = Some(crypto::generate_api_key());
        user.save(&conn).await.expect("Error saving API key");
    }

    Ok(Json(json!({
      "apiKey": user.api_key,
      "revisionDate": format_date(&user.updated_at),
      "object": "apiKey",
    })))
}

#[post("/accounts/api-key", data = "<data>")]
async fn post_api_key(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> JsonResult {
    update_api_key(data, false, headers, conn).await
}

#[post("/accounts/rotate-api-key", data = "<data>")]
async fn rotate_api_key(data: Json<PasswordOrOtpData>, headers: Headers, conn: DbConn) -> JsonResult {
    update_api_key(data, true, headers, conn).await
}

#[get("/devices/knowndevice")]
async fn get_known_device(device: KnownDevice, conn: DbConn) -> JsonResult {
    let result = if let Some(user) = User::find_by_mail(&device.email, &conn).await {
        Device::find_by_uuid_and_user(&device.uuid, &user.uuid, &conn).await.is_some()
    } else {
        false
    };
    Ok(Json(json!(result)))
}

struct KnownDevice {
    email: String,
    uuid: DeviceId,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for KnownDevice {
    type Error = &'static str;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let email = if let Some(email_b64) = req.headers().get_one("X-Request-Email") {
            // Bitwarden seems to send padded Base64 strings since 2026.2.1
            // Since these values are not streamed and Headers are always split by newlines
            // we can safely ignore padding here and remove any '=' appended.
            let email_b64 = email_b64.trim_end_matches('=');

            let Ok(email_bytes) = data_encoding::BASE64URL_NOPAD.decode(email_b64.as_bytes()) else {
                return Outcome::Error((Status::BadRequest, "X-Request-Email value failed to decode as base64url"));
            };
            match String::from_utf8(email_bytes) {
                Ok(email) => email,
                Err(_) => {
                    return Outcome::Error((Status::BadRequest, "X-Request-Email value failed to decode as UTF-8"));
                }
            }
        } else {
            return Outcome::Error((Status::BadRequest, "X-Request-Email value is required"));
        };

        let uuid = if let Some(uuid) = req.headers().get_one("X-Device-Identifier") {
            uuid.to_owned().into()
        } else {
            return Outcome::Error((Status::BadRequest, "X-Device-Identifier value is required"));
        };

        Outcome::Success(Self {
            email,
            uuid,
        })
    }
}

#[get("/devices")]
async fn get_all_devices(headers: Headers, conn: DbConn) -> JsonResult {
    let devices = Device::find_with_auth_request_by_user(&headers.user.uuid, &conn).await;
    let devices = devices.iter().map(DeviceWithAuthRequest::to_json).collect::<Vec<Value>>();

    Ok(Json(json!({
        "data": devices,
        "continuationToken": null,
        "object": "list"
    })))
}

#[get("/devices/identifier/<device_id>")]
async fn get_device(device_id: DeviceId, headers: Headers, conn: DbConn) -> JsonResult {
    let Some(device) = Device::find_by_uuid_and_user(&device_id, &headers.user.uuid, &conn).await else {
        err!("No device found");
    };
    Ok(Json(device.to_json()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PushToken {
    push_token: String,
}

#[post("/devices/identifier/<device_id>/token", data = "<data>")]
async fn post_device_token(device_id: DeviceId, data: Json<PushToken>, headers: Headers, conn: DbConn) -> EmptyResult {
    put_device_token(device_id, data, headers, conn).await
}

#[put("/devices/identifier/<device_id>/token", data = "<data>")]
async fn put_device_token(device_id: DeviceId, data: Json<PushToken>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data = data.into_inner();
    let token = data.push_token;

    let Some(mut device) = Device::find_by_uuid_and_user(&headers.device.uuid, &headers.user.uuid, &conn).await else {
        err!(format!("Error: device {device_id} should be present before a token can be assigned"))
    };

    // Check if the new token is the same as the registered token
    // Although upstream seems to always register a device on login, we do not.
    // Unless this causes issues, lets keep it this way, else we might need to also register on every login.
    if device.push_token.as_ref() == Some(&token) {
        debug!("Device {device_id} for user {} is already registered and token is identical", headers.user.uuid);
        return Ok(());
    }

    device.push_token = Some(token);
    if let Err(e) = device.save(true, &conn).await {
        err!(format!("An error occurred while trying to save the device push token: {e}"));
    }

    register_push_device(&mut device, &conn).await?;

    Ok(())
}

#[put("/devices/identifier/<device_id>/clear-token")]
async fn put_clear_device_token(device_id: DeviceId, ip: ClientIp, conn: DbConn) -> EmptyResult {
    crate::ratelimit::check_limit_unauthenticated(&ip.ip)?;

    // This only clears push token
    // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Api/Controllers/DevicesController.cs#L215
    // https://github.com/bitwarden/server/blob/9ebe16587175b1c0e9208f84397bb75d0d595510/src/Core/Services/Implementations/DeviceService.cs#L37
    // This is somehow not implemented in any app, added it in case it is required
    // 2025: Also, it looks like it only clears the first found device upstream, which is probably faulty.
    //       This because currently multiple accounts could be on the same device/app and that would cause issues.
    //       Vaultwarden removes the push-token for all devices, but this probably means we should also unregister all these devices.
    if !CONFIG.push_enabled() {
        return Ok(());
    }

    if let Some(device) = Device::find_by_uuid(&device_id, &conn).await {
        Device::clear_push_token_by_uuid(&device_id, &conn).await?;
        unregister_push_device(device.push_uuid.as_ref()).await?;
    }

    Ok(())
}

// On upstream server, both PUT and POST are declared. Implementing the POST method in case it would be useful somewhere
#[post("/devices/identifier/<device_id>/clear-token")]
async fn post_clear_device_token(device_id: DeviceId, ip: ClientIp, conn: DbConn) -> EmptyResult {
    put_clear_device_token(device_id, ip, conn).await
}

// Trusted device encryption
// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Api/Controllers/DevicesController.cs>

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrustedDeviceKeysData {
    encrypted_user_key: String,
    encrypted_public_key: String,
    encrypted_private_key: String,
}

#[put("/devices/<device_id>/keys", data = "<data>")]
async fn put_device_keys(
    device_id: DeviceId,
    data: Json<TrustedDeviceKeysData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    let data = data.into_inner();

    validate_enc_string("EncryptedUserKey", Some(&data.encrypted_user_key))?;
    validate_enc_string("EncryptedPublicKey", Some(&data.encrypted_public_key))?;
    validate_enc_string("EncryptedPrivateKey", Some(&data.encrypted_private_key))?;

    let Some(mut device) = Device::find_by_uuid_and_user(&device_id, &headers.user.uuid, &conn).await else {
        err_code!("Resource not found.", "No device found", Status::NotFound.code)
    };

    device.encrypted_user_key = Some(data.encrypted_user_key);
    device.encrypted_public_key = Some(data.encrypted_public_key);
    device.encrypted_private_key = Some(data.encrypted_private_key);
    device.save_trust_keys(&conn).await?;

    Ok(Json(device.to_json()))
}

#[post("/devices/<device_id>/keys", data = "<data>")]
async fn post_device_keys(
    device_id: DeviceId,
    data: Json<TrustedDeviceKeysData>,
    headers: Headers,
    conn: DbConn,
) -> JsonResult {
    put_device_keys(device_id, data, headers, conn).await
}

#[post("/devices/<device_id>/retrieve-keys")]
async fn post_device_retrieve_keys(device_id: DeviceId, headers: Headers, conn: DbConn) -> JsonResult {
    let Some(device) = Device::find_by_uuid_and_user(&device_id, &headers.user.uuid, &conn).await else {
        err_code!("Resource not found.", "No device found", Status::NotFound.code)
    };

    Ok(Json(device.to_protected_json()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UntrustDevicesData {
    devices: Vec<DeviceId>,
}

#[post("/devices/untrust", data = "<data>")]
async fn post_devices_untrust(data: Json<UntrustDevicesData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data = data.into_inner();

    let owned: HashSet<DeviceId> =
        Device::find_by_user(&headers.user.uuid, &conn).await.into_iter().map(|device| device.uuid).collect();

    if let Some(unknown) = data.devices.iter().find(|device_id| !owned.contains(*device_id)) {
        err_code!(
            "Unauthorized.",
            format!("User {} does not have access to device {unknown}", headers.user.uuid),
            Status::Unauthorized.code
        )
    }

    Device::untrust_many(&headers.user.uuid, data.devices, &conn).await
}

// No `POST /devices/update-trust`: no client calls it, the key rotation re-wraps the device keys, and upstream removed
// it for that reason.
// Ref: <https://github.com/bitwarden/server/commit/9edf11112df3de36de87b20635f9f1ac591fd883>

#[expect(clippy::needless_pass_by_value, reason = "Not beneficial for Headers")]
#[post("/devices/lost-trust")]
fn post_devices_lost_trust(headers: Headers) -> EmptyResult {
    error!(
        "User {} has a device key, but didn't receive decryption keys for device {} of type {}",
        headers.user.uuid,
        headers.device.uuid,
        DeviceType::from_i32(headers.device.atype)
    );

    Ok(())
}

/// Upstream deactivates the device, which hides it and drops its keys. Removing it does both here, and also ends its
/// session, as its refresh token goes with it.
/// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Core/Services/Implementations/DeviceService.cs>
#[delete("/devices/<device_id>")]
async fn delete_device(device_id: DeviceId, headers: Headers, conn: DbConn) -> EmptyResult {
    let Some(device) = Device::find_by_uuid_and_user(&device_id, &headers.user.uuid, &conn).await else {
        err_code!("Resource not found.", "No device found", Status::NotFound.code)
    };

    if let Err(e) = unregister_push_device(device.push_uuid.as_ref()).await {
        error!("Unable to unregister the device {} from the push relay: {e}", device.uuid);
    }

    device.delete(&conn).await
}

#[post("/devices/<device_id>/deactivate")]
async fn post_deactivate_device(device_id: DeviceId, headers: Headers, conn: DbConn) -> EmptyResult {
    delete_device(device_id, headers, conn).await
}

#[get("/tasks")]
fn get_tasks(_client_headers: ClientHeaders) -> JsonResult {
    Ok(Json(json!({
        "data": [],
        "object": "list"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthRequestRequest {
    access_code: String,
    device_identifier: DeviceId,
    email: String,
    public_key: String,
    #[serde(rename = "type")]
    atype: Option<i32>,
}

impl AuthRequestRequest {
    /// Upstream's `[Required]` fields, which a blank value doesn't meet either, and `[StringLength(25)]` on the access
    /// code. A blank email or device identifier finds no user or device.
    fn validate(&self) -> EmptyResult {
        if self.access_code.trim().is_empty()
            || self.access_code.encode_utf16().count() > 25
            || self.public_key.trim().is_empty()
        {
            err!("Invalid auth request")
        }
        if self.atype.is_none() {
            err!("The Type field is required.")
        }
        Ok(())
    }

    fn atype(&self) -> Option<AuthRequestType> {
        self.atype.and_then(AuthRequestType::from_i32)
    }
}

#[post("/auth-requests", data = "<data>")]
async fn post_auth_request(
    data: Json<AuthRequestRequest>,
    client_headers: ClientHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> JsonResult {
    crate::ratelimit::check_limit_unauthenticated(&client_headers.ip.ip)?;

    let data = data.into_inner();

    // Before looking up the user, so that the answer tells nothing about them
    data.validate()?;
    let atype = match data.atype() {
        Some(AuthRequestType::AdminApproval) => err!("You must be authenticated to create a request of that type."),
        Some(atype) => atype,
        None => err!("Unknown auth request type"),
    };

    let Some(user) = User::find_by_mail(&data.email, &conn).await else {
        err!("User or known device not found.", "User not found")
    };

    // Like upstream, only from a known device of the user, here also of the type it has
    let device = match Device::find_by_uuid_and_user(&data.device_identifier, &user.uuid, &conn).await {
        Some(device) if device.atype == client_headers.device_type => device,
        _ => err!("User or known device not found.", "Device verification failed"),
    };

    let auth_request = AuthRequest::new(
        user.uuid.clone(),
        atype,
        data.device_identifier.clone(),
        client_headers.device_type,
        client_headers.ip.ip.to_string(),
        data.access_code,
        data.public_key,
    );
    auth_request.save(&conn).await?;

    // Like upstream, only pushed to the other devices, an event is only logged for an admin approval
    nt.send_auth_request(&user.uuid, &auth_request.uuid, &device, &conn).await;

    Ok(Json(auth_request.to_json()))
}

/// Upstream makes one request per organization of the user and the clients follow the first one only. Its TDE
/// organization requires the single organization policy, so there is the one request, to the organization that holds
/// the user key through account recovery, as its own TODO intends. Here every membership counts as one of the SSO
/// organization and none has to be the only one, so the one request goes to an organization that can approve it: the
/// one the account enrolled in when it was created, which `find_main_user_org` names, or else the first enrolled. An
/// approval of a second request would only tell the user so, while the client keeps waiting for the first.
/// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Core/Auth/Services/Implementations/AuthRequestService.cs>
/// Ref: <https://github.com/bitwarden/server/blob/9c109b6b4addad5eb821e263e5cdc25657dc6563/src/Core/Auth/Services/Implementations/SsoConfigService.cs#L68-L90>
#[post("/auth-requests/admin-request", data = "<data>")]
async fn post_admin_auth_request(data: Json<AuthRequestRequest>, headers: Headers, conn: DbConn) -> JsonResult {
    // Every request mails the approvers, which upstream's limit on every POST of an IP keeps in check
    crate::ratelimit::check_limit_admin_auth_request(&headers.ip.ip)?;

    let data = data.into_inner();

    data.validate()?;
    if data.atype() != Some(AuthRequestType::AdminApproval) {
        err!("Invalid AuthRequestType. Expected AdminApproval.")
    }

    // The user of the email has to be the caller, and the device one of theirs
    if User::find_by_mail(&data.email, &conn).await.is_none_or(|user| user.uuid != headers.user.uuid)
        || Device::find_by_uuid_and_user(&data.device_identifier, &headers.user.uuid, &conn).await.is_none()
    {
        err!("User or known device not found.")
    }

    let memberships: Vec<Membership> = Membership::find_by_user(&headers.user.uuid, &conn)
        .await
        .into_iter()
        .filter(Membership::has_admin_approval)
        .collect();
    let main_org =
        Membership::find_main_user_org(&headers.user.uuid, &conn).await.map(|membership| membership.org_uuid);
    let Some(membership) = memberships
        .iter()
        .find(|membership| main_org.as_ref() == Some(&membership.org_uuid))
        .or_else(|| memberships.first())
    else {
        err!("User does not belong to any organizations.")
    };

    log_user_event_including_accepted_orgs(
        EventType::UserRequestedDeviceApproval,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        &conn,
    )
    .await;

    let auth_request = create_admin_auth_request(&data, &headers, &membership.org_uuid, &conn).await?;

    Ok(Json(auth_request.to_json()))
}

/// The admin approval request for the organization, whose approvers are mailed about it
async fn create_admin_auth_request(
    data: &AuthRequestRequest,
    headers: &Headers,
    org_id: &OrganizationId,
    conn: &DbConn,
) -> ApiResult<AuthRequest> {
    let mut auth_request = AuthRequest::new(
        headers.user.uuid.clone(),
        AuthRequestType::AdminApproval,
        data.device_identifier.clone(),
        headers.device.atype,
        headers.ip.ip.to_string(),
        data.access_code.clone(),
        data.public_key.clone(),
    );
    auth_request.organization_uuid = Some(org_id.clone());
    auth_request.save(conn).await?;

    notify_device_approval_requested(&headers.user, org_id, conn).await;
    Ok(auth_request)
}

/// Mails the confirmed members who may answer, like upstream's `NotifyAdminsOfDeviceApprovalRequestAsync`.
async fn notify_device_approval_requested(user: &User, org_id: &OrganizationId, conn: &DbConn) {
    if !CONFIG.mail_enabled() {
        return;
    }

    let approvers = Membership::find_by_org(org_id, conn)
        .await
        .into_iter()
        .filter(|member| member.has_status(MembershipStatus::Confirmed) && member.has_manage_reset_password_role());

    for approver in approvers {
        let Some(admin) = User::find_by_uuid(&approver.user_uuid, conn).await else {
            continue;
        };

        if let Err(e) = mail::send_device_approval_requested(&admin.email, org_id, &user.email, &user.name).await {
            error!("Error sending device approval request email: {e:#?}");
        }
    }
}

/// Like upstream, a request that is gone is not found, which has the clients make a new one, and one that ran out is
/// returned until it is purged.
/// Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Api/Auth/Controllers/AuthRequestsController.cs>
#[get("/auth-requests/<auth_request_id>")]
async fn get_auth_request(auth_request_id: AuthRequestId, headers: Headers, conn: DbConn) -> JsonResult {
    let Some(auth_request) = AuthRequest::find_by_uuid_and_user(&auth_request_id, &headers.user.uuid, &conn).await
    else {
        err_code!("Resource not found.", "Record not found or user uuid does not match", Status::NotFound.code)
    };

    Ok(Json(auth_request.to_json()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthResponseRequest {
    device_identifier: DeviceId,
    key: Option<String>,
    master_password_hash: Option<String>,
    request_approved: bool,
}

#[put("/auth-requests/<auth_request_id>", data = "<data>")]
async fn put_auth_request(
    auth_request_id: AuthRequestId,
    data: Json<AuthResponseRequest>,
    headers: Headers,
    conn: DbConn,
    ant: AnonymousNotify<'_>,
    nt: Notify<'_>,
) -> JsonResult {
    let data = data.into_inner();
    let Some(mut auth_request) = AuthRequest::find_by_uuid_and_user(&auth_request_id, &headers.user.uuid, &conn).await
    else {
        err_code!("Resource not found.", "Record not found or user uuid does not match", Status::NotFound.code)
    };

    // Like upstream, only the newest request of a device can be approved
    // Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Api/Auth/Controllers/AuthRequestsController.cs>
    if data.request_approved
        && AuthRequest::find_by_user_and_requested_device(
            &headers.user.uuid,
            &auth_request.request_device_identifier,
            &conn,
        )
        .await
        .is_none_or(|newest| newest.uuid != auth_request.uuid)
    {
        err!("This request is no longer valid. Make sure to approve the most recent request.")
    }

    // Ref: <https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/src/Core/Auth/Services/Implementations/AuthRequestService.cs>
    if auth_request.approved.is_some() {
        err!("An authentication request with the same device already exists.")
    }

    if auth_request.is_expired() {
        err_code!("Resource not found.", "Request has expired", Status::NotFound.code)
    }

    // Like upstream, any device of the user can answer a request between devices, an admin approval names none
    if !auth_request.is_admin_approval() {
        let Some(device) = Device::find_by_uuid_and_user(&data.device_identifier, &headers.user.uuid, &conn).await
        else {
            err!("Invalid device.")
        };
        auth_request.response_device_id = Some(device.uuid);
    }

    // Like upstream, a denial is kept as the answer, which is not pushed, but which the asking device sees when it checks
    auth_request.approved = Some(data.request_approved);
    auth_request.response_date = Some(Utc::now().naive_utc());
    if data.request_approved {
        auth_request.enc_key = data.key;
        auth_request.master_password_hash = data.master_password_hash;
    }
    if !auth_request.save_answer(&conn).await? {
        err!("An authentication request with the same device already exists.")
    }

    if data.request_approved {
        ant.send_auth_response(&auth_request.user_uuid, &auth_request.uuid).await;
        nt.send_auth_response(&auth_request.user_uuid, &auth_request.uuid, Some(&headers.device), &conn).await;
    }

    // Like upstream, only the answer to a request of an organization is an event, one of that organization
    if let Some(org_id) = &auth_request.organization_uuid
        && let Some(member) = Membership::find_by_user_and_org(&auth_request.user_uuid, org_id, &conn).await
    {
        let event_type = if data.request_approved {
            EventType::OrganizationUserApprovedAuthRequest
        } else {
            EventType::OrganizationUserRejectedAuthRequest
        };
        log_event(event_type, &member.uuid, org_id, &headers.user.uuid, headers.device.atype, &headers.ip.ip, &conn)
            .await;
    }

    Ok(Json(auth_request.to_json()))
}

#[get("/auth-requests/<auth_request_id>/response?<code>")]
async fn get_auth_request_response(
    auth_request_id: AuthRequestId,
    code: &str,
    client_headers: ClientHeaders,
    conn: DbConn,
) -> JsonResult {
    crate::ratelimit::check_limit_unauthenticated(&client_headers.ip.ip)?;

    // Like upstream's `GetValidatedAuthRequestAsync`, anything but a valid request is not found
    let Some(auth_request) = AuthRequest::find_by_uuid(&auth_request_id, &conn).await else {
        err_code!("Resource not found.", "Record not found", Status::NotFound.code)
    };

    // Unlike upstream, from the IP that asked, except for an admin approval: it waits for days and its device moves
    // between networks meanwhile, while the iOS app polls it here. Its answer is the user key for the public key of
    // the request, which only the device that asked can unwrap, and only an authenticated session can ask for one.
    if auth_request.device_type != client_headers.device_type
        || (!auth_request.is_admin_approval() && auth_request.request_ip != client_headers.ip.ip.to_string())
        || !auth_request.check_access_code(code)
    {
        err_code!("Resource not found.", "Invalid device, IP or code", Status::NotFound.code)
    }

    if auth_request.is_expired() {
        err_code!("Resource not found.", "Request has expired", Status::NotFound.code)
    }

    Ok(Json(auth_request.to_json()))
}

/// Like upstream, every request of the user
#[get("/auth-requests")]
async fn get_auth_requests(headers: Headers, conn: DbConn) -> JsonResult {
    let auth_requests = AuthRequest::find_by_user(&headers.user.uuid, &conn).await;

    Ok(Json(json!({
        "data": auth_requests.iter().map(AuthRequest::to_json).collect::<Vec<Value>>(),
        "continuationToken": null,
        "object": "list"
    })))
}

/// Like upstream's `PendingAuthRequestResponseModel`, the pending request of each device, with the device if it is known
#[get("/auth-requests/pending")]
async fn get_auth_requests_pending(headers: Headers, conn: DbConn) -> JsonResult {
    let mut auth_requests = Vec::new();
    for auth_request in AuthRequest::find_pending_by_user(&headers.user.uuid, &conn).await {
        let device =
            Device::find_by_uuid_and_user(&auth_request.request_device_identifier, &headers.user.uuid, &conn).await;
        let mut json = auth_request.to_json();
        json["requestDeviceId"] = json!(device.map(|device| device.uuid));
        auth_requests.push(json);
    }

    Ok(Json(json!({
        "data": auth_requests,
        "continuationToken": null,
        "object": "list"
    })))
}

pub async fn purge_auth_requests(pool: DbPool) {
    debug!("Purging auth requests");
    if let Ok(conn) = pool.get().await {
        AuthRequest::purge_expired_auth_requests(&conn).await;
    } else {
        error!("Failed to get DB connection while purging auth requests");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AES_KEY: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|Y2lwaGVy|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn device(id: &str, trusted: bool) -> Device {
        let mut device = Device::new(id.to_owned().into(), String::from("user").into(), String::new(), 9);
        if trusted {
            device.encrypted_user_key = Some(String::from("4.b2xk"));
            device.encrypted_public_key = Some(String::from(AES_KEY));
            device.encrypted_private_key = Some(String::from(AES_KEY));
        }
        device
    }

    fn update(device_id: &str) -> UpdateDeviceKeysData {
        UpdateDeviceKeysData {
            device_id: device_id.to_owned().into(),
            encrypted_user_key: String::from("4.bmV3"),
            encrypted_public_key: String::from(AES_KEY),
        }
    }

    fn rotated(result: &[(DeviceId, String, String)]) -> Vec<String> {
        result.iter().map(|(device_id, ..)| device_id.to_string()).collect()
    }

    #[test]
    fn only_trusted_devices_are_rotated() {
        let mut half_trusted = device("d", true);
        half_trusted.encrypted_user_key = None;
        let devices = [device("a", true), device("b", true), device("c", false), half_trusted];

        // Entries for untrusted, unknown or repeated devices are ignored, like upstream.
        let updates = [update("a"), update("b"), update("b"), update("c"), update("d"), update("stranger")];
        assert_eq!(rotated(&validate_device_keydata(&updates, &devices).unwrap()), ["a", "b"]);
        assert_eq!(rotated(&validate_device_keydata(&[update("a"), update("b")], &devices).unwrap()), ["a", "b"]);
        assert_eq!(rotated(&validate_device_keydata(&[], &devices[2..]).unwrap()), Vec::<String>::new());
    }

    #[test]
    fn a_rotation_must_cover_every_trusted_device_with_valid_keys() {
        let devices = [device("a", true), device("b", true)];
        let mut bad_user_key = update("a");
        bad_user_key.encrypted_user_key = String::from("not an enc string");
        let mut bad_public_key = update("c");
        bad_public_key.encrypted_public_key = String::new();

        for (updates, expected) in [
            (vec![update("a")], "All existing trusted devices must be included"),
            (vec![bad_user_key, update("b")], "EncryptedUserKey"),
            (vec![update("a"), update("b"), bad_public_key], "EncryptedPublicKey"),
        ] {
            let err = validate_device_keydata(&updates, &devices).unwrap_err();
            assert!(format!("{err}").contains(expected), "expected {expected:?}, got {err}");
        }
    }

    #[test]
    fn an_auth_request_needs_its_type() {
        let mut body = serde_json::json!({
            "accessCode": "code",
            "deviceIdentifier": "device",
            "email": "user@example.com",
            "publicKey": "key"
        });
        let request: AuthRequestRequest = serde_json::from_value(body.clone()).unwrap();
        assert!(request.validate().is_err());

        body["type"] = serde_json::json!(2);
        let request: AuthRequestRequest = serde_json::from_value(body.clone()).unwrap();
        assert!(request.validate().is_ok());
        assert_eq!(request.atype(), Some(AuthRequestType::AdminApproval));

        // Upstream's `[Required]` refuses a blank value, and `[StringLength(25)]` a longer access code
        for (field, value) in
            [("accessCode", String::from(" ")), ("accessCode", "a".repeat(26)), ("publicKey", String::from("\t "))]
        {
            let mut body = body.clone();
            body[field] = serde_json::json!(value);
            let request: AuthRequestRequest = serde_json::from_value(body).unwrap();
            assert!(request.validate().is_err(), "{field}: {value:?}");
        }
    }

    #[test]
    fn a_new_master_password_needs_the_current_kdf_ranges() {
        let kdf = |kdf, kdf_iterations, kdf_memory, kdf_parallelism| KDFData {
            kdf,
            kdf_iterations,
            kdf_memory,
            kdf_parallelism,
        };
        let (pbkdf2, argon2) = (UserKdfType::Pbkdf2 as i32, UserKdfType::Argon2id as i32);
        for (settings, valid) in [
            (kdf(pbkdf2, 600_000, None, None), true),
            (kdf(pbkdf2, 2_000_000, None, None), true),
            (kdf(pbkdf2, 599_999, None, None), false),
            (kdf(pbkdf2, 100_000, None, None), false),
            (kdf(pbkdf2, 2_000_001, None, None), false),
            (kdf(argon2, 2, Some(15), Some(1)), true),
            (kdf(argon2, 10, Some(1024), Some(16)), true),
            (kdf(argon2, 1, Some(64), Some(4)), false),
            (kdf(argon2, 11, Some(64), Some(4)), false),
            (kdf(argon2, 3, Some(14), Some(4)), false),
            (kdf(argon2, 3, Some(1025), Some(4)), false),
            (kdf(argon2, 3, None, Some(4)), false),
            (kdf(argon2, 3, Some(64), Some(0)), false),
            (kdf(argon2, 3, Some(64), Some(17)), false),
            (kdf(argon2, 3, Some(64), None), false),
            // Like upstream, a type it doesn't know isn't checked here
            (kdf(7, 1, None, None), true),
        ] {
            assert_eq!(settings.validate_new_settings().is_ok(), valid, "{settings:?}");
        }
    }

    #[cfg(sqlite)]
    fn account_keys(name: &str, v2: bool) -> ValidatedAccountKeys {
        ValidatedAccountKeys {
            private_key: format!("2.{name}-private"),
            public_key: format!("{name}-public"),
            v2: v2.then(|| ValidatedV2AccountKeys {
                signed_public_key: format!("{name}-signed-public"),
                signing_key: format!("{name}-signing"),
                verifying_key: format!("{name}-verifying"),
                signature_algorithm: SignatureAlgorithm::Ed25519,
                security_state: format!("{name}-security-state"),
                security_version: 2,
            }),
        }
    }

    /// Two key setups of one account read it before either wrote: only the first lands, and the second leaves neither
    /// its key pair on the user nor its signature key pair behind.
    #[cfg(sqlite)]
    #[test]
    fn only_one_of_two_concurrent_key_setups_lands() {
        crate::db::test_db::run(async |db| {
            let conn = db.conn();
            for v2 in [true, false] {
                let mut user = User::new(&format!("{}@example.com", crate::util::get_uuid()), None);
                user.save(&conn).await.unwrap();
                let mut first = User::find_by_uuid(&user.uuid, &conn).await.unwrap();
                let mut second = User::find_by_uuid(&user.uuid, &conn).await.unwrap();

                save_initial_account_keys(&account_keys("first", v2), &mut first, &conn).await.unwrap();
                let err = save_initial_account_keys(&account_keys("second", v2), &mut second, &conn).await.unwrap_err();
                assert_eq!(err.message(), "User has existing keypair");

                let saved = User::find_by_uuid(&user.uuid, &conn).await.unwrap();
                assert_eq!(saved.private_key.as_deref(), Some("2.first-private"));
                assert_eq!(saved.public_key.as_deref(), Some("first-public"));
                let pair = UserSignatureKeyPair::find_by_user(&user.uuid, &conn).await;
                if v2 {
                    assert_eq!(saved.signed_public_key.as_deref(), Some("first-signed-public"));
                    let pair = pair.unwrap();
                    assert_eq!(
                        (pair.signing_key.as_str(), pair.verifying_key.as_str()),
                        ("first-signing", "first-verifying")
                    );
                } else {
                    assert!(saved.signed_public_key.is_none() && pair.is_none());
                }
            }
        });
    }

    #[test]
    fn rotation_requires_device_key_unlock_data() {
        let mut unlock_data = serde_json::json!({
            "emergencyAccessUnlockData": [],
            "masterPasswordUnlockData": {
                "kdfType": 0,
                "kdfIterations": 600_000,
                "email": "user@example.com",
                "masterKeyAuthenticationHash": "hash",
                "masterKeyEncryptedUserKey": "key"
            },
            "organizationAccountRecoveryUnlockData": [],
            "passkeyUnlockData": [],
            "deviceKeyUnlockData": []
        });

        let data: RotateAccountUnlockData = serde_json::from_value(unlock_data.clone()).unwrap();
        assert!(data.common.device_key_unlock_data.is_empty());

        unlock_data.as_object_mut().unwrap().remove("deviceKeyUnlockData");
        assert!(serde_json::from_value::<RotateAccountUnlockData>(unlock_data).is_err());
    }

    #[test]
    fn test_register_data_current_format() {
        // Web and iOS since the master password authentication/unlock split
        let data: RegisterData = serde_json::from_str(
            r#"{
                "email": "user@example.com",
                "emailVerificationToken": "token",
                "userAsymmetricKeys": {"publicKey": "pub", "encryptedPrivateKey": "priv"},
                "masterPasswordAuthentication": {
                    "kdf": {"kdfType": 0, "iterations": 600000},
                    "salt": "user@example.com",
                    "masterPasswordAuthenticationHash": "hash"
                },
                "masterPasswordUnlock": {
                    "kdf": {"kdfType": 0, "iterations": 600000},
                    "salt": "user@example.com",
                    "masterKeyWrappedUserKey": "key"
                }
            }"#,
        )
        .unwrap();

        assert!(!data.compat.unprocessable(&data.email));
        assert_eq!(data.compat.hash(), "hash");
        assert_eq!(data.compat.key(), "key");
        assert_eq!(data.compat.kdf().kdf_iterations, 600_000);
        assert!(data.keys.is_some());
        assert_eq!(data.email_verification_token.as_deref(), Some("token"));
    }

    #[test]
    fn test_register_data_flat_format() {
        // Android before 2026.9.0
        let data: RegisterData = serde_json::from_str(
            r#"{
                "email": "user@example.com",
                "emailVerificationToken": "token",
                "masterPasswordHash": "hash",
                "masterPasswordHint": null,
                "userSymmetricKey": "key",
                "userAsymmetricKeys": {"publicKey": "pub", "encryptedPrivateKey": "priv"},
                "kdf": 0,
                "kdfIterations": 600000
            }"#,
        )
        .unwrap();

        assert!(!data.compat.unprocessable(&data.email));
        assert_eq!(data.compat.hash(), "hash");
        assert_eq!(data.compat.key(), "key");
        assert_eq!(data.compat.kdf().kdf_iterations, 600_000);
        assert!(data.keys.is_some());
    }
}
