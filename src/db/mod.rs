mod query_logger;

use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use diesel::{
    Connection, RunQueryDsl,
    connection::SimpleConnection,
    r2d2::{CustomizeConnection, Pool, PooledConnection},
};
use rocket::{
    Request,
    http::Status,
    request::{FromRequest, Outcome},
};
use tokio::{
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

use crate::{
    CONFIG,
    error::{Error, MapResult},
};

// These changes are based on Rocket 0.5-rc wrapper of Diesel: https://github.com/SergioBenitez/Rocket/blob/v0.5-rc/contrib/sync_db_pools
// A wrapper around spawn_blocking that propagates panics to the calling code.
pub async fn run_blocking<F, R>(job: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    match tokio::task::spawn_blocking(job).await {
        Ok(ret) => ret,
        Err(e) => match e.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            Err(_) => unreachable!("spawn_blocking tasks are never cancelled"),
        },
    }
}

// This is used to generate the main DbConn and DbPool enums, which contain one variant for each database supported
#[derive(diesel::MultiConnection)]
pub enum DbConnInner {
    #[cfg(mysql)]
    Mysql(diesel::mysql::MysqlConnection),
    #[cfg(postgresql)]
    Postgresql(diesel::pg::PgConnection),
    #[cfg(sqlite)]
    Sqlite(diesel::sqlite::SqliteConnection),
}

/// Custom connection manager that implements manual connection establishment
pub struct DbConnManager {
    database_url: String,
}

impl DbConnManager {
    pub fn new(database_url: &str) -> Self {
        Self {
            database_url: database_url.to_owned(),
        }
    }

    fn establish_connection(&self) -> Result<DbConnInner, diesel::r2d2::Error> {
        match DbConnType::from_url(&self.database_url) {
            #[cfg(mysql)]
            Ok(DbConnType::Mysql) => {
                let conn = diesel::mysql::MysqlConnection::establish(&self.database_url)?;
                Ok(DbConnInner::Mysql(conn))
            }
            #[cfg(postgresql)]
            Ok(DbConnType::Postgresql) => {
                let conn = diesel::pg::PgConnection::establish(&self.database_url)?;
                Ok(DbConnInner::Postgresql(conn))
            }
            #[cfg(sqlite)]
            Ok(DbConnType::Sqlite) => {
                let conn = diesel::sqlite::SqliteConnection::establish(&self.database_url)?;
                Ok(DbConnInner::Sqlite(conn))
            }

            Err(e) => Err(diesel::r2d2::Error::ConnectionError(diesel::ConnectionError::InvalidConnectionUrl(
                format!("Unable to estabilsh a connection: {e:?}"),
            ))),
        }
    }
}

impl diesel::r2d2::ManageConnection for DbConnManager {
    type Connection = DbConnInner;
    type Error = diesel::r2d2::Error;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        self.establish_connection()
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        use diesel::r2d2::R2D2Connection;
        conn.ping().map_err(diesel::r2d2::Error::QueryError)
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        use diesel::r2d2::R2D2Connection;
        conn.is_broken()
    }
}

#[derive(Eq, PartialEq)]
pub enum DbConnType {
    #[cfg(mysql)]
    Mysql,
    #[cfg(postgresql)]
    Postgresql,
    #[cfg(sqlite)]
    Sqlite,
}

pub static ACTIVE_DB_TYPE: OnceLock<DbConnType> = OnceLock::new();

pub struct DbConn {
    conn: Arc<Mutex<Option<PooledConnection<DbConnManager>>>>,
    permit: Option<OwnedSemaphorePermit>,
}

#[derive(Debug)]
pub struct DbConnOptions {
    pub init_stmts: String,
}

impl CustomizeConnection<DbConnInner, diesel::r2d2::Error> for DbConnOptions {
    fn on_acquire(&self, conn: &mut DbConnInner) -> Result<(), diesel::r2d2::Error> {
        if !self.init_stmts.is_empty() {
            conn.batch_execute(&self.init_stmts).map_err(diesel::r2d2::Error::QueryError)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct DbPool {
    // This is an 'Option' so that we can drop the pool in a 'spawn_blocking'.
    pool: Option<Pool<DbConnManager>>,
    semaphore: Arc<Semaphore>,
}

impl Drop for DbConn {
    fn drop(&mut self) {
        let conn = Arc::clone(&self.conn);
        let permit = self.permit.take();

        // Since connection can't be on the stack in an async fn during an
        // await, we have to spawn a new blocking-safe thread...
        tokio::task::spawn_blocking(move || {
            // And then re-enter the runtime to wait on the async mutex, but in a blocking fashion.
            let mut conn = tokio::runtime::Handle::current().block_on(conn.lock_owned());

            if let Some(conn) = conn.take() {
                drop(conn);
            }

            // Drop permit after the connection is dropped
            drop(permit);
        });
    }
}

impl Drop for DbPool {
    fn drop(&mut self) {
        let pool = self.pool.take();
        // Only use spawn_blocking if the Tokio runtime is still available
        // Otherwise the pool will be dropped on the current thread
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(move || drop(pool));
        }
    }
}

impl DbPool {
    // For the given database URL, guess its type, run migrations, create pool, and return it
    pub fn from_config() -> Result<Self, Error> {
        let db_url = CONFIG.database_url();
        let conn_type = DbConnType::from_url(&db_url)?;

        // Only set the default instrumentation if the log level is specifically set to either warn, info or debug
        if log_enabled!(target: "vaultwarden::db::query_logger", log::Level::Warn)
            || log_enabled!(target: "vaultwarden::db::query_logger", log::Level::Info)
            || log_enabled!(target: "vaultwarden::db::query_logger", log::Level::Debug)
        {
            drop(diesel::connection::set_default_instrumentation(query_logger::simple_logger));
        }

        match conn_type {
            #[cfg(mysql)]
            DbConnType::Mysql => {
                mysql_migrations::run_migrations(&db_url)?;
            }
            #[cfg(postgresql)]
            DbConnType::Postgresql => {
                postgresql_migrations::run_migrations(&db_url)?;
            }
            #[cfg(sqlite)]
            DbConnType::Sqlite => {
                sqlite_migrations::run_migrations(&db_url)?;
            }
        }

        let max_conns = CONFIG.database_max_conns();
        let manager = DbConnManager::new(&db_url);
        let pool = Pool::builder()
            .max_size(max_conns)
            .min_idle(Some(CONFIG.database_min_conns()))
            .idle_timeout(Some(Duration::from_secs(CONFIG.database_idle_timeout())))
            .connection_timeout(Duration::from_secs(CONFIG.database_timeout()))
            .connection_customizer(Box::new(DbConnOptions {
                init_stmts: conn_type.get_init_stmts(),
            }))
            .build(manager)
            .map_res("Failed to create pool")?;

        // Set a global to determine the database more easily throughout the rest of the code
        if ACTIVE_DB_TYPE.set(conn_type).is_err() {
            error!("Tried to set the active database connection type more than once.");
        }

        Ok(DbPool {
            pool: Some(pool),
            semaphore: Arc::new(Semaphore::new(max_conns as usize)),
        })
    }

    // Get a connection from the pool
    pub async fn get(&self) -> Result<DbConn, Error> {
        let duration = Duration::from_secs(CONFIG.database_timeout());
        let permit = match timeout(duration, Arc::clone(&self.semaphore).acquire_owned()).await {
            Ok(p) => p.expect("Semaphore should be open"),
            Err(_) => {
                err!("Timeout waiting for database connection");
            }
        };

        let p = self.pool.as_ref().expect("DbPool.pool should always be Some()");
        let pool = p.clone();
        let c =
            run_blocking(move || pool.get_timeout(duration)).await.map_res("Error retrieving connection from pool")?;
        Ok(DbConn {
            conn: Arc::new(Mutex::new(Some(c))),
            permit: Some(permit),
        })
    }
}

impl DbConnType {
    pub fn from_url(url: &str) -> Result<Self, Error> {
        // Mysql
        if url.len() > 6 && &url[..6] == "mysql:" {
            #[cfg(mysql)]
            return Ok(DbConnType::Mysql);

            #[cfg(not(mysql))]
            err!("`DATABASE_URL` is a MySQL URL, but the 'mysql' feature is not enabled")

        // Postgresql
        } else if url.len() > 11 && (&url[..11] == "postgresql:" || &url[..9] == "postgres:") {
            #[cfg(postgresql)]
            return Ok(DbConnType::Postgresql);

            #[cfg(not(postgresql))]
            err!("`DATABASE_URL` is a PostgreSQL URL, but the 'postgresql' feature is not enabled")

        // Sqlite (explicit)
        } else if url.len() > 7 && &url[..7] == "sqlite:" {
            #[cfg(sqlite)]
            return Ok(DbConnType::Sqlite);

            #[cfg(not(sqlite))]
            err!("`DATABASE_URL` is a SQLite URL, but the 'sqlite' feature is not enabled")
        }

        // No recognized scheme — assume legacy bare-path SQLite, but the database file must already exist.
        // This prevents misconfigured URLs (typos, quoted strings) from silently creating a new empty SQLite database.
        #[cfg(sqlite)]
        {
            if std::path::Path::new(url).exists() {
                return Ok(DbConnType::Sqlite);
            }
            err!(format!(
                "`DATABASE_URL` does not match any known database scheme (mysql://, postgresql://, sqlite://) \
                    and no existing SQLite database was found at '{url}'. \
                    If you intend to use SQLite, use an explicit `sqlite://` scheme in your `DATABASE_URL`. \
                    Otherwise, check your DATABASE_URL for typos or quoting issues."
            ))
        }

        #[cfg(not(sqlite))]
        err!("`DATABASE_URL` does not match any known database scheme (mysql://, postgresql://, sqlite://)")
    }

    pub fn get_init_stmts(&self) -> String {
        let init_stmts = CONFIG.database_conn_init();
        if init_stmts.is_empty() {
            self.default_init_stmts()
        } else {
            init_stmts
        }
    }

    pub fn default_init_stmts(&self) -> String {
        match self {
            #[cfg(mysql)]
            Self::Mysql => String::new(),
            #[cfg(postgresql)]
            Self::Postgresql => String::new(),
            #[cfg(sqlite)]
            Self::Sqlite => "PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;".to_owned(),
        }
    }
}

impl DbConn {
    pub async fn run<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut DbConnInner) -> R + Send,
        R: Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        let mut conn = conn.lock_owned().await;
        let conn = conn.as_mut().expect("Internal invariant broken: self.conn is Some");

        // Run blocking can't be used due to the 'static limitation, use block_in_place instead
        tokio::task::block_in_place(move || f(conn))
    }
}

#[macro_export]
macro_rules! db_run {
    ( $conn:ident: $body:block ) => {
        $conn.run(move |$conn| $body).await
    };

    ( $conn:ident: $( $($db:ident),+ $body:block )+ ) => {
        $conn.run(move |$conn| {
            match $conn {
                $($(
                #[cfg($db)]
                pastey::paste!(&mut $crate::db::DbConnInner::[<$db:camel>](ref mut $conn)) => {
                    $body
                },
            )+)+}
        }).await
    };
}

// Write all ToSql<Text, DB> and FromSql<Text, DB> given a serializable/deserializable type.
#[macro_export]
macro_rules! impl_FromToSqlText {
    ($name:ty) => {
        #[cfg(mysql)]
        impl ToSql<Text, diesel::mysql::Mysql> for $name {
            fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::mysql::Mysql>) -> diesel::serialize::Result {
                serde_json::to_writer(out, self).map(|_| diesel::serialize::IsNull::No).map_err(Into::into)
            }
        }

        #[cfg(postgresql)]
        impl ToSql<Text, diesel::pg::Pg> for $name {
            fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::pg::Pg>) -> diesel::serialize::Result {
                serde_json::to_writer(out, self).map(|_| diesel::serialize::IsNull::No).map_err(Into::into)
            }
        }

        #[cfg(sqlite)]
        impl ToSql<Text, diesel::sqlite::Sqlite> for $name {
            fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, diesel::sqlite::Sqlite>) -> diesel::serialize::Result {
                serde_json::to_string(self).map_err(Into::into).map(|str| {
                    out.set_value(str);
                    diesel::serialize::IsNull::No
                })
            }
        }

        impl<DB: diesel::backend::Backend> FromSql<Text, DB> for $name
        where
            String: FromSql<Text, DB>,
        {
            fn from_sql(bytes: DB::RawValue<'_>) -> diesel::deserialize::Result<Self> {
                <String as FromSql<Text, DB>>::from_sql(bytes)
                    .and_then(|str| serde_json::from_str(&str).map_err(Into::into))
            }
        }
    };
}

pub mod schema;

// Reexport the models, needs to be after the macros are defined so it can access them
pub mod models;

/// A real SQLite database behind a real [`DbConn`], so the organization ACL tests execute the actual
/// Diesel queries instead of a re-typed copy of them. A temporary file rather than `:memory:` because
/// every pooled connection would otherwise open a database of its own.
#[cfg(all(test, sqlite))]
pub(crate) mod test_db {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    /// The membership/collection/group tables the organization ACL queries touch, with the exact
    /// columns `src/db/schema.rs` declares.
    pub const ORG_ACL_SCHEMA: &str = "
        CREATE TABLE users (
            uuid TEXT NOT NULL PRIMARY KEY,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at DATETIME NOT NULL DEFAULT '2026-01-01 00:00:00',
            updated_at DATETIME NOT NULL,
            verified_at DATETIME,
            last_verifying_at DATETIME,
            login_verify_count INTEGER NOT NULL DEFAULT 0,
            email TEXT NOT NULL DEFAULT '',
            email_new TEXT,
            email_new_token TEXT,
            name TEXT NOT NULL DEFAULT '',
            password_hash BLOB NOT NULL DEFAULT X'',
            salt BLOB NOT NULL DEFAULT X'',
            password_iterations INTEGER NOT NULL DEFAULT 600000,
            password_hint TEXT,
            akey TEXT NOT NULL DEFAULT '',
            private_key TEXT,
            public_key TEXT,
            totp_secret TEXT,
            totp_recover TEXT,
            security_stamp TEXT NOT NULL DEFAULT '',
            stamp_exception TEXT,
            equivalent_domains TEXT NOT NULL DEFAULT '[]',
            excluded_globals TEXT NOT NULL DEFAULT '[]',
            client_kdf_type INTEGER NOT NULL DEFAULT 0,
            client_kdf_iter INTEGER NOT NULL DEFAULT 600000,
            client_kdf_memory INTEGER,
            client_kdf_parallelism INTEGER,
            api_key TEXT,
            avatar_color TEXT,
            external_id TEXT
        );
        CREATE TABLE twofactor (
            uuid TEXT NOT NULL PRIMARY KEY, user_uuid TEXT NOT NULL, atype INTEGER NOT NULL,
            enabled BOOLEAN NOT NULL, data TEXT NOT NULL, last_used BIGINT NOT NULL
        );
        CREATE TABLE collections (uuid TEXT NOT NULL PRIMARY KEY, org_uuid TEXT NOT NULL, name TEXT NOT NULL, external_id TEXT);
        CREATE TABLE ciphers (
            uuid TEXT NOT NULL PRIMARY KEY,
            created_at DATETIME NOT NULL DEFAULT '2026-01-01 00:00:00',
            updated_at DATETIME NOT NULL DEFAULT '2026-01-01 00:00:00',
            user_uuid TEXT, organization_uuid TEXT, key TEXT,
            atype INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL DEFAULT '', notes TEXT, fields TEXT,
            data TEXT NOT NULL DEFAULT '{}', password_history TEXT, deleted_at DATETIME, reprompt INTEGER
        );
        CREATE TABLE ciphers_collections (
            cipher_uuid TEXT NOT NULL, collection_uuid TEXT NOT NULL,
            PRIMARY KEY (cipher_uuid, collection_uuid)
        );
        CREATE TABLE groups_users (groups_uuid TEXT NOT NULL, users_organizations_uuid TEXT NOT NULL, PRIMARY KEY (groups_uuid, users_organizations_uuid));
        CREATE TABLE users_collections (
            user_uuid TEXT NOT NULL, collection_uuid TEXT NOT NULL,
            read_only BOOLEAN NOT NULL DEFAULT FALSE, hide_passwords BOOLEAN NOT NULL DEFAULT FALSE,
            manage BOOLEAN NOT NULL DEFAULT FALSE,
            PRIMARY KEY (user_uuid, collection_uuid)
        );
        CREATE TABLE collections_groups (
            collections_uuid TEXT NOT NULL, groups_uuid TEXT NOT NULL,
            read_only BOOLEAN NOT NULL DEFAULT FALSE, hide_passwords BOOLEAN NOT NULL DEFAULT FALSE,
            manage BOOLEAN NOT NULL DEFAULT FALSE,
            PRIMARY KEY (collections_uuid, groups_uuid)
        );
        CREATE TABLE groups (
            uuid TEXT NOT NULL PRIMARY KEY, organizations_uuid TEXT NOT NULL, name TEXT NOT NULL,
            access_all BOOLEAN NOT NULL DEFAULT FALSE, external_id TEXT,
            creation_date DATETIME NOT NULL, revision_date DATETIME NOT NULL
        );
        CREATE TABLE users_organizations (
            uuid TEXT NOT NULL PRIMARY KEY, user_uuid TEXT NOT NULL, org_uuid TEXT NOT NULL,
            invited_by_email TEXT, akey TEXT NOT NULL, status INTEGER NOT NULL, atype INTEGER NOT NULL,
            reset_password_key TEXT, external_id TEXT,
            manage_users BOOLEAN NOT NULL DEFAULT FALSE,
            manage_groups BOOLEAN NOT NULL DEFAULT FALSE,
            manage_policies BOOLEAN NOT NULL DEFAULT FALSE,
            create_new_collections BOOLEAN NOT NULL DEFAULT FALSE,
            edit_any_collection BOOLEAN NOT NULL DEFAULT FALSE,
            delete_any_collection BOOLEAN NOT NULL DEFAULT FALSE,
            access_event_logs BOOLEAN NOT NULL DEFAULT FALSE,
            access_import_export BOOLEAN NOT NULL DEFAULT FALSE,
            access_reports BOOLEAN NOT NULL DEFAULT FALSE
        );
    ";

    pub struct TestDb {
        path: PathBuf,
        // An `Option` so `Drop` can close every connection before deleting the file.
        pool: Option<Pool<DbConnManager>>,
    }

    impl TestDb {
        /// `schema` is the DDL and seed data the test needs.
        pub fn new(schema: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "vaultwarden-test-{}-{}.sqlite3",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            // An existing file makes `DbConnType::from_url` take the bare-path SQLite branch.
            drop(std::fs::remove_file(&path));
            std::fs::File::create(&path).expect("Error creating test database file");

            let pool = Pool::builder()
                .max_size(4)
                .build(DbConnManager::new(path.to_str().expect("Test database path is not UTF-8")))
                .expect("Error creating test database pool");
            pool.get().expect("Error opening test database").batch_execute(schema).expect("Error applying test schema");

            Self {
                path,
                pool: Some(pool),
            }
        }

        pub fn conn(&self) -> DbConn {
            let pool = self.pool.as_ref().expect("Test pool is closed");
            DbConn {
                conn: Arc::new(Mutex::new(Some(pool.get().expect("Error getting test connection")))),
                permit: None,
            }
        }
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            drop(self.pool.take());
            drop(std::fs::remove_file(&self.path));
        }
    }

    /// `DbConn::run` uses `block_in_place`, which needs a multi-threaded runtime.
    pub fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Error building test runtime")
            .block_on(future)
    }
}

/// Creates a back-up of the sqlite database
/// MySQL/MariaDB and PostgreSQL are not supported.
#[cfg(sqlite)]
pub fn backup_sqlite() -> Result<String, Error> {
    use diesel::Connection;

    let db_url = CONFIG.database_url();
    if DbConnType::from_url(&CONFIG.database_url()).is_ok_and(|t| t == DbConnType::Sqlite) {
        // Strip the sqlite:// prefix if present to get the raw file path
        let file_path = db_url.strip_prefix("sqlite://").unwrap_or(&db_url);
        // Open a read-only connection for the backup
        let mut conn = diesel::sqlite::SqliteConnection::establish(&format!("sqlite://{file_path}?mode=ro"))?;

        let db_path = std::path::Path::new(file_path).parent().unwrap();
        let backup_file = db_path
            .join(format!("db_{}.sqlite3", chrono::Utc::now().format("%Y%m%d_%H%M%S")))
            .to_string_lossy()
            .into_owned();

        diesel::sql_query("VACUUM INTO ?")
            .bind::<diesel::sql_types::Text, _>(&backup_file)
            .execute(&mut conn)
            .map(|_| ())
            .map_res("VACUUM INTO failed")?;

        Ok(backup_file)
    } else {
        err_silent!("The database type is not SQLite. Backups only works for SQLite databases")
    }
}

#[cfg(not(sqlite))]
pub fn backup_sqlite() -> Result<String, Error> {
    err_silent!("The database type is not SQLite. Backups only works for SQLite databases")
}

/// Get the SQL Server version
pub async fn get_sql_server_version(conn: &DbConn) -> String {
    db_run! { conn:
        postgresql,mysql {
            diesel::select(diesel::dsl::sql::<diesel::sql_types::Text>("version();"))
            .get_result::<String>(conn)
            .unwrap_or_else(|_| "Unknown".to_owned())
        }
        sqlite {
            diesel::select(diesel::dsl::sql::<diesel::sql_types::Text>("sqlite_version();"))
            .get_result::<String>(conn)
            .unwrap_or_else(|_| "Unknown".to_owned())
        }
    }
}

/// Attempts to retrieve a single connection from the managed database pool. If
/// no pool is currently managed, fails with an `InternalServerError` status. If
/// no connections are available, fails with a `ServiceUnavailable` status.
#[rocket::async_trait]
impl<'r> FromRequest<'r> for DbConn {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.rocket().state::<DbPool>() {
            Some(p) => match p.get().await {
                Ok(dbconn) => Outcome::Success(dbconn),
                _ => Outcome::Error((Status::ServiceUnavailable, ())),
            },
            None => Outcome::Error((Status::InternalServerError, ())),
        }
    }
}

/// The single migration this feature adds.
///
/// Some database states cannot be converted without a decision that belongs to an owner. The migration
/// file refuses them itself as a backstop, but Diesel surfaces only the driver-level duplicate-key error
/// that produces; the preflight evaluates the same predicates first and offers the way out.
const CUSTOM_ROLE_PERMISSIONS_MIGRATION: &str = "20260630120000";
// Upgrade compatibility covers official Vaultwarden database states. Intermediate, unreleased
// revisions of the Custom-role PR are development artifacts and must be reset or restored from a
// pre-PR backup instead of growing another migration-reconciliation state machine here.

/// The nine permission columns the migration adds.
const CUSTOM_ROLE_PERMISSION_COLUMNS: [&str; 9] = [
    "manage_users",
    "manage_groups",
    "manage_policies",
    "create_new_collections",
    "edit_any_collection",
    "delete_any_collection",
    "access_event_logs",
    "access_import_export",
    "access_reports",
];

/// Every column `users_organizations` has once the migration has run, and nothing else.
///
/// A fingerprint, not a schema definition: a table carrying exactly these eighteen names is the one
/// this migration produces. One column more or fewer and nothing may be inferred about it.
const EXPECTED_MEMBERSHIP_COLUMNS: [&str; 18] = [
    "uuid",
    "user_uuid",
    "org_uuid",
    "akey",
    "status",
    "atype",
    "reset_password_key",
    "external_id",
    "invited_by_email",
    "manage_users",
    "manage_groups",
    "manage_policies",
    "create_new_collections",
    "edit_any_collection",
    "delete_any_collection",
    "access_event_logs",
    "access_import_export",
    "access_reports",
];

/// The one-line reason the Custom-role preflight refused to start, once it has.
///
/// The refusal is deterministic -- it reads schema and ledger state no retry can change -- so
/// `create_db_pool` stops immediately instead of retrying it as a connection problem. It also gives the
/// startup path a plain sentence: `Error`'s `Display` renders the JSON body, its `Debug` escapes newlines.
static CUSTOM_ROLE_PREFLIGHT_REFUSAL: OnceLock<String> = OnceLock::new();

/// Why startup was stopped by the Custom-role preflight, if it was. `None` means the database was
/// simply not reachable (yet), which is worth retrying.
pub fn custom_role_preflight_refusal() -> Option<&'static str> {
    CUSTOM_ROLE_PREFLIGHT_REFUSAL.get().map(String::as_str)
}

/// What to do with a legacy `User + access_all` membership, from `LEGACY_USER_ACCESS_ALL_MIGRATION`.
///
/// The bit is a state official Vaultwarden wrote: until upstream commit `0d16da44` both the invite and
/// the edit endpoint stored a client-supplied `access_all` regardless of the role requested. It has no
/// representation in the new model -- dynamic read/write reach over every collection and nothing else --
/// so which meaning to keep is a decision about that member's access, not something the upgrade can
/// infer. Refusing stays the default; the other two let an owner decide once for the instance.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LegacyUserAccessAllPolicy {
    /// Stop and print the recovery procedure.
    #[default]
    Refuse,
    /// The reach is no longer wanted: clear the bit. Explicit assignments are kept.
    Drop,
    /// The reach has to survive: write it out as explicit assignments, then clear the bit.
    Materialize,
}

impl LegacyUserAccessAllPolicy {
    pub fn from_config(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "refuse" => Some(Self::Refuse),
            "drop" => Some(Self::Drop),
            "materialize" => Some(Self::Materialize),
            _ => None,
        }
    }

    /// An unparsable value cannot reach here -- `validate_config` rejects it at startup -- but
    /// falling back to the refusal keeps the failure mode closed rather than silently permissive.
    fn configured() -> Self {
        Self::from_config(&CONFIG.legacy_user_access_all_migration()).unwrap_or_default()
    }
}

/// Whether this backend commits a migration's schema statements one at a time, so an interrupted upgrade
/// can leave the migration half-applied.
///
/// MySQL and MariaDB do: every `ALTER TABLE` implicitly commits. SQLite and PostgreSQL run the whole
/// migration in one transaction, so a half-applied schema there was not produced by an interruption.
type InterruptibleSchemaChanges = bool;

/// The migration's Manager -> Custom conversion, replayed when an interrupted upgrade is resumed.
///
/// Character for character the `UPDATE` in
/// `migrations/mysql/2026-06-30-120000_add_custom_role_permissions/up.sql`. Idempotent for the same
/// reason it is safe there -- it matches only `atype = 3` -- which is what lets one recovery path cover
/// *both* interruption points. It reads `access_all`, so it must run before that column is dropped.
#[cfg(mysql)]
const CUSTOM_ROLE_MANAGER_CONVERSION_SQL: &str = "\
UPDATE users_organizations \
SET create_new_collections = access_all, \
    edit_any_collection = access_all, \
    delete_any_collection = access_all, \
    atype = 4 \
WHERE atype = 3";

/// The migration's final schema statement.
#[cfg(mysql)]
const DROP_ACCESS_ALL_SQL: &str = "ALTER TABLE users_organizations DROP COLUMN access_all";

/// What an interrupted upgrade still owes, in order -- exactly what the migration file does from its
/// `UPDATE` onwards. The caller records the ledger entry afterwards. Gated on MySQL, the only backend
/// a resume is reachable on.
#[cfg(mysql)]
const CUSTOM_ROLE_RESUME_STATEMENTS: [&str; 2] = [CUSTOM_ROLE_MANAGER_CONVERSION_SQL, DROP_ACCESS_ALL_SQL];

/// Relax the direct assignments of an affected membership before the bit goes away.
///
/// `access_all` *overrode* `read_only` and `hide_passwords`, so inserting only the missing rows would
/// quietly downgrade every collection the member was also explicitly assigned to. `manage` is
/// deliberately untouched -- `access_all` never conferred it, and an existing grant is its own decision.
const LEGACY_USER_ACCESS_ALL_RELAX_SQL: &str = "\
UPDATE users_collections \
SET read_only = FALSE, hide_passwords = FALSE \
WHERE EXISTS ( \
    SELECT 1 \
    FROM users_organizations uo \
    INNER JOIN collections c ON c.org_uuid = uo.org_uuid \
    WHERE uo.user_uuid = users_collections.user_uuid \
      AND c.uuid = users_collections.collection_uuid \
      AND uo.atype = 2 \
      AND uo.access_all = TRUE \
      AND uo.status = 2 \
)";

/// Write the reach out as explicit assignments.
///
/// Confirmed memberships only: a `users_collections` row is not bound to the membership status the way
/// `access_all` was, so materialising an invited, accepted or revoked membership would hand it durable
/// assignments it does not have today. Those only lose the bit.
const LEGACY_USER_ACCESS_ALL_MATERIALIZE_SQL: &str = "\
INSERT INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords) \
SELECT uo.user_uuid, c.uuid, FALSE, FALSE \
FROM users_organizations uo \
INNER JOIN collections c ON c.org_uuid = uo.org_uuid \
WHERE uo.atype = 2 \
  AND uo.access_all = TRUE \
  AND uo.status = 2 \
  AND NOT EXISTS ( \
      SELECT 1 FROM users_collections uc \
      WHERE uc.user_uuid = uo.user_uuid \
        AND uc.collection_uuid = c.uuid \
  )";

/// Clear the bit on every affected membership, whatever its status. Always the last statement: the
/// two above select on it.
const LEGACY_USER_ACCESS_ALL_CLEAR_SQL: &str =
    "UPDATE users_organizations SET access_all = FALSE WHERE atype = 2 AND access_all = TRUE";

const LEGACY_USER_ACCESS_ALL_RECOVERY: &str = concat!(
    "\n\nThe same decision applies to every affected membership on this instance, so it can also be ",
    "taken once, without any SQL, by setting LEGACY_USER_ACCESS_ALL_MIGRATION before the next start:\n",
    "  drop         clear the bit. Each member keeps the collections they are explicitly assigned\n",
    "               to and loses the organization-wide reach.\n",
    "  materialize  write the reach out as explicit assignments first, then clear the bit. Confirmed\n",
    "               memberships only; the others are treated as 'drop'.\n",
    "Both are applied before the migration touches anything, and the setting is inert afterwards.\n\n",
    "To decide per membership instead, list them:\n",
    "SELECT uuid, user_uuid, org_uuid, status\n",
    "FROM users_organizations\n",
    "WHERE atype = 2\n",
    "  AND access_all = TRUE;\n\n",
    "The bit gave these members read/write reach over every collection of the organization, including ",
    "collections created later, but no collection-management authority -- and it stopped applying as ",
    "soon as the membership was revoked. The new role model has no equivalent, so an owner has to pick ",
    "one of the two meanings per membership, with every Vaultwarden instance stopped and a backup ",
    "taken.\n\n",
    "The reach is no longer wanted -- this is also the right choice for an invited, accepted or revoked ",
    "membership: clear the bit. The member keeps every collection they are explicitly assigned to.\n",
    "UPDATE users_organizations\n",
    "SET access_all = FALSE\n",
    "WHERE uuid = '<MEMBERSHIP_UUID>';\n\n",
    "The reach has to survive: write it out as explicit assignments first, then clear the bit. Do this ",
    "only for a confirmed membership, and only if a snapshot is acceptable -- collections created after ",
    "this point are not added, and unlike access_all these rows are not tied to the membership status.\n",
    "access_all overrode read_only and hide_passwords, so the collections the member is *already* ",
    "assigned to have to be relaxed as well -- otherwise they come out of the upgrade with less access ",
    "than they have now. Run both statements, in this order:\n",
    "UPDATE users_collections\n",
    "SET read_only = FALSE, hide_passwords = FALSE\n",
    "WHERE user_uuid = (SELECT user_uuid FROM users_organizations WHERE uuid = '<MEMBERSHIP_UUID>')\n",
    "  AND collection_uuid IN (\n",
    "    SELECT c.uuid FROM collections c\n",
    "    INNER JOIN users_organizations uo ON uo.org_uuid = c.org_uuid\n",
    "    WHERE uo.uuid = '<MEMBERSHIP_UUID>'\n",
    "  );\n",
    "INSERT INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords)\n",
    "SELECT uo.user_uuid, c.uuid, FALSE, FALSE\n",
    "FROM users_organizations uo\n",
    "INNER JOIN collections c ON c.org_uuid = uo.org_uuid\n",
    "WHERE uo.uuid = '<MEMBERSHIP_UUID>'\n",
    "  AND NOT EXISTS (\n",
    "    SELECT 1 FROM users_collections uc\n",
    "    WHERE uc.user_uuid = uo.user_uuid AND uc.collection_uuid = c.uuid\n",
    "  );\n\n",
    "If the member genuinely needs organization-wide reach afterwards, give them the Custom role with ",
    "the 'Edit any collection' permission from the web vault once the upgrade has completed. That is ",
    "the supported, visible and revocable equivalent."
);

const AMBIGUOUS_PARTIAL_MIGRATION_RECOVERY: &str = concat!(
    "\n\nSome of the columns this migration adds already exist, so a previous attempt changed the ",
    "table -- but the result is not the schema an interrupted run leaves behind, so how far it got ",
    "cannot be established and finishing it would run the conversion against a table this build does ",
    "not recognise.\n\n",
    "An interruption is resumed automatically, and only on MySQL and MariaDB, where each ALTER TABLE ",
    "commits on its own. It requires all of:\n",
    "  * all nine Custom-role permission columns present and NOT NULL\n",
    "  * users_organizations carrying exactly the eighteen expected columns plus access_all\n",
    "  * a migration ledger that exists and records nothing newer than this migration\n",
    "  * no plain User membership still carrying access_all\n\n",
    "On SQLite and PostgreSQL the whole migration runs inside one transaction, so it cannot stop ",
    "half-way: this schema was produced by something else and is never resumed.\n\n",
    "Restore the backup taken before the schema was changed and start the upgrade again."
);

const MISSING_ACCESS_ALL_RECOVERY: &str = concat!(
    "\n\nThe upgrade derives every Custom collection permission from that column, so it cannot run ",
    "without it, and neither of the two questions above it can be answered.\n\n",
    "One way to reach this state *is* recoverable and is repaired automatically: on MySQL and ",
    "MariaDB every ALTER TABLE commits on its own, so a process that dies after the migration's ",
    "final DROP COLUMN and before Diesel records the migration leaves a database that is already ",
    "fully converted and only missing its ledger row. That is not this database -- the checks below ",
    "did not all pass, so the schema is not the one the completed migration produces and nothing may ",
    "be assumed about how far it got:\n",
    "  * all nine Custom-role permission columns present and NOT NULL\n",
    "  * users_organizations carrying exactly the eighteen expected columns\n",
    "  * no membership left on the legacy Manager role (atype = 3)\n",
    "  * a migration ledger that exists and records nothing newer than this migration\n\n",
    "Restore the backup taken before the schema was changed and start again from there."
);

/// What the preflight reads. All of it comes from the schema and the migration ledger.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
// Each field is an independent observation about the database, not a mode: they are combined by
// `custom_role_preflight_decision` and `custom_role_migration_is_complete`, which is exactly what
// the lint would have them replaced by.
#[allow(clippy::struct_excessive_bools)]
struct CustomRoleMigrationFacts {
    memberships_table_exists: bool,
    /// {`CUSTOM_ROLE_PERMISSIONS_MIGRATION`} is recorded, i.e. this database is already upgraded.
    migration_applied: bool,
    access_all_column_exists: bool,
    legacy_user_access_all_count: i64,
    /// The migration ledger table exists, so a missing entry means "not recorded" rather than
    /// "nowhere to look".
    migration_ledger_exists: bool,
    /// How many of [`CUSTOM_ROLE_PERMISSION_COLUMNS`] exist, and how many of those are NOT NULL.
    permission_columns_present: i64,
    permission_columns_not_null: i64,
    /// Total number of columns on `users_organizations`, and how many of them are names from
    /// [`EXPECTED_MEMBERSHIP_COLUMNS`]. Both have to equal the expected count: the first rules out a
    /// column this build knows nothing about, the second rules out a missing one.
    membership_column_count: i64,
    expected_membership_columns_present: i64,
    /// Memberships still carrying the legacy persisted Manager role.
    legacy_manager_rows: i64,
    /// A migration newer than the Custom-role one is recorded. Diesel applies migrations in order,
    /// so this can only mean the ledger was edited or the binary is older than the database.
    newer_migration_recorded: bool,
}

/// The stable part of the migration's final schema fingerprint. Additional columns may be added by
/// later migrations, but the removed legacy column must stay gone and all permission columns must be
/// present and non-nullable.
fn custom_role_schema_matches_applied_migration(facts: CustomRoleMigrationFacts) -> bool {
    let counted = |count: i64, expected: usize| usize::try_from(count).is_ok_and(|found| found == expected);

    facts.memberships_table_exists
        && !facts.access_all_column_exists
        && counted(facts.permission_columns_present, CUSTOM_ROLE_PERMISSION_COLUMNS.len())
        && counted(facts.permission_columns_not_null, CUSTOM_ROLE_PERMISSION_COLUMNS.len())
}

/// Whether the facts prove that the Custom-role migration ran to completion and only its ledger entry
/// is missing. This repair requires the exact table produced by this migration, no legacy Manager rows,
/// and a ledger into which the missing entry can safely be inserted.
fn custom_role_migration_is_complete(facts: CustomRoleMigrationFacts) -> bool {
    let counted = |count: i64, expected: usize| usize::try_from(count).is_ok_and(|found| found == expected);

    custom_role_schema_matches_applied_migration(facts)
        && !facts.migration_applied
        && facts.migration_ledger_exists
        && !facts.newer_migration_recorded
        && counted(facts.membership_column_count, EXPECTED_MEMBERSHIP_COLUMNS.len())
        && counted(facts.expected_membership_columns_present, EXPECTED_MEMBERSHIP_COLUMNS.len())
        && facts.legacy_manager_rows == 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CustomRolePreflightDecision {
    Proceed,
    /// The migration finished but its ledger entry never committed. Record it and continue.
    RecordCompletedMigration,
    /// The migration got as far as adding its columns -- and possibly as far as converting the
    /// legacy Managers -- but not to the end. Finish it, then record it.
    ResumeInterruptedMigration,
    /// Clear the legacy `User + access_all` bit, then continue.
    DropLegacyUserAccessAll,
    /// Write the reach of a confirmed legacy `User + access_all` membership out as explicit
    /// assignments, clear the bit, then continue.
    MaterializeLegacyUserAccessAll,
    RefuseMissingAccessAll,
    RefuseLegacyUserAccessAll,
    /// The migration ledger says the migration ran, but the expected final schema is not present.
    RefuseMigrationHistorySchemaMismatch,
    /// Some of the migration's columns exist while it is still unrecorded, but the schema is not the
    /// one an interrupted run leaves behind. Nothing may be assumed about how far it got.
    RefuseAmbiguousPartialMigration,
}

/// Whether the facts prove the migration was interrupted after it added its columns, leaving a schema
/// that can be finished rather than restored from a backup.
///
/// An exact fingerprint of the one state an interrupted run produces, not "some of the columns are
/// there": any other shape means something other than this migration changed the table. Only
/// `legacy_manager_rows` is unconstrained -- it differs between the two interruption points and the
/// conversion is idempotent, so one resume covers both. `legacy_user_access_all_count` must be zero,
/// which the caller establishes first.
fn custom_role_migration_is_resumable(facts: CustomRoleMigrationFacts) -> bool {
    let counted = |count: i64, expected: usize| usize::try_from(count).is_ok_and(|found| found == expected);

    facts.memberships_table_exists
        && !facts.migration_applied
        && facts.access_all_column_exists
        && facts.legacy_user_access_all_count == 0
        && facts.migration_ledger_exists
        && !facts.newer_migration_recorded
        && counted(facts.permission_columns_present, CUSTOM_ROLE_PERMISSION_COLUMNS.len())
        && counted(facts.permission_columns_not_null, CUSTOM_ROLE_PERMISSION_COLUMNS.len())
        // Exactly the finished table, plus the legacy column the migration has not dropped yet.
        && counted(facts.membership_column_count, EXPECTED_MEMBERSHIP_COLUMNS.len() + 1)
        && counted(facts.expected_membership_columns_present, EXPECTED_MEMBERSHIP_COLUMNS.len())
}

/// The decision to act on once any legacy `User + access_all` rows have been resolved.
///
/// Resolving them changes one fact, so the answer is recomputed: a database that is *both*
/// half-applied and carries such a row must still be resumed, not handed to Diesel.
fn custom_role_decision_after_legacy_resolution(
    facts: CustomRoleMigrationFacts,
    legacy_user_access_all: LegacyUserAccessAllPolicy,
    interruptible_schema_changes: InterruptibleSchemaChanges,
) -> CustomRolePreflightDecision {
    let mut resolved = facts;
    resolved.legacy_user_access_all_count = 0;
    custom_role_preflight_decision(resolved, legacy_user_access_all, interruptible_schema_changes)
}

fn custom_role_preflight_decision(
    facts: CustomRoleMigrationFacts,
    legacy_user_access_all: LegacyUserAccessAllPolicy,
    interruptible_schema_changes: InterruptibleSchemaChanges,
) -> CustomRolePreflightDecision {
    // A recorded migration is trusted only when the table has the required final column fingerprint.
    // Diesel will never run it again, so a mismatch must stop here instead of failing later at runtime.
    if facts.migration_applied {
        return if custom_role_schema_matches_applied_migration(facts) {
            CustomRolePreflightDecision::Proceed
        } else {
            CustomRolePreflightDecision::RefuseMigrationHistorySchemaMismatch
        };
    }

    // A fresh installation: Diesel creates the schema from scratch and there is nothing to convert.
    if !facts.memberships_table_exists {
        return CustomRolePreflightDecision::Proceed;
    }

    // The migration is pending, so the legacy column has to be there -- both questions below read it.
    // Unless the migration already ran and only its ledger entry is missing: MySQL and MariaDB commit
    // every ALTER TABLE on their own, so a process killed between the final `DROP COLUMN access_all`
    // and Diesel's ledger insert leaves a fully converted database that looks pending. Record the entry
    // instead of sending the operator to a backup.
    if !facts.access_all_column_exists {
        if custom_role_migration_is_complete(facts) {
            return CustomRolePreflightDecision::RecordCompletedMigration;
        }
        return CustomRolePreflightDecision::RefuseMissingAccessAll;
    }

    // A plain User carrying membership `access_all` has no representation in the new model: unlimited
    // reach over every collection, present and future, with no management authority. Materialising it as
    // direct assignments turns a dynamic guarantee into a snapshot and -- since a `users_collections` row
    // is not bound to the membership status -- would hand a revoked or never-confirmed member durable
    // assignments. Refuse, unless the owner has already decided once (`LegacyUserAccessAllPolicy`).
    if facts.legacy_user_access_all_count != 0 {
        return match legacy_user_access_all {
            LegacyUserAccessAllPolicy::Refuse => CustomRolePreflightDecision::RefuseLegacyUserAccessAll,
            LegacyUserAccessAllPolicy::Drop => CustomRolePreflightDecision::DropLegacyUserAccessAll,
            LegacyUserAccessAllPolicy::Materialize => CustomRolePreflightDecision::MaterializeLegacyUserAccessAll,
        };
    }

    // Nothing left to resolve and the legacy column still there. If the migration's own columns are
    // *also* present, a previous run stopped part-way: on MySQL/MariaDB each `ALTER TABLE` commits on
    // its own. Handing the file back to Diesel would re-run the `ADD COLUMN` and abort with a bare
    // duplicate-column error, which is what this branch replaces.
    if facts.permission_columns_present != 0 {
        if interruptible_schema_changes && custom_role_migration_is_resumable(facts) {
            return CustomRolePreflightDecision::ResumeInterruptedMigration;
        }
        return CustomRolePreflightDecision::RefuseAmbiguousPartialMigration;
    }

    CustomRolePreflightDecision::Proceed
}

/// The full operator-facing text for a refusal: what was found, and what to do about it.
///
/// Kept separate from the `Error` so it can be logged with `Display` (the only formatting that
/// preserves the newlines the SQL below depends on) and asserted on in tests.
fn custom_role_preflight_report(decision: CustomRolePreflightDecision, facts: CustomRoleMigrationFacts) -> String {
    let detail = match decision {
        CustomRolePreflightDecision::RefuseMissingAccessAll => format!(
            "The membership access_all column is missing while migration \
             {CUSTOM_ROLE_PERMISSIONS_MIGRATION} is still pending."
        ),
        CustomRolePreflightDecision::RefuseLegacyUserAccessAll => format!(
            "Found {} membership(s) of the plain User type carrying the legacy access_all bit. That \
             combination has no representation in the Custom role model: it grants dynamic reach over \
             every collection without any management authority.",
            facts.legacy_user_access_all_count
        ),
        CustomRolePreflightDecision::RefuseMigrationHistorySchemaMismatch => format!(
            "Migration {CUSTOM_ROLE_PERMISSIONS_MIGRATION} is recorded as applied, but the database \
             does not have the expected final users_organizations schema: access_all present={}, \
             permission columns={}/{} ({} NOT NULL), table columns={}, expected columns present={}.",
            facts.access_all_column_exists,
            facts.permission_columns_present,
            CUSTOM_ROLE_PERMISSION_COLUMNS.len(),
            facts.permission_columns_not_null,
            facts.membership_column_count,
            facts.expected_membership_columns_present
        ),
        CustomRolePreflightDecision::RefuseAmbiguousPartialMigration => format!(
            "Migration {CUSTOM_ROLE_PERMISSIONS_MIGRATION} is still pending, but {} of its {} \
             permission columns already exist on users_organizations ({} of them NOT NULL) and the \
             table currently has {} columns.",
            facts.permission_columns_present,
            CUSTOM_ROLE_PERMISSION_COLUMNS.len(),
            facts.permission_columns_not_null,
            facts.membership_column_count
        ),
        _ => unreachable!("only a refusal is an error"),
    };

    let recovery = match decision {
        CustomRolePreflightDecision::RefuseMissingAccessAll => MISSING_ACCESS_ALL_RECOVERY,
        CustomRolePreflightDecision::RefuseLegacyUserAccessAll => LEGACY_USER_ACCESS_ALL_RECOVERY,
        CustomRolePreflightDecision::RefuseAmbiguousPartialMigration => AMBIGUOUS_PARTIAL_MIGRATION_RECOVERY,
        CustomRolePreflightDecision::RefuseMigrationHistorySchemaMismatch => concat!(
            "\n\nMigration history and database schema disagree; restore a backup or repair the schema ",
            "before starting Vaultwarden. No automatic repair was attempted."
        ),
        _ => "",
    };

    format!("Custom-role migration preflight stopped startup. Nothing has been changed.\n\n{detail}{recovery}")
}

/// `'a', 'b', 'c'` — a literal list for an `IN (...)` predicate. The names are compile-time
/// constants from this file, never request data.
fn sql_name_list(names: &[&str]) -> String {
    names.iter().map(|name| format!("'{name}'")).collect::<Vec<_>>().join(", ")
}

/// Report a refusal and produce the error that stops startup.
///
/// Printed here through `Display`, and only here: the startup path logs a failed pool with `{e:?}`,
/// whose `Debug` escapes the newlines the recovery SQL depends on, and pool creation is retried. Log it
/// once readably, flag the refusal so the retry loop stops, and let a one-line error travel back.
fn custom_role_preflight_error(decision: CustomRolePreflightDecision, facts: CustomRoleMigrationFacts) -> Error {
    error!("{}", custom_role_preflight_report(decision, facts));

    let detail = match decision {
        CustomRolePreflightDecision::RefuseMissingAccessAll => {
            "the membership access_all column is missing while the Custom-role migration is still pending"
        }
        CustomRolePreflightDecision::RefuseLegacyUserAccessAll => {
            "a plain User membership still carries the legacy access_all bit"
        }
        CustomRolePreflightDecision::RefuseMigrationHistorySchemaMismatch => {
            "migration history and the database schema disagree"
        }
        CustomRolePreflightDecision::RefuseAmbiguousPartialMigration => {
            "the Custom-role migration is partially applied and the schema is not one it can finish"
        }
        _ => unreachable!("only a refusal is an error"),
    };

    let summary = format!(
        "The Custom-role migration preflight refused to start: {detail}. \
         Nothing has been changed; the recovery procedure is printed above."
    );
    // First refusal wins; a second would say the same thing about the same database.
    drop(CUSTOM_ROLE_PREFLIGHT_REFUSAL.set(summary.clone()));

    std::io::Error::other(summary).into()
}

/// The statements that resolve the legacy flag, in the order they have to run.
///
/// The last one is always the clear, so its row count is the number of memberships resolved.
fn legacy_user_access_all_statements(decision: CustomRolePreflightDecision) -> &'static [&'static str] {
    match decision {
        CustomRolePreflightDecision::MaterializeLegacyUserAccessAll => &[
            LEGACY_USER_ACCESS_ALL_RELAX_SQL,
            LEGACY_USER_ACCESS_ALL_MATERIALIZE_SQL,
            LEGACY_USER_ACCESS_ALL_CLEAR_SQL,
        ],
        CustomRolePreflightDecision::DropLegacyUserAccessAll => &[LEGACY_USER_ACCESS_ALL_CLEAR_SQL],
        _ => &[],
    }
}

fn log_resolved_legacy_user_access_all(decision: CustomRolePreflightDecision, memberships: usize) {
    let action = match decision {
        CustomRolePreflightDecision::MaterializeLegacyUserAccessAll => {
            "their organization-wide reach was written out as explicit collection assignments \
             (confirmed memberships only) and the flag was cleared"
        }
        CustomRolePreflightDecision::DropLegacyUserAccessAll => {
            "the flag was cleared; each member keeps the collections they are explicitly assigned to"
        }
        _ => unreachable!("no other decision resolves the legacy flag"),
    };
    warn!(
        "LEGACY_USER_ACCESS_ALL_MIGRATION resolved {memberships} plain User membership(s) carrying the \
         legacy access_all flag before migration {CUSTOM_ROLE_PERMISSIONS_MIGRATION}: {action}. This ran \
         once, on the configured policy; the setting has no effect on an upgraded database."
    );
}

fn log_recorded_completed_migration() {
    warn!(
        "Custom-role migration {CUSTOM_ROLE_PERMISSIONS_MIGRATION}: the schema is fully converted but the \
         migration was not recorded. This is what an interrupted migration leaves behind on MySQL and \
         MariaDB, where every ALTER TABLE commits on its own. Every completed-schema check passed, so the \
         missing ledger entry has been recorded and startup continues; no data was changed."
    );
}

#[cfg(mysql)]
fn log_resumed_interrupted_migration(converted: usize) {
    warn!(
        "Custom-role migration {CUSTOM_ROLE_PERMISSIONS_MIGRATION}: its permission columns were already \
         present while the migration was still unrecorded, which is what an interrupted upgrade leaves \
         behind on MySQL and MariaDB, where every ALTER TABLE commits on its own. The schema matched the \
         expected fingerprint exactly, so the migration was finished: {converted} legacy Manager \
         membership(s) converted, the access_all column dropped and the migration recorded. The \
         conversion is the migration's own statement and matches only atype = 3, so a run that had \
         already converted them changed nothing here."
    );
}

// Embed the migrations from the migrations folder into the application
// This way, the program automatically migrates the database to the latest version
// https://docs.rs/diesel_migrations/*/diesel_migrations/macro.embed_migrations.html
#[cfg(sqlite)]
mod sqlite_migrations {
    use diesel::{Connection, RunQueryDsl};
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
    pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/sqlite");

    /// Diesel runs each SQLite migration inside a transaction, so a failure rolls the whole file
    /// back and no half-applied schema can be left behind.
    const INTERRUPTIBLE_SCHEMA_CHANGES: super::InterruptibleSchemaChanges = false;

    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        count: i64,
    }

    fn count(
        connection: &mut diesel::sqlite::SqliteConnection,
        query: impl Into<String>,
    ) -> Result<i64, diesel::result::Error> {
        diesel::sql_query(query).get_result::<Count>(connection).map(|row| row.count)
    }

    fn table_exists(
        connection: &mut diesel::sqlite::SqliteConnection,
        table: &str,
    ) -> Result<bool, diesel::result::Error> {
        count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM sqlite_master \
                 WHERE type = 'table' AND name = '{table}'"
            ),
        )
        .map(|value| value != 0)
    }

    /// Read-only, with exactly one exception: the idempotent ledger insert that records a migration
    /// which provably already ran (see `custom_role_migration_is_complete`).
    ///
    /// `pragma_table_xinfo` rather than `table_info`: the latter omits generated columns, so one would
    /// pass the exact-column-count fingerprint unseen.
    fn preflight(connection: &mut diesel::sqlite::SqliteConnection) -> Result<(), super::Error> {
        let memberships_table_exists = table_exists(connection, "users_organizations")?;
        let migration_ledger_exists = table_exists(connection, "__diesel_schema_migrations")?;
        let migration_applied = migration_ledger_exists
            && count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                     WHERE version = '{}'",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ),
            )? != 0;
        if !memberships_table_exists {
            let facts = super::CustomRoleMigrationFacts {
                memberships_table_exists,
                migration_applied,
                migration_ledger_exists,
                ..Default::default()
            };
            return match super::custom_role_preflight_decision(
                facts,
                super::LegacyUserAccessAllPolicy::configured(),
                INTERRUPTIBLE_SCHEMA_CHANGES,
            ) {
                super::CustomRolePreflightDecision::Proceed => Ok(()),
                decision => Err(super::custom_role_preflight_error(decision, facts)),
            };
        }

        let newer_migration_recorded = migration_ledger_exists
            && count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                     WHERE version > '{}'",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ),
            )? != 0;
        let access_all_column_exists = count(
            connection,
            "SELECT COUNT(*) AS count FROM pragma_table_xinfo('users_organizations') \
             WHERE name = 'access_all'",
        )? != 0;

        let permission_columns_present = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM pragma_table_xinfo('users_organizations') \
                 WHERE name IN ({})",
                super::sql_name_list(&super::CUSTOM_ROLE_PERMISSION_COLUMNS)
            ),
        )?;
        let permission_columns_not_null = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM pragma_table_xinfo('users_organizations') \
                 WHERE name IN ({}) AND \"notnull\" = 1",
                super::sql_name_list(&super::CUSTOM_ROLE_PERMISSION_COLUMNS)
            ),
        )?;
        let membership_column_count =
            count(connection, "SELECT COUNT(*) AS count FROM pragma_table_xinfo('users_organizations')")?;
        let expected_membership_columns_present = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM pragma_table_xinfo('users_organizations') \
                 WHERE name IN ({})",
                super::sql_name_list(&super::EXPECTED_MEMBERSHIP_COLUMNS)
            ),
        )?;
        let legacy_manager_rows =
            count(connection, "SELECT COUNT(*) AS count FROM users_organizations WHERE atype = 3")?;

        // Status is deliberately not part of this count: an invited, accepted or revoked membership
        // carrying the bit is exactly the state that must never become durable direct assignments, so
        // it has to stop the upgrade as well.
        let legacy_user_access_all_count = if access_all_column_exists {
            count(
                connection,
                "SELECT COUNT(*) AS count FROM users_organizations \
                 WHERE atype = 2 \
                   AND access_all = TRUE",
            )?
        } else {
            0
        };
        let facts = super::CustomRoleMigrationFacts {
            memberships_table_exists,
            migration_applied,
            access_all_column_exists,
            legacy_user_access_all_count,
            migration_ledger_exists,
            permission_columns_present,
            permission_columns_not_null,
            membership_column_count,
            expected_membership_columns_present,
            legacy_manager_rows,
            newer_migration_recorded,
        };

        let policy = super::LegacyUserAccessAllPolicy::configured();
        let decision = super::custom_role_preflight_decision(facts, policy, INTERRUPTIBLE_SCHEMA_CHANGES);
        match decision {
            super::CustomRolePreflightDecision::Proceed => Ok(()),
            super::CustomRolePreflightDecision::RecordCompletedMigration => {
                diesel::sql_query(format!(
                    "INSERT OR IGNORE INTO __diesel_schema_migrations (version, run_on) \
                     VALUES ('{}', CURRENT_TIMESTAMP)",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ))
                .execute(connection)?;
                super::log_recorded_completed_migration();
                Ok(())
            }
            super::CustomRolePreflightDecision::DropLegacyUserAccessAll
            | super::CustomRolePreflightDecision::MaterializeLegacyUserAccessAll => {
                // Resolving the flag mutates authorization data, so all refusal conditions are
                // evaluated before entering the resolution transaction.
                match super::custom_role_decision_after_legacy_resolution(facts, policy, INTERRUPTIBLE_SCHEMA_CHANGES) {
                    super::CustomRolePreflightDecision::Proceed => {}
                    followup => return Err(super::custom_role_preflight_error(followup, facts)),
                }
                let resolved = connection.transaction::<usize, diesel::result::Error, _>(|connection| {
                    let mut resolved = 0;
                    for statement in super::legacy_user_access_all_statements(decision) {
                        resolved = diesel::sql_query(*statement).execute(connection)?;
                    }
                    Ok(resolved)
                })?;
                super::log_resolved_legacy_user_access_all(decision, resolved);
                Ok(())
            }
            // SQLite runs the whole migration inside one transaction, so it cannot stop half-way and
            // `custom_role_preflight_decision` never resumes for it. Fail closed rather than rely on
            // that from a distance.
            super::CustomRolePreflightDecision::ResumeInterruptedMigration => Err(super::custom_role_preflight_error(
                super::CustomRolePreflightDecision::RefuseAmbiguousPartialMigration,
                facts,
            )),
            decision => Err(super::custom_role_preflight_error(decision, facts)),
        }
    }

    pub fn run_migrations(db_url: &str) -> Result<(), super::Error> {
        // Establish a connection to the sqlite database (this will create a new one, if it does
        // not exist, and exit if there is an error).
        let mut connection = diesel::sqlite::SqliteConnection::establish(db_url)?;

        preflight(&mut connection)?;

        // Run the migrations after successfully establishing a connection
        // Disable Foreign Key Checks during migration
        // Scoped to a connection.
        diesel::sql_query("PRAGMA foreign_keys = OFF")
            .execute(&mut connection)
            .expect("Failed to disable Foreign Key Checks during migrations");

        // Turn on WAL in SQLite
        if crate::CONFIG.enable_db_wal() {
            diesel::sql_query("PRAGMA journal_mode=wal").execute(&mut connection).expect("Failed to turn on WAL");
        }

        connection.run_pending_migrations(MIGRATIONS).expect("Error running migrations");
        Ok(())
    }
}

#[cfg(mysql)]
mod mysql_migrations {
    use diesel::{Connection, RunQueryDsl};
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
    pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/mysql");

    /// MySQL and MariaDB commit every `ALTER TABLE` on their own, so a process killed part-way
    /// through a migration leaves it half-applied. This is the only backend an interrupted upgrade
    /// can be resumed on.
    const INTERRUPTIBLE_SCHEMA_CHANGES: super::InterruptibleSchemaChanges = true;

    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        count: i64,
    }

    fn count(
        connection: &mut diesel::mysql::MysqlConnection,
        query: impl Into<String>,
    ) -> Result<i64, diesel::result::Error> {
        diesel::sql_query(query).get_result::<Count>(connection).map(|row| row.count)
    }

    fn table_exists(
        connection: &mut diesel::mysql::MysqlConnection,
        table: &str,
    ) -> Result<bool, diesel::result::Error> {
        count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM information_schema.tables \
                 WHERE table_schema = DATABASE() AND table_name = '{table}'"
            ),
        )
        .map(|value| value != 0)
    }

    /// Read-only apart from the idempotent ledger insert and the resume below. This is the backend that
    /// produces both states: MySQL and MariaDB commit every ALTER TABLE on their own, so a process killed
    /// part-way through leaves a database that looks pending but is not.
    fn preflight(connection: &mut diesel::mysql::MysqlConnection) -> Result<(), super::Error> {
        let memberships_table_exists = table_exists(connection, "users_organizations")?;
        let migration_ledger_exists = table_exists(connection, "__diesel_schema_migrations")?;
        let migration_applied = migration_ledger_exists
            && count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                     WHERE version = '{}'",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ),
            )? != 0;
        if !memberships_table_exists {
            let facts = super::CustomRoleMigrationFacts {
                memberships_table_exists,
                migration_applied,
                migration_ledger_exists,
                ..Default::default()
            };
            return match super::custom_role_preflight_decision(
                facts,
                super::LegacyUserAccessAllPolicy::configured(),
                INTERRUPTIBLE_SCHEMA_CHANGES,
            ) {
                super::CustomRolePreflightDecision::Proceed => Ok(()),
                decision => Err(super::custom_role_preflight_error(decision, facts)),
            };
        }

        let newer_migration_recorded = migration_ledger_exists
            && count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                     WHERE version > '{}'",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ),
            )? != 0;
        let access_all_column_exists = count(
            connection,
            "SELECT COUNT(*) AS count FROM information_schema.columns \
             WHERE table_schema = DATABASE() \
               AND table_name = 'users_organizations' \
               AND column_name = 'access_all'",
        )? != 0;

        let permission_columns_present = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM information_schema.columns \
                 WHERE table_schema = DATABASE() \
                   AND table_name = 'users_organizations' \
                   AND column_name IN ({})",
                super::sql_name_list(&super::CUSTOM_ROLE_PERMISSION_COLUMNS)
            ),
        )?;
        let permission_columns_not_null = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM information_schema.columns \
                 WHERE table_schema = DATABASE() \
                   AND table_name = 'users_organizations' \
                   AND column_name IN ({}) \
                   AND is_nullable = 'NO'",
                super::sql_name_list(&super::CUSTOM_ROLE_PERMISSION_COLUMNS)
            ),
        )?;
        let membership_column_count = count(
            connection,
            "SELECT COUNT(*) AS count FROM information_schema.columns \
             WHERE table_schema = DATABASE() AND table_name = 'users_organizations'",
        )?;
        let expected_membership_columns_present = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM information_schema.columns \
                 WHERE table_schema = DATABASE() \
                   AND table_name = 'users_organizations' \
                   AND column_name IN ({})",
                super::sql_name_list(&super::EXPECTED_MEMBERSHIP_COLUMNS)
            ),
        )?;
        let legacy_manager_rows =
            count(connection, "SELECT COUNT(*) AS count FROM users_organizations WHERE atype = 3")?;

        // Status is deliberately not part of this count: an invited, accepted or revoked membership
        // carrying the bit is exactly the state that must never become durable direct assignments, so
        // it has to stop the upgrade as well.
        let legacy_user_access_all_count = if access_all_column_exists {
            count(
                connection,
                "SELECT COUNT(*) AS count FROM users_organizations \
                 WHERE atype = 2 \
                   AND access_all = TRUE",
            )?
        } else {
            0
        };
        let facts = super::CustomRoleMigrationFacts {
            memberships_table_exists,
            migration_applied,
            access_all_column_exists,
            legacy_user_access_all_count,
            migration_ledger_exists,
            permission_columns_present,
            permission_columns_not_null,
            membership_column_count,
            expected_membership_columns_present,
            legacy_manager_rows,
            newer_migration_recorded,
        };

        let policy = super::LegacyUserAccessAllPolicy::configured();
        let decision = super::custom_role_preflight_decision(facts, policy, INTERRUPTIBLE_SCHEMA_CHANGES);
        match decision {
            super::CustomRolePreflightDecision::Proceed => Ok(()),
            super::CustomRolePreflightDecision::RecordCompletedMigration => {
                record_migration(connection)?;
                super::log_recorded_completed_migration();
                Ok(())
            }
            super::CustomRolePreflightDecision::ResumeInterruptedMigration => resume_migration(connection),
            super::CustomRolePreflightDecision::DropLegacyUserAccessAll
            | super::CustomRolePreflightDecision::MaterializeLegacyUserAccessAll => {
                // Resolving the flag mutates authorization data, so all refusal conditions are
                // evaluated before entering the resolution transaction. A valid MySQL/MariaDB
                // interruption is resumed afterwards.
                let followup =
                    super::custom_role_decision_after_legacy_resolution(facts, policy, INTERRUPTIBLE_SCHEMA_CHANGES);
                if !matches!(
                    followup,
                    super::CustomRolePreflightDecision::Proceed
                        | super::CustomRolePreflightDecision::ResumeInterruptedMigration
                ) {
                    return Err(super::custom_role_preflight_error(followup, facts));
                }
                let resolved = connection.transaction::<usize, diesel::result::Error, _>(|connection| {
                    let mut resolved = 0;
                    for statement in super::legacy_user_access_all_statements(decision) {
                        resolved = diesel::sql_query(*statement).execute(connection)?;
                    }
                    Ok(resolved)
                })?;
                super::log_resolved_legacy_user_access_all(decision, resolved);
                match followup {
                    super::CustomRolePreflightDecision::ResumeInterruptedMigration => resume_migration(connection),
                    _ => Ok(()),
                }
            }
            decision => Err(super::custom_role_preflight_error(decision, facts)),
        }
    }

    /// Idempotent ledger insert, so a repeated or racing startup is a no-op rather than a
    /// duplicate-key failure.
    fn record_migration(connection: &mut diesel::mysql::MysqlConnection) -> Result<(), diesel::result::Error> {
        diesel::sql_query(format!(
            "INSERT IGNORE INTO __diesel_schema_migrations (version, run_on) \
             VALUES ('{}', CURRENT_TIMESTAMP)",
            super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
        ))
        .execute(connection)
        .map(|_| ())
    }

    /// Finish a migration that stopped between its first `ALTER TABLE` and its last.
    ///
    /// Only reached once `custom_role_migration_is_resumable` has confirmed the schema, so these are the
    /// statements that run has not executed -- or, for the conversion, one that matches nothing the
    /// second time. Diesel then finds the migration recorded and never opens the file.
    fn resume_migration(connection: &mut diesel::mysql::MysqlConnection) -> Result<(), super::Error> {
        let mut converted = 0;
        for statement in super::CUSTOM_ROLE_RESUME_STATEMENTS {
            let affected = diesel::sql_query(statement).execute(connection)?;
            if statement == super::CUSTOM_ROLE_MANAGER_CONVERSION_SQL {
                converted = affected;
            }
        }
        record_migration(connection)?;
        super::log_resumed_interrupted_migration(converted);
        Ok(())
    }

    pub fn run_migrations(db_url: &str) -> Result<(), super::Error> {
        // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
        let mut connection = diesel::mysql::MysqlConnection::establish(db_url)?;

        preflight(&mut connection)?;

        // Disable Foreign Key Checks during migration
        // Scoped to a connection/session.
        diesel::sql_query("SET FOREIGN_KEY_CHECKS = 0")
            .execute(&mut connection)
            .expect("Failed to disable Foreign Key Checks during migrations");

        connection.run_pending_migrations(MIGRATIONS).expect("Error running migrations");
        Ok(())
    }
}

#[cfg(postgresql)]
mod postgresql_migrations {
    use diesel::{Connection, RunQueryDsl};
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
    pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/postgresql");

    /// Diesel runs each PostgreSQL migration inside a transaction, and PostgreSQL DDL is
    /// transactional, so a failure rolls the whole file back.
    const INTERRUPTIBLE_SCHEMA_CHANGES: super::InterruptibleSchemaChanges = false;

    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        count: i64,
    }

    fn count(
        connection: &mut diesel::pg::PgConnection,
        query: impl Into<String>,
    ) -> Result<i64, diesel::result::Error> {
        diesel::sql_query(query).get_result::<Count>(connection).map(|row| row.count)
    }

    /// Resolved through `to_regclass`, i.e. exactly the way an unqualified name in a migration is
    /// resolved -- and deliberately *not* through `table_schema = current_schema()`.
    ///
    /// `current_schema()` is where new objects are created, not necessarily where an existing table is
    /// found: with `search_path = decoy, real` and the tables in `real` it answers `decoy`, the lookup
    /// finds nothing, `preflight` returns early, and Diesel then runs the migration against `real` with
    /// both checks silently skipped. `to_regclass` walks the same path the migration does.
    fn table_exists(connection: &mut diesel::pg::PgConnection, table: &str) -> Result<bool, diesel::result::Error> {
        count(connection, format!("SELECT COUNT(*) AS count FROM pg_class WHERE oid = to_regclass('{table}')"))
            .map(|value| value != 0)
    }

    /// Read-only, with exactly one exception: the idempotent ledger insert that records a migration
    /// which provably already ran (see `custom_role_migration_is_complete`). PostgreSQL has
    /// transactional DDL, so it never produces that state itself -- the repair is here so a database
    /// restored or copied from a MySQL-side incident is handled identically on every backend.
    fn preflight(connection: &mut diesel::pg::PgConnection) -> Result<(), super::Error> {
        let memberships_table_exists = table_exists(connection, "users_organizations")?;
        let migration_ledger_exists = table_exists(connection, "__diesel_schema_migrations")?;
        let migration_applied = migration_ledger_exists
            && count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                     WHERE version = '{}'",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ),
            )? != 0;
        if !memberships_table_exists {
            let facts = super::CustomRoleMigrationFacts {
                memberships_table_exists,
                migration_applied,
                migration_ledger_exists,
                ..Default::default()
            };
            return match super::custom_role_preflight_decision(
                facts,
                super::LegacyUserAccessAllPolicy::configured(),
                INTERRUPTIBLE_SCHEMA_CHANGES,
            ) {
                super::CustomRolePreflightDecision::Proceed => Ok(()),
                decision => Err(super::custom_role_preflight_error(decision, facts)),
            };
        }

        let newer_migration_recorded = migration_ledger_exists
            && count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                     WHERE version > '{}'",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ),
            )? != 0;
        // Columns are resolved through the same `to_regclass` lookup as [`table_exists`], so a
        // `search_path` split cannot make the schema and the column check describe two different
        // tables.
        let access_all_column_exists = count(
            connection,
            "SELECT COUNT(*) AS count FROM pg_attribute \
             WHERE attrelid = to_regclass('users_organizations') \
               AND attnum > 0 \
               AND NOT attisdropped \
               AND attname = 'access_all'",
        )? != 0;

        let permission_columns_present = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM pg_attribute \
                 WHERE attrelid = to_regclass('users_organizations') \
                   AND attnum > 0 AND NOT attisdropped \
                   AND attname IN ({})",
                super::sql_name_list(&super::CUSTOM_ROLE_PERMISSION_COLUMNS)
            ),
        )?;
        let permission_columns_not_null = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM pg_attribute \
                 WHERE attrelid = to_regclass('users_organizations') \
                   AND attnum > 0 AND NOT attisdropped AND attnotnull \
                   AND attname IN ({})",
                super::sql_name_list(&super::CUSTOM_ROLE_PERMISSION_COLUMNS)
            ),
        )?;
        let membership_column_count = count(
            connection,
            "SELECT COUNT(*) AS count FROM pg_attribute \
             WHERE attrelid = to_regclass('users_organizations') \
               AND attnum > 0 AND NOT attisdropped",
        )?;
        let expected_membership_columns_present = count(
            connection,
            format!(
                "SELECT COUNT(*) AS count FROM pg_attribute \
                 WHERE attrelid = to_regclass('users_organizations') \
                   AND attnum > 0 AND NOT attisdropped \
                   AND attname IN ({})",
                super::sql_name_list(&super::EXPECTED_MEMBERSHIP_COLUMNS)
            ),
        )?;
        let legacy_manager_rows =
            count(connection, "SELECT COUNT(*) AS count FROM users_organizations WHERE atype = 3")?;

        // Status is deliberately not part of this count: an invited, accepted or revoked membership
        // carrying the bit is exactly the state that must never become durable direct assignments, so
        // it has to stop the upgrade as well.
        let legacy_user_access_all_count = if access_all_column_exists {
            count(
                connection,
                "SELECT COUNT(*) AS count FROM users_organizations \
                 WHERE atype = 2 \
                   AND access_all = TRUE",
            )?
        } else {
            0
        };
        let facts = super::CustomRoleMigrationFacts {
            memberships_table_exists,
            migration_applied,
            access_all_column_exists,
            legacy_user_access_all_count,
            migration_ledger_exists,
            permission_columns_present,
            permission_columns_not_null,
            membership_column_count,
            expected_membership_columns_present,
            legacy_manager_rows,
            newer_migration_recorded,
        };

        let policy = super::LegacyUserAccessAllPolicy::configured();
        let decision = super::custom_role_preflight_decision(facts, policy, INTERRUPTIBLE_SCHEMA_CHANGES);
        match decision {
            super::CustomRolePreflightDecision::Proceed => Ok(()),
            super::CustomRolePreflightDecision::RecordCompletedMigration => {
                diesel::sql_query(format!(
                    "INSERT INTO __diesel_schema_migrations (version, run_on) \
                     VALUES ('{}', CURRENT_TIMESTAMP) ON CONFLICT (version) DO NOTHING",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ))
                .execute(connection)?;
                super::log_recorded_completed_migration();
                Ok(())
            }
            super::CustomRolePreflightDecision::DropLegacyUserAccessAll
            | super::CustomRolePreflightDecision::MaterializeLegacyUserAccessAll => {
                // Resolving the flag mutates authorization data, so all refusal conditions are
                // evaluated before entering the resolution transaction.
                match super::custom_role_decision_after_legacy_resolution(facts, policy, INTERRUPTIBLE_SCHEMA_CHANGES) {
                    super::CustomRolePreflightDecision::Proceed => {}
                    followup => return Err(super::custom_role_preflight_error(followup, facts)),
                }
                let resolved = connection.transaction::<usize, diesel::result::Error, _>(|connection| {
                    let mut resolved = 0;
                    for statement in super::legacy_user_access_all_statements(decision) {
                        resolved = diesel::sql_query(*statement).execute(connection)?;
                    }
                    Ok(resolved)
                })?;
                super::log_resolved_legacy_user_access_all(decision, resolved);
                Ok(())
            }
            // PostgreSQL runs the whole migration inside one transaction, so it cannot stop half-way
            // and `custom_role_preflight_decision` never resumes for it. Fail closed rather than rely
            // on that from a distance.
            super::CustomRolePreflightDecision::ResumeInterruptedMigration => Err(super::custom_role_preflight_error(
                super::CustomRolePreflightDecision::RefuseAmbiguousPartialMigration,
                facts,
            )),
            decision => Err(super::custom_role_preflight_error(decision, facts)),
        }
    }

    pub fn run_migrations(db_url: &str) -> Result<(), super::Error> {
        // Make sure the database is up to date (create if it doesn't exist, or run the migrations)
        let mut connection = diesel::pg::PgConnection::establish(db_url)?;

        preflight(&mut connection)?;

        connection.run_pending_migrations(MIGRATIONS).expect("Error running migrations");
        Ok(())
    }
}

/// The one upgrade shape that has no representation in the new model: a plain `User` still carrying
/// membership `access_all`. Refusing is the default and the only fail-closed answer; the two other
/// policies are an explicit operator decision.
#[cfg(test)]
mod custom_role_preflight_tests {
    use super::{
        CustomRoleMigrationFacts, CustomRolePreflightDecision, LegacyUserAccessAllPolicy,
        custom_role_preflight_decision,
    };

    #[test]
    fn the_legacy_user_access_all_policy_decides_a_pending_upgrade() {
        let pending = CustomRoleMigrationFacts {
            memberships_table_exists: true,
            access_all_column_exists: true,
            legacy_user_access_all_count: 1,
            ..CustomRoleMigrationFacts::default()
        };

        for (policy, expected) in [
            (LegacyUserAccessAllPolicy::Refuse, CustomRolePreflightDecision::RefuseLegacyUserAccessAll),
            (LegacyUserAccessAllPolicy::Drop, CustomRolePreflightDecision::DropLegacyUserAccessAll),
            (LegacyUserAccessAllPolicy::Materialize, CustomRolePreflightDecision::MaterializeLegacyUserAccessAll),
        ] {
            assert_eq!(custom_role_preflight_decision(pending, policy, false), expected, "{policy:?}");
        }

        // What an unset or unparsable configuration value falls back to.
        assert_eq!(LegacyUserAccessAllPolicy::default(), LegacyUserAccessAllPolicy::Refuse);

        // Without such a row the upgrade runs, whatever the policy says.
        let clean = CustomRoleMigrationFacts {
            legacy_user_access_all_count: 0,
            ..pending
        };
        assert_eq!(
            custom_role_preflight_decision(clean, LegacyUserAccessAllPolicy::Refuse, false),
            CustomRolePreflightDecision::Proceed
        );
    }
}
