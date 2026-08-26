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
/// Everything in this section exists for one reason: two states that a real Vaultwarden database can
/// be in cannot be converted without a decision that belongs to an owner rather than to a migration.
/// The migration file refuses both of them itself, as the backstop for a bare migration runner, but
/// Diesel reports only the driver-level duplicate-key error that refusal produces. The preflight
/// evaluates the same two predicates before Diesel starts, so the operator gets the question, the
/// review query and the way out instead.
const CUSTOM_ROLE_PERMISSIONS_MIGRATION: &str = "20260630120000";

/// An owner's decision that the collection authority a legacy Manager held *through a group* may
/// become a permanent membership permission.
///
/// Written by an operator, read and consumed by {`CUSTOM_ROLE_PERMISSIONS_MIGRATION`}.
const PERMANENT_COLLECTION_AUTHORITY_ACK_TABLE: &str = "__vw_ack_permanent_collection_authority";

/// Counts the memberships {`CUSTOM_ROLE_PERMISSIONS_MIGRATION`} refuses to convert without
/// [`PERMANENT_COLLECTION_AUTHORITY_ACK_TABLE`].
///
/// Deliberately the same predicate as the guard inside that file, phrased against the same legacy
/// schema: the migration has not run yet whenever this is evaluated. The two must never disagree --
/// `the_preflight_lookahead_agrees_with_the_migration` pins that against the real file.
///
/// `groups` is the backend's quoting of the reserved identifier.
fn permanent_authority_lookahead_query(groups: &str) -> String {
    format!(
        "SELECT COUNT(*) AS count FROM users_organizations AS uo \
         WHERE uo.atype = 3 \
           AND uo.access_all = FALSE \
           AND EXISTS ( \
               SELECT 1 \
               FROM groups_users AS gu \
               INNER JOIN {groups} AS g ON g.uuid = gu.groups_uuid \
               WHERE gu.users_organizations_uuid = uo.uuid \
                 AND g.organizations_uuid = uo.org_uuid \
                 AND g.access_all = TRUE \
           )"
    )
}

const LEGACY_USER_ACCESS_ALL_RECOVERY: &str = concat!(
    "\n\nList the affected memberships:\n",
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
    "INSERT INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords, manage)\n",
    "SELECT uo.user_uuid, c.uuid, FALSE, FALSE, FALSE\n",
    "FROM users_organizations uo\n",
    "INNER JOIN collections c ON c.org_uuid = uo.org_uuid\n",
    "WHERE uo.uuid = '<MEMBERSHIP_UUID>'\n",
    "  AND NOT EXISTS (\n",
    "    SELECT 1 FROM users_collections uc\n",
    "    WHERE uc.user_uuid = uo.user_uuid AND uc.collection_uuid = c.uuid\n",
    "  );\n\n",
    "Existing assignments are left untouched by that statement, so re-check their read_only / ",
    "hide_passwords values: access_all used to override both.\n\n",
    "If the member genuinely needs organization-wide reach afterwards, give them the Custom role with ",
    "the 'Edit any collection' permission from the web vault once the upgrade has completed. That is ",
    "the supported, visible and revocable equivalent."
);

/// The one question this feature has to ask.
///
/// {`CUSTOM_ROLE_PERMISSIONS_MIGRATION`} refuses the same condition from inside the migration, as the
/// backstop for a bare migration runner. On the normal startup path that abort would reach the
/// operator as nothing but `UNIQUE constraint failed: __vw_permanent_authority_guard.blocked` (or
/// `Duplicate entry '1' for key 'PRIMARY'` on MySQL/MariaDB), so the decision, the review query and
/// the acknowledgement all have to be printed from here.
const PERMANENT_COLLECTION_AUTHORITY_RECOVERY: &str = concat!(
    "\n\nBefore the Custom role, a Manager who reached every collection through an organization-local ",
    "group with access_all held that authority *while* the group relationship lasted: it ended with ",
    "the group, with its accessAll, and with the membership leaving it, and it was inert whenever ",
    "ORG_GROUPS_ENABLED was false. The new model has no permission that is bound to a group like ",
    "that -- edit_any_collection and delete_any_collection live on the membership -- so the upgrade ",
    "writes the authority onto the membership, and the result is deliberately not identical to what ",
    "it replaces:\n",
    "  * it no longer lapses when the last qualifying group disappears, or when accessAll is ",
    "cleared;\n",
    "  * it applies even with the groups feature switched off;\n",
    "  * edit_any_collection additionally satisfies has_full_access(), so the member reaches every ",
    "collection of the organization directly rather than through the group.\n\n",
    "Granting that silently would be a migration handing out durable organization-wide collection ",
    "edit and delete on its own authority; skipping it silently would take a capability away. ",
    "Neither is Vaultwarden's to choose, so an owner decides. Review the affected memberships with ",
    "every Vaultwarden instance stopped and a backup taken:\n",
    "SELECT uo.uuid, uo.user_uuid, uo.org_uuid, uo.status\n",
    "FROM users_organizations uo\n",
    "WHERE uo.atype = 3\n",
    "  AND uo.access_all = FALSE\n",
    "  AND EXISTS (\n",
    "    SELECT 1 FROM groups_users gu\n",
    "    INNER JOIN \"groups\" g ON g.uuid = gu.groups_uuid\n",
    "      AND g.organizations_uuid = uo.org_uuid\n",
    "    WHERE gu.users_organizations_uuid = uo.uuid AND g.access_all = TRUE);\n\n",
    "(Quote `groups` with backticks instead of double quotes on MySQL/MariaDB.)\n\n",
    "An invited, accepted or revoked membership is listed too, and deliberately so. It holds no ",
    "authority today -- every guard requires a confirmed membership -- but the permission is what it ",
    "would come back with if the membership is ever restored, and by then the group it came from may ",
    "be gone.\n\n",
    "A Manager whose own membership access_all bit is set is not listed: that bit is already a ",
    "durable membership-level grant, so converting it into the three collection permissions changes ",
    "no meaning.\n\n",
    "To decline the authority for a membership, end the group relationship it comes from -- for the ",
    "one membership, or for the whole group at once:\n",
    "DELETE FROM groups_users\n",
    "WHERE users_organizations_uuid = '<MEMBERSHIP_UUID>'\n",
    "  AND groups_uuid = '<GROUP_UUID>';\n",
    "UPDATE \"groups\" SET access_all = FALSE WHERE uuid = '<GROUP_UUID>';\n\n",
    "That also takes away the access the membership has today, which is the same decision either ",
    "way -- just made before the upgrade rather than after it. Whatever still matches the query ",
    "above is what the acknowledgement covers; the permissions can equally be cleared afterwards, ",
    "since Vaultwarden does not start until the decision is recorded and nothing is ever live in ",
    "between:\n",
    "UPDATE users_organizations\n",
    "SET edit_any_collection = FALSE, delete_any_collection = FALSE\n",
    "WHERE uuid = '<MEMBERSHIP_UUID>';\n\n",
    "Then record the decision once, and restart:\n",
    "CREATE TABLE __vw_ack_permanent_collection_authority (acknowledged INTEGER NOT NULL PRIMARY KEY);\n\n",
    "The acknowledgement is consumed by the migration, so one decision covers one upgrade. It grants ",
    "nothing and revokes nothing by itself -- whatever you leave in place is what the members keep."
);

const MISSING_ACCESS_ALL_RECOVERY: &str = concat!(
    "\n\nThe upgrade derives every Custom collection permission from that column, so it cannot run ",
    "without it, and neither of the two questions above it can be answered. This state does not arise ",
    "from any Vaultwarden version: the column is only ever removed together with the ledger entry ",
    "that records the removal.\n\n",
    "If the database was rolled back with tools/custom_role_rollback/, run that script to completion ",
    "-- it restores the column and the ledger together. Otherwise restore the backup taken before the ",
    "schema was changed by hand and start again from there."
);

/// What the preflight reads. All of it comes from the schema and the migration ledger.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "These are independent facts read from a database schema and its migration ledger"
)]
struct CustomRoleMigrationFacts {
    memberships_table_exists: bool,
    /// {`CUSTOM_ROLE_PERMISSIONS_MIGRATION`} is recorded, i.e. this database is already upgraded.
    migration_applied: bool,
    access_all_column_exists: bool,
    legacy_user_access_all_count: i64,
    permanent_collection_authority_ack: bool,
    /// See [`permanent_authority_lookahead_query`].
    unconfirmed_permanent_authority_count: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CustomRolePreflightDecision {
    Proceed,
    RefuseMissingAccessAll,
    RefuseLegacyUserAccessAll,
    RefuseUnconfirmedPermanentCollectionAuthority,
}

fn custom_role_preflight_decision(facts: CustomRoleMigrationFacts) -> CustomRolePreflightDecision {
    // A fresh installation: Diesel creates the schema from scratch and there is nothing to convert.
    if !facts.memberships_table_exists {
        return CustomRolePreflightDecision::Proceed;
    }

    // Already upgraded. Every question below is about the legacy schema, which no longer exists, and
    // Diesel never runs a recorded migration again.
    if facts.migration_applied {
        return CustomRolePreflightDecision::Proceed;
    }

    // The migration is pending, so the legacy column has to be there -- both questions below read it,
    // and the conversion derives all three collection permissions from it.
    if !facts.access_all_column_exists {
        return CustomRolePreflightDecision::RefuseMissingAccessAll;
    }

    // A plain User carrying membership `access_all` has no representation in the new model: the bit
    // gave unlimited *reach* over every collection, present and future, without any management
    // authority, and the role that replaces it cannot express that. Converting the reach into direct
    // per-collection assignments would silently turn a dynamic guarantee into a point-in-time
    // snapshot, and -- because a `users_collections` row is not bound to the membership status the
    // way `access_all` was -- would hand a revoked or never-confirmed member durable assignments that
    // outlive this schema. Refuse and let an owner decide.
    if facts.legacy_user_access_all_count != 0 {
        return CustomRolePreflightDecision::RefuseLegacyUserAccessAll;
    }

    // The schema is fine and the upgrade is ready to run, but one step of it changes a meaning that
    // nothing in the new model can express, and that is an owner's decision rather than a migration's.
    if !facts.permanent_collection_authority_ack && facts.unconfirmed_permanent_authority_count != 0 {
        return CustomRolePreflightDecision::RefuseUnconfirmedPermanentCollectionAuthority;
    }

    CustomRolePreflightDecision::Proceed
}

fn custom_role_preflight_error(decision: CustomRolePreflightDecision, facts: CustomRoleMigrationFacts) -> Error {
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
        CustomRolePreflightDecision::RefuseUnconfirmedPermanentCollectionAuthority => format!(
            "Found {} legacy Manager membership(s) whose organization-wide collection authority comes \
             only from an organization-local group with access_all. Migration \
             {CUSTOM_ROLE_PERMISSIONS_MIGRATION} would turn that group-bound capability into a \
             permanent membership permission, which is an owner's decision.",
            facts.unconfirmed_permanent_authority_count
        ),
        CustomRolePreflightDecision::Proceed => {
            unreachable!("Proceed is not an error")
        }
    };

    let recovery = match decision {
        CustomRolePreflightDecision::RefuseMissingAccessAll => MISSING_ACCESS_ALL_RECOVERY,
        CustomRolePreflightDecision::RefuseLegacyUserAccessAll => LEGACY_USER_ACCESS_ALL_RECOVERY,
        CustomRolePreflightDecision::RefuseUnconfirmedPermanentCollectionAuthority => {
            PERMANENT_COLLECTION_AUTHORITY_RECOVERY
        }
        CustomRolePreflightDecision::Proceed => "",
    };

    std::io::Error::other(format!(
        "Custom-role migration preflight stopped startup: {detail} Nothing has been changed.{recovery}"
    ))
    .into()
}

// Embed the migrations from the migrations folder into the application
// This way, the program automatically migrates the database to the latest version
// https://docs.rs/diesel_migrations/*/diesel_migrations/macro.embed_migrations.html
#[cfg(sqlite)]
mod sqlite_migrations {
    use diesel::{Connection, RunQueryDsl};
    use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
    pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/sqlite");

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

    fn preflight(connection: &mut diesel::sqlite::SqliteConnection) -> Result<(), super::Error> {
        let memberships_table_exists = table_exists(connection, "users_organizations")?;
        if !memberships_table_exists {
            return Ok(());
        }

        let migration_applied = table_exists(connection, "__diesel_schema_migrations")?
            && count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                     WHERE version = '{}'",
                    super::CUSTOM_ROLE_PERMISSIONS_MIGRATION
                ),
            )? != 0;
        let access_all_column_exists = count(
            connection,
            "SELECT COUNT(*) AS count FROM pragma_table_info('users_organizations') \
             WHERE name = 'access_all'",
        )? != 0;

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
        let unconfirmed_permanent_authority_count = if access_all_column_exists {
            count(connection, super::permanent_authority_lookahead_query("\"groups\""))?
        } else {
            0
        };

        let facts = super::CustomRoleMigrationFacts {
            memberships_table_exists,
            migration_applied,
            access_all_column_exists,
            legacy_user_access_all_count,
            permanent_collection_authority_ack: table_exists(
                connection,
                super::PERMANENT_COLLECTION_AUTHORITY_ACK_TABLE,
            )?,
            unconfirmed_permanent_authority_count,
        };

        let decision = super::custom_role_preflight_decision(facts);
        if decision == super::CustomRolePreflightDecision::Proceed {
            Ok(())
        } else {
            Err(super::custom_role_preflight_error(decision, facts))
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

    fn preflight(connection: &mut diesel::mysql::MysqlConnection) -> Result<(), super::Error> {
        let memberships_table_exists = table_exists(connection, "users_organizations")?;
        if !memberships_table_exists {
            return Ok(());
        }

        let migration_applied = table_exists(connection, "__diesel_schema_migrations")?
            && count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                     WHERE version = '{}'",
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
        let unconfirmed_permanent_authority_count = if access_all_column_exists {
            count(connection, super::permanent_authority_lookahead_query("`groups`"))?
        } else {
            0
        };

        let facts = super::CustomRoleMigrationFacts {
            memberships_table_exists,
            migration_applied,
            access_all_column_exists,
            legacy_user_access_all_count,
            permanent_collection_authority_ack: table_exists(
                connection,
                super::PERMANENT_COLLECTION_AUTHORITY_ACK_TABLE,
            )?,
            unconfirmed_permanent_authority_count,
        };

        let decision = super::custom_role_preflight_decision(facts);
        if decision == super::CustomRolePreflightDecision::Proceed {
            Ok(())
        } else {
            Err(super::custom_role_preflight_error(decision, facts))
        }
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
    /// `current_schema()` is the first *existing* schema on the `search_path`, which is where new
    /// objects are created. It is not necessarily the schema an existing table is found in: with
    /// `search_path = decoy, real` and the tables in `real`, `current_schema()` answers `decoy`, the
    /// lookup finds nothing, and `preflight` returns early on `!memberships_table_exists` -- silently
    /// skipping both checks while Diesel then runs the migration against `real`. `to_regclass` walks
    /// the same path the migration does, so the preflight and the statements it is guarding can no
    /// longer disagree about which table they mean. (The migration itself resolves the
    /// acknowledgement the same way, and `tools/custom_role_rollback/postgresql.sql` binds the
    /// namespace once for the same reason.)
    fn table_exists(connection: &mut diesel::pg::PgConnection, table: &str) -> Result<bool, diesel::result::Error> {
        count(connection, format!("SELECT COUNT(*) AS count FROM pg_class WHERE oid = to_regclass('{table}')"))
            .map(|value| value != 0)
    }

    fn preflight(connection: &mut diesel::pg::PgConnection) -> Result<(), super::Error> {
        let memberships_table_exists = table_exists(connection, "users_organizations")?;
        if !memberships_table_exists {
            return Ok(());
        }

        let migration_applied = table_exists(connection, "__diesel_schema_migrations")?
            && count(
                connection,
                format!(
                    "SELECT COUNT(*) AS count FROM __diesel_schema_migrations \
                     WHERE version = '{}'",
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
        let unconfirmed_permanent_authority_count = if access_all_column_exists {
            count(connection, super::permanent_authority_lookahead_query("\"groups\""))?
        } else {
            0
        };

        let facts = super::CustomRoleMigrationFacts {
            memberships_table_exists,
            migration_applied,
            access_all_column_exists,
            legacy_user_access_all_count,
            permanent_collection_authority_ack: table_exists(
                connection,
                super::PERMANENT_COLLECTION_AUTHORITY_ACK_TABLE,
            )?,
            unconfirmed_permanent_authority_count,
        };

        let decision = super::custom_role_preflight_decision(facts);
        if decision == super::CustomRolePreflightDecision::Proceed {
            Ok(())
        } else {
            Err(super::custom_role_preflight_error(decision, facts))
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

/// Executes the real migration file against a throwaway SQLite database.
///
/// Everything else in this file tests the *decision* the preflight makes; nothing else tests the SQL
/// that decision is protecting. The rules the migration encodes -- legacy authority is materialized
/// from what a membership held at that moment, and only from its own organization -- are invisible to
/// a Rust test unless the statements actually run.
#[cfg(all(test, sqlite))]
mod custom_role_migration_sql_tests {
    use diesel::connection::SimpleConnection;
    use diesel::{
        Connection, RunQueryDsl,
        sql_types::{BigInt, Text},
        sqlite::SqliteConnection,
    };

    const ADD_CUSTOM_ROLE_PERMISSIONS: &str =
        include_str!("../../migrations/sqlite/2026-06-30-120000_add_custom_role_permissions/up.sql");

    const PERMANENT_AUTHORITY_ACK: &str =
        "CREATE TABLE __vw_ack_permanent_collection_authority (acknowledged INTEGER NOT NULL PRIMARY KEY)";

    /// `users_organizations` exactly as current upstream main leaves it: membership `access_all`, the
    /// retired Manager role, and none of the nine permission columns.
    const LEGACY_SCHEMA: &str = "
        CREATE TABLE users_organizations (
            uuid       TEXT    NOT NULL PRIMARY KEY,
            user_uuid  TEXT    NOT NULL,
            org_uuid   TEXT    NOT NULL,
            access_all BOOLEAN NOT NULL,
            akey       TEXT    NOT NULL DEFAULT '',
            status     INTEGER NOT NULL DEFAULT 2,
            atype      INTEGER NOT NULL,
            reset_password_key TEXT,
            external_id TEXT,
            invited_by_email TEXT DEFAULT NULL,
            UNIQUE (user_uuid, org_uuid)
        );
        CREATE TABLE groups (
            uuid TEXT NOT NULL PRIMARY KEY,
            organizations_uuid TEXT NOT NULL,
            access_all BOOLEAN NOT NULL DEFAULT FALSE
        );
        CREATE TABLE groups_users (
            groups_uuid TEXT NOT NULL,
            users_organizations_uuid TEXT NOT NULL,
            PRIMARY KEY (groups_uuid, users_organizations_uuid)
        );
    ";

    /// One membership per legacy shape the conversion treats differently, in two organizations.
    ///
    /// `m_mgr_foreign` is the tenancy probe: a *first* organization's Manager carrying a
    /// `groups_users` row that points at the *second* organization's `accessAll` group. Nothing in
    /// the HTTP API creates that row, which is exactly why the organization predicate in the
    /// migration has to be tested rather than assumed.
    const LEGACY_MEMBERSHIPS: &str = "
        INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES
            ('g_all',    'org1', TRUE),
            ('g_plain',  'org1', FALSE),
            ('g2_all',   'org2', TRUE);
        INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, status, atype) VALUES
            ('m_owner',       'u1',  'org1', TRUE,   2,  0),
            ('m_admin',       'u2',  'org1', TRUE,   2,  1),
            ('m_user',        'u3',  'org1', FALSE,  2,  2),
            ('m_mgr_all',     'u4',  'org1', TRUE,   2,  3),
            ('m_mgr_bare',    'u5',  'org1', FALSE,  2,  3),
            ('m_mgr_plain_g', 'u6',  'org1', FALSE,  2,  3),
            ('m_mgr_group',   'u7',  'org1', FALSE,  2,  3),
            ('m_user_group',  'u8',  'org1', FALSE,  2,  2),
            ('m_mgr_invited', 'u9',  'org1', FALSE,  0,  3),
            ('m_mgr_revoked', 'u10', 'org1', FALSE, -1,  3),
            ('m_mgr_foreign', 'u11', 'org1', FALSE,  2,  3),
            ('m2_mgr_group',  'u12', 'org2', FALSE,  2,  3),
            ('m2_user',       'u7',  'org2', FALSE,  2,  2);
        INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES
            ('g_all',   'm_mgr_group'),
            ('g_all',   'm_user_group'),
            ('g_all',   'm_mgr_revoked'),
            ('g_plain', 'm_mgr_plain_g'),
            ('g2_all',  'm2_mgr_group'),
            ('g2_all',  'm_mgr_foreign');
    ";

    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = BigInt)]
        count: i64,
    }

    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Text)]
        value: String,
    }

    fn count(connection: &mut SqliteConnection, query: &str) -> i64 {
        diesel::sql_query(query).get_result::<Count>(connection).map(|row| row.count).unwrap()
    }

    fn rows(connection: &mut SqliteConnection, query: &str) -> Vec<String> {
        diesel::sql_query(query).load::<Row>(connection).unwrap().into_iter().map(|row| row.value).collect()
    }

    fn connect(memberships: &str) -> SqliteConnection {
        let mut connection = SqliteConnection::establish(":memory:").unwrap();
        connection.batch_execute("PRAGMA foreign_keys = OFF").unwrap();
        connection.batch_execute(LEGACY_SCHEMA).unwrap();
        connection.batch_execute(memberships).unwrap();
        connection
    }

    fn acknowledge(connection: &mut SqliteConnection) {
        connection.batch_execute(PERMANENT_AUTHORITY_ACK).unwrap();
    }

    /// Applies the migration the way Diesel's harness does: inside a transaction, so a refusal rolls
    /// back the temporary guard tables as well and a retry starts from the same state a restart would.
    fn migrate(connection: &mut SqliteConnection) -> Result<(), diesel::result::Error> {
        connection.transaction(|connection| connection.batch_execute(ADD_CUSTOM_ROLE_PERMISSIONS))
    }

    /// Every membership's role plus the six permissions the conversion can set, as one line each.
    fn state(connection: &mut SqliteConnection) -> Vec<String> {
        rows(
            connection,
            "SELECT uuid || ' atype=' || atype \
                 || ' ' || create_new_collections || edit_any_collection || delete_any_collection \
                 || ' ' || manage_users || manage_groups || manage_policies \
                 || access_event_logs || access_import_export || access_reports AS value \
             FROM users_organizations ORDER BY uuid",
        )
    }

    fn legacy_state(connection: &mut SqliteConnection) -> Vec<String> {
        rows(
            connection,
            "SELECT uuid || ' atype=' || atype || ' access_all=' || access_all AS value \
             FROM users_organizations ORDER BY uuid",
        )
    }

    fn table_exists(connection: &mut SqliteConnection, table: &str) -> bool {
        count(
            connection,
            &format!("SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = '{table}'"),
        ) != 0
    }

    /// The whole conversion, in one comparison. Written out per membership on purpose: every line is
    /// a rule, and a regression in any of them is a silent authorization change.
    #[test]
    fn the_conversion_maps_every_legacy_shape_exactly_once() {
        let mut connection = connect(LEGACY_MEMBERSHIPS);
        acknowledge(&mut connection);
        migrate(&mut connection).unwrap();

        assert_eq!(
            state(&mut connection),
            [
                // The second organization is converted on its own terms...
                "m2_mgr_group atype=4 011 000000",
                // ...and the same *user* holding a plain User membership there gains nothing from
                // being a Manager in the first organization.
                "m2_user atype=2 000 000000",
                // Admin keeps its role; the new model grants it everything implicitly, so no
                // permission column is set.
                "m_admin atype=1 000 000000",
                // Membership access_all was the "Manage all collections" checkbox: all three.
                "m_mgr_all atype=4 111 000000",
                // Manager with nothing: Custom with nothing.
                "m_mgr_bare atype=4 000 000000",
                // A groups_users row pointing at another organization's accessAll group grants
                // nothing -- the migration requires the group to belong to the membership's own org.
                "m_mgr_foreign atype=4 000 000000",
                // Group-derived authority: edit and delete, never create.
                "m_mgr_group atype=4 011 000000",
                // Invited is converted like any other membership.
                "m_mgr_invited atype=4 000 000000",
                // A group without accessAll conveys nothing.
                "m_mgr_plain_g atype=4 000 000000",
                // Revoked is converted like any other membership: status is not part of the rule.
                "m_mgr_revoked atype=4 011 000000",
                "m_owner atype=0 000 000000",
                // A plain User is never converted, not even inside an accessAll group.
                "m_user atype=2 000 000000",
                "m_user_group atype=2 000 000000",
            ]
        );
    }

    /// The nine columns exist, `access_all` does not, and nothing else about the table changed.
    #[test]
    fn the_rebuilt_table_has_the_final_shape() {
        let mut connection = connect(LEGACY_MEMBERSHIPS);
        acknowledge(&mut connection);
        migrate(&mut connection).unwrap();

        assert_eq!(
            rows(&mut connection, "SELECT name AS value FROM pragma_table_xinfo('users_organizations')"),
            [
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
            ]
        );
        // The primary key and the UNIQUE pair, and nothing else: the rollback script checks for
        // exactly these two and would refuse a database the rebuild had changed.
        assert_eq!(count(&mut connection, "SELECT COUNT(*) AS count FROM pragma_index_list('users_organizations')"), 2);
        assert_eq!(
            count(
                &mut connection,
                "SELECT COUNT(*) AS count FROM users_organizations WHERE uuid = 'm_owner' AND user_uuid = 'u1'"
            ),
            1
        );
    }

    /// The one shape the upgrade refuses outright, checked in the SQL rather than only in the Rust
    /// preflight: `diesel migration run` and a bare `MigrationHarness` never consult the preflight,
    /// and the column that carries the reach is gone a few statements later.
    #[test]
    fn a_plain_user_carrying_access_all_is_refused_and_nothing_changes() {
        let memberships = "
            INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
                ('m_user_all', 'u1', 'org1', TRUE, 2);
        ";
        let mut connection = connect(memberships);
        acknowledge(&mut connection);
        let before = legacy_state(&mut connection);

        assert!(migrate(&mut connection).is_err());

        assert_eq!(legacy_state(&mut connection), before);
        assert!(
            count(
                &mut connection,
                "SELECT COUNT(*) AS count FROM pragma_table_info('users_organizations') WHERE name = 'access_all'"
            ) == 1,
            "the refusal must leave the legacy column in place"
        );
        assert_eq!(
            count(
                &mut connection,
                "SELECT COUNT(*) AS count FROM pragma_table_info('users_organizations') \
                 WHERE name IN ('manage_users', 'create_new_collections', 'access_reports')"
            ),
            0,
            "the refusal must not leave a half-applied schema behind"
        );
    }

    /// Materializing group-derived authority makes a group-bound capability permanent. That is the
    /// one meaning the new model cannot reproduce, so it takes an owner's decision.
    #[test]
    fn group_derived_authority_needs_an_acknowledgement() {
        let mut connection = connect(LEGACY_MEMBERSHIPS);
        let before = legacy_state(&mut connection);

        assert!(migrate(&mut connection).is_err());
        assert_eq!(legacy_state(&mut connection), before);

        acknowledge(&mut connection);
        migrate(&mut connection).unwrap();
    }

    /// A Manager whose own `access_all` bit is set is not part of the question: that bit is already a
    /// durable membership-level grant, so converting it changes no meaning and must not stop an
    /// upgrade that has nothing else to decide.
    #[test]
    fn a_manager_with_its_own_access_all_bit_is_not_asked_about() {
        let memberships = "
            INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g_all', 'org1', TRUE);
            INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
                ('m_mgr_both', 'u1', 'org1', TRUE, 3);
            INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g_all', 'm_mgr_both');
        ";
        let mut connection = connect(memberships);

        migrate(&mut connection).unwrap();

        assert_eq!(state(&mut connection), ["m_mgr_both atype=4 111 000000"]);
    }

    /// One decision covers one upgrade. The acknowledgement is consumed, and a leftover downgrade
    /// acknowledgement is cleared with it so consent is never inherited across a re-upgrade.
    #[test]
    fn the_acknowledgements_are_consumed_by_the_upgrade() {
        let mut connection = connect(LEGACY_MEMBERSHIPS);
        acknowledge(&mut connection);
        connection
            .batch_execute("CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY)")
            .unwrap();

        migrate(&mut connection).unwrap();

        assert!(!table_exists(&mut connection, super::PERMANENT_COLLECTION_AUTHORITY_ACK_TABLE));
        assert!(!table_exists(&mut connection, "__vw_allow_custom_role_downgrade"));
    }

    /// The preflight refuses before Diesel starts; the migration refuses from inside. They read the
    /// same condition, so they have to answer identically for every shape -- otherwise Vaultwarden
    /// either asks a question the migration would not have asked, or lets the migration abort with
    /// nothing but a duplicate-key error.
    #[test]
    fn the_preflight_lookahead_agrees_with_the_migration() {
        let cases: [(&str, &str); 6] = [
            (
                "nothing to decide",
                "INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) \
                 VALUES ('m', 'u', 'org1', FALSE, 3);",
            ),
            (
                "group without accessAll",
                "
                INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g', 'org1', FALSE);
                INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
                    ('m', 'u', 'org1', FALSE, 3);
                INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g', 'm');",
            ),
            (
                "group with accessAll",
                "
                INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g', 'org1', TRUE);
                INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
                    ('m', 'u', 'org1', FALSE, 3);
                INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g', 'm');",
            ),
            (
                "membership access_all as well",
                "
                INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g', 'org1', TRUE);
                INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
                    ('m', 'u', 'org1', TRUE, 3);
                INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g', 'm');",
            ),
            (
                "plain User in an accessAll group",
                "
                INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g', 'org1', TRUE);
                INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
                    ('m', 'u', 'org1', FALSE, 2);
                INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g', 'm');",
            ),
            (
                "accessAll group of another organization",
                "
                INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES ('g', 'org2', TRUE);
                INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, atype) VALUES
                    ('m', 'u', 'org1', FALSE, 3);
                INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES ('g', 'm');",
            ),
        ];

        for (name, memberships) in cases {
            let mut connection = connect(memberships);
            let predicted = count(&mut connection, &super::permanent_authority_lookahead_query("\"groups\"")) != 0;
            let refused = migrate(&mut connection).is_err();
            assert_eq!(predicted, refused, "preflight and migration disagree for: {name}");
        }
    }
}

/// Runs the real migration, then `tools/custom_role_rollback/sqlite.sql`, then the migration again --
/// against a throwaway SQLite database, with the real files on both legs.
///
/// The round trip is the claim the rollback tooling rests on: an operator who downgrades and later
/// upgrades again has to arrive at the same permissions, or the escape hatch quietly rewrites
/// authorization.
#[cfg(all(test, sqlite))]
mod custom_role_rollback_sql_tests {
    use diesel::connection::SimpleConnection;
    use diesel::{Connection, RunQueryDsl, sql_types::Text, sqlite::SqliteConnection};

    const MIGRATION: &str =
        include_str!("../../migrations/sqlite/2026-06-30-120000_add_custom_role_permissions/up.sql");
    const REVERT: &str = include_str!("../../migrations/sqlite/2026-06-30-120000_add_custom_role_permissions/down.sql");
    const ROLLBACK: &str = include_str!("../../tools/custom_role_rollback/sqlite.sql");

    const VERSION: &str = "20260630120000";

    const PERMANENT_AUTHORITY_ACK: &str =
        "CREATE TABLE __vw_ack_permanent_collection_authority (acknowledged INTEGER NOT NULL PRIMARY KEY)";
    const DOWNGRADE_ACK: &str =
        "CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY)";
    const ALLOWLIST: &str =
        "CREATE TABLE __vw_rollback_manager_allowlist (users_organizations_uuid TEXT NOT NULL PRIMARY KEY)";

    /// `users_organizations` exactly as current upstream main leaves it -- the rollback script checks
    /// for *precisely* eighteen columns and two indexes afterwards, so a reduced fixture would not
    /// exercise the checks it exists for.
    const UPSTREAM_SCHEMA: &str = "
        CREATE TABLE __diesel_schema_migrations (
            version VARCHAR(50) NOT NULL PRIMARY KEY,
            run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE users_organizations (
            uuid       TEXT    NOT NULL PRIMARY KEY,
            user_uuid  TEXT    NOT NULL,
            org_uuid   TEXT    NOT NULL,
            access_all BOOLEAN NOT NULL DEFAULT FALSE,
            akey       TEXT    NOT NULL DEFAULT '',
            status     INTEGER NOT NULL DEFAULT 2,
            atype      INTEGER NOT NULL,
            reset_password_key TEXT,
            external_id TEXT,
            invited_by_email TEXT DEFAULT NULL,
            UNIQUE (user_uuid, org_uuid)
        );
        CREATE TABLE groups (
            uuid TEXT NOT NULL PRIMARY KEY,
            organizations_uuid TEXT NOT NULL,
            access_all BOOLEAN NOT NULL DEFAULT FALSE
        );
        CREATE TABLE groups_users (
            groups_uuid TEXT NOT NULL,
            users_organizations_uuid TEXT NOT NULL,
            PRIMARY KEY (groups_uuid, users_organizations_uuid)
        );
        INSERT INTO __diesel_schema_migrations (version) VALUES ('20250109172300');
    ";

    /// One membership per legacy shape that the mapping treats differently.
    const LEGACY_MEMBERSHIPS: &str = "
        INSERT INTO groups (uuid, organizations_uuid, access_all) VALUES
            ('g_all', 'org', TRUE),
            ('g_plain', 'org', FALSE);
        INSERT INTO users_organizations (uuid, user_uuid, org_uuid, access_all, status, atype) VALUES
            ('m_owner',     'u1', 'org', TRUE,   2, 0),
            ('m_admin',     'u2', 'org', TRUE,   2, 1),
            ('m_user',      'u3', 'org', FALSE,  2, 2),
            ('m_mgr_bare',  'u4', 'org', FALSE,  2, 3),
            ('m_mgr_all',   'u5', 'org', TRUE,   2, 3),
            ('m_mgr_group', 'u6', 'org', FALSE,  2, 3),
            ('m_mgr_gone',  'u7', 'org', FALSE, -1, 3);
        INSERT INTO groups_users (groups_uuid, users_organizations_uuid) VALUES
            ('g_all', 'm_mgr_group'),
            ('g_all', 'm_mgr_gone'),
            ('g_plain', 'm_mgr_bare');
    ";

    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Text)]
        value: String,
    }

    fn rows(connection: &mut SqliteConnection, query: &str) -> Vec<String> {
        diesel::sql_query(query).load::<Row>(connection).unwrap().into_iter().map(|row| row.value).collect()
    }

    fn count(connection: &mut SqliteConnection, query: &str) -> i64 {
        rows(connection, &format!("SELECT ({query}) || '' AS value"))[0].parse().unwrap()
    }

    /// Every membership's role plus its nine permissions, as one comparable line each.
    fn permission_state(connection: &mut SqliteConnection) -> Vec<String> {
        rows(
            connection,
            "SELECT uuid || ' atype=' || atype || ' status=' || status \
                 || ' ' || manage_users || manage_groups || manage_policies \
                 || create_new_collections || edit_any_collection || delete_any_collection \
                 || access_event_logs || access_import_export || access_reports AS value \
             FROM users_organizations ORDER BY uuid",
        )
    }

    fn legacy_state(connection: &mut SqliteConnection) -> Vec<String> {
        rows(
            connection,
            "SELECT uuid || ' atype=' || atype || ' access_all=' || access_all AS value \
             FROM users_organizations ORDER BY uuid",
        )
    }

    /// Applies the migration, recording its version the way Diesel would.
    fn upgrade(connection: &mut SqliteConnection) -> Result<(), diesel::result::Error> {
        connection.batch_execute(PERMANENT_AUTHORITY_ACK)?;
        connection.batch_execute(MIGRATION)?;
        connection.batch_execute(&format!("INSERT INTO __diesel_schema_migrations (version) VALUES ('{VERSION}')"))
    }

    /// `.bail on` is a sqlite3 shell command, not SQL. Dropping it is safe here -- a failing statement
    /// fails the whole `batch_execute` anyway -- but the assertion keeps the test honest if another
    /// dot-command is ever added, because those the shell would act on and this runner would not.
    fn rollback_sql() -> String {
        let (dot, sql): (Vec<&str>, Vec<&str>) = ROLLBACK.lines().partition(|line| line.starts_with('.'));
        assert_eq!(dot, [".bail on"], "unexpected sqlite3 shell command in the rollback script");
        sql.join("\n")
    }

    fn connect() -> SqliteConnection {
        connect_with(LEGACY_MEMBERSHIPS)
    }

    fn connect_with(memberships: &str) -> SqliteConnection {
        let mut connection = SqliteConnection::establish(":memory:").unwrap();
        connection.batch_execute("PRAGMA foreign_keys = OFF").unwrap();
        connection.batch_execute(UPSTREAM_SCHEMA).unwrap();
        connection.batch_execute(memberships).unwrap();
        connection
    }

    /// The whole point of the tooling: upgrade, roll back, upgrade again, and land on the same
    /// permissions. The allowlist is what makes it converge -- it names exactly the memberships that
    /// were Managers, which is what the second upgrade then reads.
    #[test]
    fn upgrade_rollback_and_upgrade_again_converge() {
        let mut connection = connect();
        upgrade(&mut connection).unwrap();
        let after_first_upgrade = permission_state(&mut connection);

        connection.batch_execute(ALLOWLIST).unwrap();
        connection
            .batch_execute(
                "INSERT INTO __vw_rollback_manager_allowlist (users_organizations_uuid) VALUES \
                 ('m_mgr_bare'), ('m_mgr_all'), ('m_mgr_group'), ('m_mgr_gone')",
            )
            .unwrap();
        connection.batch_execute(&rollback_sql()).unwrap();

        assert_eq!(
            legacy_state(&mut connection),
            [
                "m_admin atype=1 access_all=1",
                "m_mgr_all atype=3 access_all=1",
                "m_mgr_bare atype=3 access_all=0",
                // Group-derived authority came back as 0/1/1, which is not all three, so the legacy
                // "manage all collections" bit stays off -- the old binary derives the same authority
                // from `groups.access_all` again anyway.
                "m_mgr_gone atype=3 access_all=0",
                "m_mgr_group atype=3 access_all=0",
                "m_owner atype=0 access_all=1",
                "m_user atype=2 access_all=0",
            ]
        );
        assert_eq!(count(&mut connection, "SELECT COUNT(*) FROM __diesel_schema_migrations"), 1);

        upgrade(&mut connection).unwrap();
        assert_eq!(permission_state(&mut connection), after_first_upgrade, "the round trip must converge");
    }

    /// The role mapping is a decision, not a conversion, so the script refuses to make it up.
    #[test]
    fn the_rollback_refuses_without_an_allowlist_and_changes_nothing() {
        let mut connection = connect();
        upgrade(&mut connection).unwrap();
        let before = permission_state(&mut connection);

        assert!(connection.batch_execute(&rollback_sql()).is_err());

        assert_eq!(permission_state(&mut connection), before);
        assert_eq!(count(&mut connection, "SELECT COUNT(*) FROM __diesel_schema_migrations"), 2);
    }

    /// A migration this script has never seen may have changed anything, including the table it
    /// rebuilds from a fixed column list.
    #[test]
    fn the_rollback_refuses_a_ledger_from_the_future() {
        let mut connection = connect();
        upgrade(&mut connection).unwrap();
        connection.batch_execute(ALLOWLIST).unwrap();
        connection.batch_execute("INSERT INTO __diesel_schema_migrations (version) VALUES ('20270101000000')").unwrap();
        let before = permission_state(&mut connection);

        assert!(connection.batch_execute(&rollback_sql()).is_err());
        assert_eq!(permission_state(&mut connection), before);
    }

    /// The Diesel alternative the README documents, end to end. Both decisions are required, and both
    /// are consumed by the revert they authorize.
    #[test]
    fn the_diesel_revert_runs_with_both_acknowledgements() {
        let mut connection = connect();
        let before = legacy_state(&mut connection);
        upgrade(&mut connection).unwrap();

        connection.batch_execute(DOWNGRADE_ACK).unwrap();
        connection.batch_execute(ALLOWLIST).unwrap();
        connection
            .batch_execute(
                "INSERT INTO __vw_rollback_manager_allowlist (users_organizations_uuid) VALUES \
                 ('m_mgr_bare'), ('m_mgr_all'), ('m_mgr_group'), ('m_mgr_gone')",
            )
            .unwrap();
        connection.batch_execute(REVERT).unwrap();

        // The fixture's Owner and Admin already carry the bit, which is what current main writes for
        // them, so this database round-trips byte-identically. (A database where an Owner somehow had
        // it cleared would come back with it set: the upgrade dropped the column precisely because
        // their role already implies it, so the original value is gone.)
        assert_eq!(legacy_state(&mut connection), before);
        assert!(
            count(
                &mut connection,
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' \
                 AND name IN ('__vw_allow_custom_role_downgrade', '__vw_rollback_manager_allowlist')"
            ) == 0,
            "both decisions authorized exactly this downgrade"
        );
    }

    /// Without the acknowledgement the revert stops before its first mutation.
    #[test]
    fn the_revert_stops_at_the_guard_and_mutates_nothing() {
        let mut connection = connect();
        upgrade(&mut connection).unwrap();
        let before = permission_state(&mut connection);

        assert!(connection.batch_execute(REVERT).is_err());
        assert_eq!(permission_state(&mut connection), before);

        // The acknowledgement alone is not enough either: the role mapping is a separate decision.
        connection.batch_execute(DOWNGRADE_ACK).unwrap();
        assert!(connection.batch_execute(REVERT).is_err());
        assert_eq!(permission_state(&mut connection), before);
    }
}

#[cfg(test)]
mod custom_role_migration_preflight_tests {
    use super::{
        CustomRoleMigrationFacts, CustomRolePreflightDecision, custom_role_preflight_decision,
        custom_role_preflight_error,
    };
    use std::error::Error as _;

    /// The refusal text, read through the I/O error the preflight wraps -- `Error`'s own `Display`
    /// renders the JSON API error body instead.
    fn message(decision: CustomRolePreflightDecision, facts: CustomRoleMigrationFacts) -> String {
        custom_role_preflight_error(decision, facts)
            .source()
            .expect("preflight error should retain its I/O error source")
            .to_string()
    }

    /// A database that has not been upgraded yet and has nothing to decide.
    fn ready() -> CustomRoleMigrationFacts {
        CustomRoleMigrationFacts {
            memberships_table_exists: true,
            migration_applied: false,
            access_all_column_exists: true,
            legacy_user_access_all_count: 0,
            permanent_collection_authority_ack: false,
            unconfirmed_permanent_authority_count: 0,
        }
    }

    #[test]
    fn an_empty_database_proceeds() {
        assert_eq!(
            custom_role_preflight_decision(CustomRoleMigrationFacts::default()),
            CustomRolePreflightDecision::Proceed
        );
    }

    #[test]
    fn an_ordinary_upgrade_proceeds() {
        assert_eq!(custom_role_preflight_decision(ready()), CustomRolePreflightDecision::Proceed);
    }

    /// The checks below all read the legacy schema, so an already-upgraded database must not be
    /// asked about them again -- and a re-run of the question would have no data to answer it from.
    #[test]
    fn an_already_upgraded_database_is_not_asked_anything() {
        let facts = CustomRoleMigrationFacts {
            migration_applied: true,
            access_all_column_exists: false,
            ..ready()
        };
        assert_eq!(custom_role_preflight_decision(facts), CustomRolePreflightDecision::Proceed);
    }

    #[test]
    fn a_pending_migration_without_the_legacy_column_is_refused() {
        let facts = CustomRoleMigrationFacts {
            access_all_column_exists: false,
            ..ready()
        };
        assert_eq!(custom_role_preflight_decision(facts), CustomRolePreflightDecision::RefuseMissingAccessAll);
    }

    #[test]
    fn legacy_user_access_all_is_refused_with_a_recovery_path() {
        let facts = CustomRoleMigrationFacts {
            legacy_user_access_all_count: 2,
            ..ready()
        };
        let decision = custom_role_preflight_decision(facts);
        assert_eq!(decision, CustomRolePreflightDecision::RefuseLegacyUserAccessAll);

        let message = message(decision, facts);
        assert!(message.contains("Nothing has been changed."), "{message}");
        assert!(message.contains("Found 2 membership(s)"), "{message}");
        assert!(message.contains("SET access_all = FALSE"), "{message}");
        assert!(message.contains("INSERT INTO users_collections"), "{message}");
    }

    #[test]
    fn unconfirmed_permanent_collection_authority_is_refused_with_the_question() {
        let facts = CustomRoleMigrationFacts {
            unconfirmed_permanent_authority_count: 3,
            ..ready()
        };
        let decision = custom_role_preflight_decision(facts);
        assert_eq!(decision, CustomRolePreflightDecision::RefuseUnconfirmedPermanentCollectionAuthority);

        let message = message(decision, facts);
        assert!(message.contains("Found 3 legacy Manager membership(s)"), "{message}");
        assert!(message.contains("CREATE TABLE __vw_ack_permanent_collection_authority"), "{message}");
        assert!(message.contains("has_full_access()"), "{message}");
    }

    /// One decision covers one upgrade, and it is asked before the migration -- never after.
    #[test]
    fn the_acknowledgement_answers_the_question_exactly_once() {
        let facts = CustomRoleMigrationFacts {
            unconfirmed_permanent_authority_count: 3,
            permanent_collection_authority_ack: true,
            ..ready()
        };
        assert_eq!(custom_role_preflight_decision(facts), CustomRolePreflightDecision::Proceed);
    }

    /// A damaged legacy schema outranks the owner's question: the answer would be unreadable, and the
    /// migration cannot run either way.
    #[test]
    fn a_damaged_schema_outranks_the_permanent_authority_question() {
        let facts = CustomRoleMigrationFacts {
            access_all_column_exists: false,
            legacy_user_access_all_count: 1,
            unconfirmed_permanent_authority_count: 1,
            ..ready()
        };
        assert_eq!(custom_role_preflight_decision(facts), CustomRolePreflightDecision::RefuseMissingAccessAll);
    }

    /// The state that must never be converted silently outranks the one that only needs a decision.
    #[test]
    fn the_unrepresentable_state_outranks_the_question() {
        let facts = CustomRoleMigrationFacts {
            legacy_user_access_all_count: 1,
            unconfirmed_permanent_authority_count: 1,
            ..ready()
        };
        assert_eq!(custom_role_preflight_decision(facts), CustomRolePreflightDecision::RefuseLegacyUserAccessAll);
    }

    /// Both refusals promise the operator that startup stopped before anything was touched. The
    /// preflight only ever reads, so that promise holds by construction -- this pins the wording that
    /// carries it.
    #[test]
    fn every_refusal_says_nothing_has_been_changed() {
        for decision in [
            CustomRolePreflightDecision::RefuseMissingAccessAll,
            CustomRolePreflightDecision::RefuseLegacyUserAccessAll,
            CustomRolePreflightDecision::RefuseUnconfirmedPermanentCollectionAuthority,
        ] {
            let message = message(decision, ready());
            assert!(message.contains("Nothing has been changed."), "{decision:?}: {message}");
        }
    }
}
