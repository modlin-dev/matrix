use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use colored::*;
use libsql::{Builder, Connection, de};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, net::SocketAddr, sync::Arc, u64};
use tokio::io::Result;
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep};

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrCode {
    MForbidden,                   // M_FORBIDDEN
    MUnknownToken,                // M_UNKNOWN_TOKEN
    MMissingToken,                // M_MISSING_TOKEN
    MUserLocked,                  // M_USER_LOCKED
    MUserSuspended,               // M_USER_SUSPENDED
    MBadJson,                     // M_BAD_JSON
    MNotJson,                     // M_NOT_JSON
    MNotFound,                    // M_NOT_FOUND
    MLimitExceeded,               // M_LIMIT_EXCEEDED
    MUnrecognized,                // M_UNRECOGNIZED
    MUnknownDevice,               // M_UNKNOWN_DEVICE
    MResourceLimitExceeded,       // M_RESOURCE_LIMIT_EXCEEDED
    MUnknown,                     // M_UNKNOWN
    MUnauthorized,                // M_UNAUTHORIZED
    MUserDeactivatedd,            // M_USER_DEACTIVATED
    MUserInUse,                   // M_USER_IN_USE
    MInvalidUsername,             // M_INVALID_USERNAME
    MRoomInUse,                   // M_ROOM_IN_USE
    MInvalidRoomState,            // M_INVALID_ROOM_STATE
    MThreepidInUse,               // M_THREEPID_IN_USE
    MThreepidNotFound,            // M_THREEPID_NOT_FOUND
    MThreepidAuthFailed,          // M_THREEPID_AUTH_FAILED
    MThreepidDenied,              // M_THREEPID_DENIED
    MServerNotTrusted,            // M_SERVER_NOT_TRUSTED
    MUnsupportedRoomVersion,      // M_UNSUPPORTED_ROOM_VERSION
    MIncompatibleRoomVersion,     // M_INCOMPATIBLE_ROOM_VERSION
    MBadState,                    // M_BAD_STATE
    MGuestAccessForbidden,        // M_GUEST_ACCESS_FORBIDDEN
    MCaptchaNeeded,               // M_CAPTCHA_NEEDED
    MCaptchaInvalid,              // M_CAPTCHA_INVALID
    MMissingParam,                // M_MISSING_PARAM
    MInvalidParam,                // M_INVALID_PARAM
    MTooLarge,                    // M_TOO_LARGE
    MExclusive,                   // M_EXCLUSIVE
    MCannotLeaveServerNoticeRoom, // M_CANNOT_LEAVE_SERVER_NOTICE_ROOM
    MThreepidMediumNotSupported,  // M_THREEPID_MEDIUM_NOT_SUPPORTED
}
#[derive(Serialize)]
pub struct MatrixError {
    pub errcode: ErrCode,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct HomeServerInfo {
    pub base_url: &'static str,
}
#[derive(Serialize)]
pub struct IdentityServerInfo {
    pub base_url: &'static str,
}
#[derive(Serialize)]
pub struct MClient {
    // /.well-known/matrix/client
    #[serde(rename = "m.homeserver")]
    pub m_homeserver: HomeServerInfo,
    #[serde(rename = "m.identity_server")]
    pub m_identity_server: IdentityServerInfo,
}

#[derive(Serialize)]
pub struct Contact {
    pub email_address: &'static str,
    pub matrix_id: &'static str,
    pub role: &'static str,
}
#[derive(Serialize)]
pub struct MSupport {
    // /.well-known/matrix/support
    pub contacts: [Contact; 2],
    pub support_page: &'static str,
}

#[derive(Serialize)]
pub struct MServer {
    // /.well-known/matrix/server
    #[serde(rename = "m.server")]
    pub m_server: &'static str,
}

#[derive(Serialize)]
pub struct MVersions {
    // /_matrix/client/versions
    pub unstable_features: HashMap<&'static str, bool>,
    pub versions: [&'static str; 1],
}
#[derive(Serialize)]
pub struct MProfile {
    // /_matrix/client/v3/profile/{userId}
    pub avatar_url: Option<String>,
    pub displayname: Option<String>,
    #[serde(rename = "m.tz")]
    pub m_tz: Option<String>,
}

#[derive(Serialize)]
pub struct Server {
    pub name: &'static str,
    pub version: &'static str,
}
#[derive(Serialize)]
pub struct Federation {
    // /_matrix/fedeation/v1/version
    pub server: Server,
}

#[derive(Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub displayname: Option<String>,
    pub avatar_url: Option<String>,
}

pub struct CreateUser {
    pub id: String,
    pub displayname: Option<String>,
    pub avatar_url: Option<String>,
}
pub struct UpdateUser {
    pub displayname: Option<String>,
    pub avatar_url: Option<String>,
}
pub struct MatrixClient {
    conn: Connection,
}
impl MatrixClient {
    pub fn new(conn: Connection) -> MatrixClient {
        MatrixClient { conn: conn }
    }
    pub async fn profile(&self, user_id: String) -> Option<User> {
        if let Ok(mut rows) = self
            .conn
            .query("SELECT * FROM users WHERE id = ?1", [user_id])
            .await
        {
            if let Ok(Some(row)) = rows.next().await {
                if let Ok(user) = de::from_row::<User>(&row) {
                    return Some(user);
                }
            }
        }
        None
    }
    pub async fn update_profile(&self, user_id: String, update: UpdateUser) -> libsql::Result<()> {
        let mut query = String::from("UPDATE users SET ");
        let mut params = Vec::new();
        let mut assignments = Vec::new();

        if let Some(dn) = update.displayname {
            params.push(libsql::Value::from(dn));
            assignments.push(format!("displayname = ?{}", params.len()));
        }
        if let Some(av) = update.avatar_url {
            params.push(libsql::Value::from(av));
            assignments.push(format!("avatar_url = ?{}", params.len()));
        }
        if assignments.is_empty() {
            return Ok(());
        }

        query.push_str(&assignments.join(", "));
        query.push_str(&format!(" WHERE id = ?{}", params.len() + 1));
        params.push(libsql::Value::from(user_id));

        self.conn.execute(&query, params).await?;
        Ok(())
    }
    pub async fn migrate(&self) -> libsql::Result<()> {
        self.conn
            .execute(
                r#"
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        displayname TEXT,
                        avatar_url TEXT
                    )
                "#,
                (),
            )
            .await?;
        Ok(())
    }
    pub async fn create_user(&self, user: CreateUser) -> libsql::Result<()> {
        self.conn
            .execute(
                "INSERT INTO users (id, displayname) VALUES (?1, ?2)",
                (user.id, user.displayname),
            )
            .await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let monitor = Monitor::new();
    let db = Builder::new_local("local.db").build().await.unwrap();
    let conn = db.connect().unwrap();

    let matrix = MatrixClient::new(conn);

    if let Ok(_) = matrix.migrate().await {
        println!("Successfully migrated!");
    } else {
        println!("Failed to migrate...");
    }
    if let Ok(_) = matrix
        .create_user(CreateUser {
            id: "@sumaiya:modlin.dev".to_string(),
            displayname: Some("Sumaiya Chowdhury".to_string()),
            avatar_url: None,
        })
        .await
    {
        println!("Successfully created user!");
    } else {
        println!("Failed to create user...");
    }

    let app = Router::new()
        .route(
            "/",
            get(|| async {
                sleep(Duration::from_millis(1000)).await;
                "Hello, world!"
            }),
        )
        .nest(
            "/.well-known",
            Router::new().nest(
                "/matrix",
                Router::new()
                    .route(
                        "/server",
                        get(|| async {
                            Json(MServer {
                                m_server: "matrix.modlin.dev:843",
                            })
                        }),
                    )
                    .route(
                        "/client",
                        get(|| async {
                            Json(MClient {
                                m_homeserver: HomeServerInfo {
                                    base_url: "https://matrix.modlin.dev/",
                                },
                                m_identity_server: IdentityServerInfo {
                                    base_url: "https://identity.modlin.dev/",
                                },
                            })
                        }),
                    )
                    .route(
                        "/support",
                        get(|| async {
                            Json(MSupport {
                                contacts: [
                                    Contact {
                                        email_address: "admin@modlin.dev",
                                        matrix_id: "@admin:modlin.dev",
                                        role: "m.role.admin",
                                    },
                                    Contact {
                                        email_address: "security@modlin.dev",
                                        matrix_id: "@security:modlin.dev",
                                        role: "m.role.security",
                                    },
                                ],
                                support_page: "https://matrix.modlin.dev/support",
                            })
                        }),
                    ),
            ),
        )
        .nest(
            "/_matrix",
            Router::new()
                .nest(
                    "/federation",
                    Router::new()
                        .nest(
                            "/v1",
                            Router::new().route(
                                "/version",
                                get(|| async {
                                    Json(Federation {
                                        server: Server {
                                            name: "@modlin/matrix",
                                            version: "0.0.0",
                                        },
                                    })
                                })
                                .fallback(unrecognized_method),
                            ),
                        )
                        .nest("/v2", Router::new())
                        .fallback(unrecognized_endpoint),
                )
                .nest(
                    "/client",
                    Router::new()
                        .nest("/v1", Router::new())
                        .nest("/v2", Router::new())
                        .nest(
                            "/v3",
                            Router::new()
                                .route(
                                    "/profile/{userId}",
                                    get(|Path(user_id): Path<String>, State(matrix): State<Arc<MatrixClient>>| async move {
                                        if let Some(user) = matrix.profile(user_id).await {
                                            return (StatusCode::OK, Json(MProfile {
                                                avatar_url: user.avatar_url,
                                                displayname: user.displayname,
                                                m_tz: Some("Asia/Dhaka".to_string()),
                                            })).into_response();
                                        }

                                        (
                                            StatusCode::NOT_FOUND,
                                            Json(MatrixError {
                                                errcode: ErrCode::MNotFound,
                                                error: Some("Profile not found".to_string()),
                                            }),
                                        ).into_response()
                                    }),
                                )
                                .route(
                                    "/profile/{userId}/{keyName}",
                                    get(|Path((user_id, key_name)): Path<(String, String)>, State(matrix): State<Arc<MatrixClient>>| async move {
                                        if let Some(user) = matrix.profile(user_id).await {
                                            let mut map: HashMap<String, Option<String>> = HashMap::new();

                                            match key_name.as_str() {
                                                "displayname" => {
                                                    map.insert("displayname".to_string(), user.displayname);
                                                }
                                                "avatar_url" => {
                                                    map.insert("avatar_url".to_string(), user.avatar_url);
                                                }
                                                "m.tz" => {
                                                    map.insert("m.tz".to_string(), Some("Asia/Dhaka".to_string()));
                                                }
                                                _ => {
                                                    return (
                                                        StatusCode::NOT_FOUND,
                                                        Json(MatrixError {
                                                            errcode: ErrCode::MNotFound,
                                                            error: Some("Profile not found".to_string()),
                                                        }),
                                                    ).into_response();
                                                }
                                            }
                                            return (StatusCode::OK, Json(map)).into_response();
                                        }

                                        (
                                            StatusCode::NOT_FOUND,
                                            Json(MatrixError {
                                                errcode: ErrCode::MNotFound,
                                                error: Some("Profile not found".to_string()),
                                            }),
                                        ).into_response()
                                    }).put(|Path((user_id, key_name)): Path<(String, String)>, State(matrix): State<Arc<MatrixClient>>| async move {
                                        matrix.update_profile(user_id, UpdateUser { displayname: (), avatar_url: () });
                                        "{}"
                                    }),
                                ).with_state(Arc::new(matrix)),
                        )
                        .route(
                            "/versions",
                            get(|| async {
                                Json(MVersions {
                                    unstable_features: HashMap::new(),
                                    versions: ["v1.1"],
                                })
                            }),
                        ),
                )
                .nest(
                    "/key",
                    Router::new()
                        .nest(
                            "/v2",
                            Router::new()
                                .route(
                                    "/server",
                                    get(|| async { "" }).fallback(unrecognized_method),
                                )
                                .route(
                                    "/query",
                                    post(|| async { "" }).fallback(unrecognized_method),
                                )
                                .route(
                                    "/query/{serverName}",
                                    get(|| async { "" }).fallback(unrecognized_method),
                                ),
                        )
                        .fallback(unrecognized_endpoint),
                )
                .fallback(unrecognized_endpoint),
        )
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            Arc::new(Mutex::new(monitor)),
            logger,
        ));

    let hostname = env::var("HOST").unwrap_or("127.0.0.1".to_string());
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(3000);
    let address = format!("{hostname}:{port}");

    let listener = tokio::net::TcpListener::bind(&address).await?;
    println!("Listening to {address}...");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "404 Not Found")
}
async fn unrecognized_endpoint() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(MatrixError {
            errcode: ErrCode::MUnrecognized,
            error: Some("Unrecognized request".to_string()),
        }),
    )
}
async fn unrecognized_method() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(MatrixError {
            errcode: ErrCode::MUnrecognized,
            error: Some("Unrecognized request".to_string()),
        }),
    )
}

async fn logger(State(mutex): State<Arc<Mutex<Monitor>>>, req: Request, next: Next) -> Response {
    let mut monitor = mutex.lock().await;
    let preq = parse_req(&req);

    let mut res = next.run(req).await;
    let pres = parse_res(&res);

    let headers = res.headers_mut();
    headers.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    headers.insert(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, DELETE, OPTIONS".parse().unwrap(),
    );
    headers.insert(
        "Access-Control-Allow-Headers",
        "X-Requested-With, Content-Type, Authorization"
            .parse()
            .unwrap(),
    );

    let ctx = monitor.log(preq, pres);
    println!("{}", prettify(ctx));

    res
}

pub struct RequestInit {
    pub method: String,
    pub path: String,
    pub user_agent: String,
    pub ip: String,
    pub created: DateTime<Utc>,
}
pub struct ResponseInit {
    pub status: u16,
    pub created: DateTime<Utc>,
}
pub struct ContextInit {
    pub id: u32,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub user_agent: String,
    pub ip: String,
    pub created: DateTime<Utc>,
}

#[derive(Clone)]
pub struct Monitor {
    pub store: u32,
}
impl Monitor {
    pub fn new() -> Monitor {
        Monitor { store: 0 }
    }
    pub fn log(&mut self, req: RequestInit, res: ResponseInit) -> ContextInit {
        let id = self.store;
        self.store += 1;

        ContextInit {
            id: id,
            method: req.method,
            path: req.path,
            status: res.status,
            user_agent: req.user_agent,
            ip: req.ip,
            created: Utc::now(),
        }
    }
}

fn parse_req(req: &Request) -> RequestInit {
    let connect_info = req.extensions().get::<ConnectInfo<SocketAddr>>();

    let headers = req.headers();
    let agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("None")
        .to_string();

    RequestInit {
        method: req.method().to_string(),
        path: req.uri().path().to_string(),
        user_agent: agent,
        ip: get_ip(req.headers(), connect_info),
        created: Utc::now(),
    }
}
fn parse_res(res: &Response) -> ResponseInit {
    let status = res.status();

    ResponseInit {
        status: status.as_u16(),
        created: Utc::now(),
    }
}

fn prettify(ctx: ContextInit) -> String {
    let status_text = ctx.status.to_string();
    let date = ctx.created.to_string();

    format!(
        "{} {} {} {} {} {} {}",
        format!("{:02}", ctx.id).dimmed(),
        &date[0..19].dimmed(),
        match ctx.method.as_str() {
            "GET" => ctx.method.green(),
            "POST" => ctx.method.blue(),
            "DELETE" => ctx.method.red(),
            _ => ctx.method.yellow(),
        },
        ctx.path.dimmed(),
        match ctx.status {
            200..=299 => status_text.green(),
            300..=399 => status_text.blue(),
            400..=499 => status_text.yellow(),
            500..=599 => status_text.red(),
            _ => status_text.dimmed(),
        },
        ctx.ip.red(),
        ctx.user_agent.dimmed(),
    )
}

fn get_ip(headers: &HeaderMap, connect_info: Option<&ConnectInfo<SocketAddr>>) -> String {
    let header_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string());
    if let Some(ip) = header_ip {
        return ip;
    }
    if let Some(ConnectInfo(addr)) = connect_info {
        return addr.ip().to_string();
    }
    "127.0.0.1".to_string()
}
