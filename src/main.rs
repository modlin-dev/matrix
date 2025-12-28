use axum::{
    Json, Router,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use colored::*;
use serde::Serialize;
use std::{env, io, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;
use tokio::time::{Duration, sleep};

#[derive(Serialize)]
struct Server {
    // /_matrix/fedeation/v1/version
    name: &'static str,
    version: &'static str,
}
#[derive(Serialize)]
struct Federation {
    server: Server,
}
#[derive(Serialize)]
struct MFederation {
    // /.well-known/matrix/server
    #[serde(rename = "m.server")]
    m_server: &'static str,
}
#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ErrCode {
    MUnrecognized,
}
#[derive(Serialize)]
struct MatrixError {
    errcode: ErrCode,
    error: String,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let monitor = Monitor::new();

    let app = Router::new()
        .route(
            "/",
            get(|| async {
                sleep(Duration::from_millis(1000)).await;
                "Hello, world!"
            }),
        )
        .route(
            "/.well-known/matrix/server",
            get(|| async {
                Json(MFederation {
                    m_server: "modlin.dev:443",
                })
            }),
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
            error: "Unrecognized request".to_string(),
        }),
    )
}
async fn unrecognized_method() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(MatrixError {
            errcode: ErrCode::MUnrecognized,
            error: "Unrecognized request".to_string(),
        }),
    )
}

async fn logger(State(mutex): State<Arc<Mutex<Monitor>>>, req: Request, next: Next) -> Response {
    let mut monitor = mutex.lock().await;
    let preq = parse_req(&req);

    let res = next.run(req).await;
    let pres = parse_res(&res);

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
