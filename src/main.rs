use axum::{extract::Path, http::StatusCode, routing::post, Extension, Router};
use chrono::Utc;
use ssh_key::{PublicKey, SshSig};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

const LOGIN_DELAY: u64 = 2;
const NAMESPACE: &str = "s3";

#[tokio::main]
async fn main() {
    let users = HashMap::from([
        ("test1".to_owned(), Option::<PublicKey>::None),
        ("test2".to_owned(), None),
        ("test3".to_owned(), None),
        ("test4".to_owned(), None),
        ("test5".to_owned(), None),
    ]);

    let app = Router::new()
        .route("/register/:uid", post(register))
        .route("/login/:uid", post(login))
        .route("/attack", post(login))
        .layer(Extension(Arc::new(RwLock::new(users))));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[axum::debug_handler]
async fn register(
    users: Extension<Arc<RwLock<HashMap<String, Option<PublicKey>>>>>,
    Path(uid): Path<String>,
    body: String,
) -> StatusCode {
    match PublicKey::from_openssh(&body) {
        Ok(public_key) => match public_key.algorithm() {
            ssh_key::Algorithm::Ed25519 => match users.write().unwrap().get_mut(&uid) {
                Some(saved_key) => match saved_key {
                    Some(_) => StatusCode::IM_A_TEAPOT,
                    None => {
                        *saved_key = Some(public_key);
                        StatusCode::OK
                    }
                },
                None => StatusCode::IM_A_TEAPOT,
            },
            _ => StatusCode::IM_A_TEAPOT,
        },
        Err(_) => StatusCode::IM_A_TEAPOT,
    }
}

#[axum::debug_handler]
async fn login(
    users: Extension<Arc<RwLock<HashMap<String, Option<PublicKey>>>>>,
    Path(uid): Path<String>,
    body: String,
) -> StatusCode {
    let timestamp = Utc::now().timestamp();
    tokio::time::sleep(tokio::time::Duration::from_secs(LOGIN_DELAY)).await;
    match SshSig::from_pem(body) {
        Ok(sig) => match sig.algorithm() {
            ssh_key::Algorithm::Ed25519 => match users.read().unwrap().get(&uid) {
                Some(saved_key) => match saved_key {
                    Some(saved_key) => {
                        match (timestamp - (LOGIN_DELAY as i64 - 1)..=timestamp).find_map(
                            |timestamp: i64| {
                                saved_key
                                    .verify(NAMESPACE, timestamp.to_string().as_bytes(), &sig)
                                    .ok()
                            },
                        ) {
                            Some(_) => StatusCode::OK,
                            None => StatusCode::IM_A_TEAPOT,
                        }
                    }
                    None => StatusCode::IM_A_TEAPOT,
                },
                None => StatusCode::IM_A_TEAPOT,
            },
            _ => StatusCode::IM_A_TEAPOT,
        },
        Err(_) => StatusCode::IM_A_TEAPOT,
    }
}
