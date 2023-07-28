use axum::{extract::Path, http::StatusCode, routing::post, Extension, Json, Router};
use ssh_key::{PublicKey, SshSig};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

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
        .layer(Extension(Arc::new(RwLock::new(users))));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    tracing::debug!("listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[axum::debug_handler]
async fn register(
    users: Extension<Arc<RwLock<HashMap<String, Option<PublicKey>>>>>,
    Path(uid): Path<String>,
    Json(public_key): Json<PublicKey>,
) -> StatusCode {
    match public_key.algorithm() {
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
    }
}

#[axum::debug_handler]
async fn login(
    users: Extension<Arc<RwLock<HashMap<String, Option<PublicKey>>>>>,
    Path(uid): Path<String>,
    Json(sig): Json<String>,
) -> StatusCode {
    match SshSig::from_pem(sig.as_bytes()) {
        Ok(sig) => match sig.algorithm() {
            ssh_key::Algorithm::Ed25519 => match users.read().unwrap().get(&uid) {
                Some(saved_key) => match saved_key {
                    Some(saved_key) => {
                        if sig.public_key() == saved_key.key_data() {
                            StatusCode::OK
                        } else {
                            StatusCode::IM_A_TEAPOT
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
