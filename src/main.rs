use axum::{extract::Path, http::StatusCode, routing::post, Extension, Json, Router};
use serde::Deserialize;
use ssh_key::{PublicKey, Signature, SshSig};
use std::{
    collections::{BTreeSet, HashMap},
    net::SocketAddr,
    sync::{Arc, RwLock},
};

#[tokio::main]
async fn main() {
    let users = HashMap::from([
        ("test1".to_owned(), Option::<PublicKey>::None),
        ("test2".to_owned(), None),
        ("test3".to_owned(), None),
        ("test4".to_owned(), None),
        ("test5".to_owned(), None),
    ]);

    let signatures = HashMap::from([
        ("test1".to_owned(), BTreeSet::<Signature>::new()),
        ("test2".to_owned(), BTreeSet::<Signature>::new()),
        ("test3".to_owned(), BTreeSet::<Signature>::new()),
        ("test4".to_owned(), BTreeSet::<Signature>::new()),
        ("test5".to_owned(), BTreeSet::<Signature>::new()),
    ]);

    let app = Router::new()
        .route("/register/:uid", post(register))
        .route("/login/:uid", post(login))
        .route("/attack", post(login))
        .layer(Extension(Arc::new(RwLock::new(users))))
        .layer(Extension(Arc::new(RwLock::new(signatures))));

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
    signatures: Extension<Arc<RwLock<HashMap<String, BTreeSet<Signature>>>>>,
    Path(uid): Path<String>,
    body: String,
) -> StatusCode {
    match SshSig::from_pem(body) {
        Ok(sig) => match sig.algorithm() {
            ssh_key::Algorithm::Ed25519 => match users.read().unwrap().get(&uid) {
                Some(saved_key) => match saved_key {
                    Some(saved_key) => {
                        if sig.public_key() == saved_key.key_data() {
                            if !signatures
                                .read()
                                .unwrap()
                                .get(&uid)
                                .unwrap()
                                .contains(sig.signature())
                            {
                                signatures
                                    .write()
                                    .unwrap()
                                    .get_mut(&uid)
                                    .unwrap()
                                    .insert(sig.signature().clone());
                                StatusCode::OK
                            } else {
                                StatusCode::IM_A_TEAPOT
                            }
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

#[axum::debug_handler]
async fn attack(body: Json<Vec<PeekRaw>>) -> StatusCode {
    todo!()
}

#[derive(Deserialize)]
struct PeekRaw {
    pub args: Vec<String>,
    pub data: String,
    pub status: u16,
    pub message: String,
}

struct PeekRegister {
    pub uid: String,
    pub public_key: PublicKey,
}

struct PeekLogin {
    pub uid: String,
    pub sig: SshSig,
}

impl TryInto<PeekLogin> for PeekRaw {
    fn try_into(self) -> Result<PeekLogin, Self::Error> {
        if self.status == 200 {
            if let Some(arg) = self.args.get(0) {
                if arg == "login" {
                    if let Ok(sig) = SshSig::from_pem(self.data) {
                        return Ok(PeekLogin {
                            uid: self.args[1].clone(),
                            sig,
                        });
                    }
                }
            }
        }
        Err(())
    }

    type Error = ();
}

impl TryInto<PeekRegister> for PeekRaw {
    fn try_into(self) -> Result<PeekRegister, Self::Error> {
        if self.status == 200 {
            if let Some(arg) = self.args.get(0) {
                if arg == "register" {
                    if let Ok(public_key) = PublicKey::from_openssh(&self.data) {
                        return Ok(PeekRegister {
                            uid: self.args[1].clone(),
                            public_key,
                        });
                    }
                }
            }
        }
        Err(())
    }

    type Error = ();
}
