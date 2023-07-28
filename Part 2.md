# Part 2

We hardcode the allowed users:

```rust
let users = HashMap::from([
    ("test1".to_owned(), Option::<PublicKey>::None),
    ("test2".to_owned(), None),
    ("test3".to_owned(), None),
    ("test4".to_owned(), None),
    ("test5".to_owned(), None),
]);
```

## Register

The function performs the following checks:

1. The request body has a valid OpenSSH key.
2. The key is of type `ed25519`.
3. The `uid` is valid.
4. The `uid` has not registered before.

If any of these fail, it returns status code [418](https://datatracker.ietf.org/doc/html/rfc2324).

```rust
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
```

# Part 2 & 3

## Login

The function initially performs the following checks:

1. The request body has a valid OpenSSH signature.
2. The signature is of type `ed25519`.
3. The `uid` is valid.
4. The `uid` has registered before.

```rust
let timestamp = Utc::now().timestamp();
tokio::time::sleep(tokio::time::Duration::from_secs(LOGIN_DELAY)).await;

match SshSig::from_pem(body) {
    Ok(sig) => match sig.algorithm() {
        ssh_key::Algorithm::Ed25519 => match users.read().unwrap().get(&uid) {
            Some(saved_key) => match saved_key {
                Some(saved_key) => {
                   ...
                }
                None => StatusCode::IM_A_TEAPOT,
            },
            None => StatusCode::IM_A_TEAPOT,
        },
        _ => StatusCode::IM_A_TEAPOT,
    },
    Err(_) => StatusCode::IM_A_TEAPOT,
}
```

Notice that we recorded the timestamp of the request and slept for some duration. 

```rust
const LOGIN_DELAY: u64 = 2;
```

We now check if the signature was generated for any timestamps in the allowed range.

```rust
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
```

Since we slept, it has been at least two seconds since the timestamp by the time we respond. Hence, a man in the middle attack is only possible if the attacker sent the same signature within two seconds of the initial request. However, all attackers receive requests and recorded responses returned by ``peek``, so by the time the attacker can first know of a request's outcome, all vulnerable timestamps have expired and even if the same signature is used, it cannot be used to authenticate the user. Hence, man in the middle attacks should not be possible by any classmates.

## Note

If the server was not running at the time of the deadline, something might have gone wrong. It should be running according to the following log:

```shell
vagrant@ubuntu-jammy ~/ed25519-auth (main)> exit
There are still jobs active:

   PID  Command
 12116  cargo run --release &

A second attempt to exit will terminate them.
Use 'disown PID' to remove jobs from the list without terminating them.
vagrant@ubuntu-jammy ~/ed25519-auth (main)> disown 12116
vagrant@ubuntu-jammy ~/ed25519-auth (main)> exit
Connection to ugster71c.student.cs.uwaterloo.ca closed.
```

My private key is included, and running the server in a fresh state should be as simple as:

```shell
cd ed25519-auth
cargo run --release
```

All the code is also in that directory and in the dropbox.