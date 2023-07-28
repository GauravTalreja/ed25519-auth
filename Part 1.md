# Part 1

## Q1

The `ugster` system's registration consists of sending the `uid` and the public key. Hence, `A` is the identity function. `B` is a SSH signature blob generated as described [in the protocol](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.sshsig?annotate=HEAD). `C` is the result of a verification function which checks whether the signature was signed by public key saved during registration. The `ugster` system seems to allow signatures of timestamps about 4-5 seconds prior to the time the request was received.

## Q2

If the private key of the user is not compromised, all signatures of timestamps are valid until they are intercepted. The `ugster` system seems to allow signatures of timestamps about 4-5 seconds prior to the time the request was received. This makes it resilient to MITM attacks outside this window. A motivated attacker can send the same signature within 4-5 seconds of when the user with the private key makes a request, and this would allow them to be authenticated, however the window for this is very small. 