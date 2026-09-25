# cwlt

**Zero-knowledge accounting wallet (holder).**

`cwlt` is the holder in the issuer-verifier-holder schema: it keeps the member's openings and creates proofs for `cblc` and other gates. Any client speaking the protocol is a holder; `cmsg` embeds it, other products embed it in their own client.

Status: name reserved, no implementation yet.

## Boundaries

What it does:

- Keeps openings, creates proofs, and checks counterpart proofs on the member's side.

What it never does:

- Client only: never runs on or trusts the server.
- Openings never leave the member's devices.
- Policies arrive as data (published circuits and keys), never as imported code.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).
