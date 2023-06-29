# Typed Session Management for Axum

[![Version](https://img.shields.io/crates/v/typed-session-axum.svg?style=flat-square)](https://crates.io/crates/typed-session-axum)
[![Downloads](https://img.shields.io/crates/d/typed-session-axum.svg?style=flat-square)](https://crates.io/crates/typed-session-axum)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square)](https://docs.rs/typed-session-axum)

API documentation: [docs.rs](https://docs.rs/typed-session-axum)

A session manager for [axum]() with focus on **efficiency** and **security**.
Compared to existing art, this crate abstracts over the concrete type used to store session data, allowing to model session states in a **type-safe** way.
Typed-session-axum was designed to live up to the [OWASP® Foundation's](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) session **security** standards, with **efficiency** and **usability** in mind.

## Security

We have designed and implemented the crate with security in mind.
Our design fulfils the requirements stated in [The OWASP® Foundation](https://owasp.org)'s cheat sheet on [session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
We additionally hash the session ids using the fast and secure hash function [blake3](https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE3) before storing them.
To mitigate exploitable bugs we use ``#![forbid(unsafe_code)]`` to ensure everything is implemented in 100% safe Rust.

For further details, refer to the [crate-level documentation](https://docs.rs/typed-session-axum).

So far, this crate has not been reviewed for security.
If you have the necessary skills and wish to contribute to an open source project, please get in touch.

## Contributing

Want to join us? Check out our ["Contributing" guide][contributing] and take a
look at some of these issues:

- [Issues labeled "good first issue"][good-first-issue]
- [Issues labeled "help wanted"][help-wanted]

Any contribution you intentionally submit for inclusion in the work shall be licensed under the [BSD-2-Clause](https://opensource.org/license/bsd-2-clause/) license.

[contributing]: https://github.com/http-rs/typed-session/blob/main/.github/CONTRIBUTING.md
[good-first-issue]: https://github.com/http-rs/typed-session/labels/good%20first%20issue
[help-wanted]: https://github.com/http-rs/typed-session/labels/help%20wanted

## Acknowledgements

This work is based on the crate [axum-sessions](https://crates.io/crate/axum-sessions) by
[Max Countryman](https://github.com/maxcountryman).

## License

This crate is licensed under the [BSD-2-Clause](https://opensource.org/license/bsd-2-clause/) license.
