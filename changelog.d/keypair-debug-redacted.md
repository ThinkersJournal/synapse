Fixed: KeyPair's Debug no longer prints the private key (CodeRipper SEC-012)

`synapse::auth::utils::KeyPair` derived `Debug`, so `{:?}` of a key pair, or of a struct holding one, wrote the private key bytes to a log. `Debug` is now written by hand and shows `<redacted>` for `private_key`. Test: `debug_never_prints_the_private_key`.

Also records the one deliberate `SEC-004` finding (the QUIC client's accept-any-certificate verifier, private to `src/transport/quic_tls.rs`) as a reasoned `[[allow]]` in `.coderipper.toml`. The reason, the QUIC design spec (§3 addendum) and a new ROADMAP row 51 say what the verifier does not protect (wire confidentiality and traffic analysis against an on-path attacker), that QUIC binds loopback by default, and that any `all_interfaces` use must first replace the verifier.
