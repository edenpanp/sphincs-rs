# Demo

Run the interactive demo from the repository root:

```sh
cargo run --release --example demo
```

Suggested live-demo choices:

- Enter any short message, or press Enter for the default message.
- Select `1` for the faster `RawSha256` demo backend.
- Select `y` for the experimental group-extension section.

The demo prints the project motivation, SPHINCS+ parameters, key/sign/verify
timings, signature size, tamper-rejection checks, raw-byte verification, and
experimental group verification plus manager identification.

This is intended to satisfy the report-demo requirement rather than only show a
happy-path API call. It demonstrates:

- Motivation: why a stateless hash-based post-quantum signature is relevant.
- Correctness: valid signatures verify under the matching public key.
- Security behaviour: modified messages and modified signatures are rejected.
- Engineering result: the optimised signing path is used and timed.
- Concrete output: key sizes, signature size, parameters, and runtime are
  printed for the marker.
- Extension scope: the group section is explicitly labelled experimental and
  shows public verification plus manager-side identification without claiming
  full DGSP support.
