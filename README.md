# halo2-zk-email

**Email verification circuit in halo2.**

## Disclaimer

DO NOT USE THIS LIBRARY IN PRODUCTION. At this point, this is under development not audited. It has known and unknown bugs and security flaws.

## Features

`halo2-zk-email` provides a library and a command-line interface for an email verification circuit compatible with the [halo2 library developed by privacy-scaling-explorations team](https://github.com/privacy-scaling-explorations/halo2).

## Requirement

- rustc 1.68.0-nightly (0468a00ae 2022-12-17)
- cargo 1.68.0-nightly (cc0a32087 2022-12-14)

## Installation and Build

You can install and build our library with the following commands.

```bash
git clone https://github.com/zkemail/halo2-zk-email.git
cd halo2-zk-email
cargo build --release
```

## Usage

You can open the API specification by executing `cargo doc --open`.

## Test

You can run the tests by executing `cargo test --release`.

## CLI

You can install CLI `zkemail` to prove and verify emails as follows:
`cargo install --path .`

To generate a proof and verify it, do:

Place demo.eml into build folder.

```bash
cargo build --release
zkemail gen-params --k 18
zkemail gen-keys
zkemail prove
zkemail verify
```

To generate regex files for a new decomposed regex definition. do:

```bash
zkemail gen-regex-files --decomposed-regex-config-path new_regex_file.json --regex-files-prefix new_regex
```