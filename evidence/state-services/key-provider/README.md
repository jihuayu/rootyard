# Local KeyProvider component evidence

`report.json`, `build.json` and `contract.log` qualify the nine local contract tests from clean d02a24e. The integration test source has its own before/after SHA in the receipt; the root package and selected test were rebuilt. The recorded `cargo rustc --profile test --test key_provider_contract` command builds the selected executable without unrelated application binaries. No provider service is used.

Clippy with all targets and `pando-lab,blob-azblob` passed at b9c1fd3; d02a24e changes only the failed AAD test fixture. Final lint confirmation follows separately. Earlier selected builds v1/v2 exhausted local disk and did not qualify a binary. The archived v3 test log preserves an actual 8-pass/1-fail run: its naive collision fixture had different lengths. d02a24e constructs an actual collision in unframed fields and forges matching public AAD metadata to ensure AEAD authentication itself rejects replay.

This is a KeyProvider component increment for #109/#105. It does not wire serving or migrate legacy Vault envelopes; persistent rewrap/reference changes, all-content Blob publication, recovery/backup and standalone deployment remain unimplemented. The independent module does not enable deletion.
