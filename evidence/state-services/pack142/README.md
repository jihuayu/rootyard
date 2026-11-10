# A4a verified pack registration and atomic publication

Actual source-bound PostgreSQL17 + Garage S3 + native Git qualification for PR138 / issues105 and107. One protected A3 pack+idx publication is registered durably, verified from actual provider bytes, then committed atomically with refs/HEAD/membership/mode/terminal/event.

All recorded passing runs are checked by the collector. The history directory preserves initial native, library and backup fixture failures. Git reverse-index generation was reproduced independently and explicitly disabled in the isolated verifier; strict pack-directory validation remains intact. See checks.json for scope and limitations. No issue is closed by this unmerged draft.
