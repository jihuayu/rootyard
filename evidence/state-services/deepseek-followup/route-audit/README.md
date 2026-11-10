# Service-aware route audit

Source commit: `40c3d25532aefeb986d453d35a4a4de206f30737`. GitHub CI on 8118163 failed 12 reference cases because
the static scanner compared `serve-blob` and legacy `serve` routes as one
router. The source audit now assigns the standalone gateway its actual separate
service scope. Unknown paths remain in the legacy scope. Within each scope,
duplicate method/path registrations fail, including duplicates in one file.
Production routes and Rust inputs are unchanged.

Root ran six route governance tests and all 591 explicitly labelled reference
model tests: all passed, zero reference skips. The reference models are not
native service acceptance. Existing native qualification remains the separate
25-case evidence in the parent directory.

DeepSeek implemented the initial correction. Root rejected an incorrect parser
approach, simplified the service composition rule, and fixed its regression
case before running the recorded gates. A separate DeepSeek source review
checks the final scoped audit; review is distinct from test execution.
