# CI trigger de-duplication (2026-11-10)

Baseline commit: `8b5a5e36f` (`main`, "test(ci): guard apt acquisition and source ownership (#190)").
Scope: workflow triggers of `CI`, `Pando synthetic lab` and `Redis contract`; a documentation-only
layering policy. No job steps, check names or required semantics are changed here.

## Before: facts read from GitHub (read-only)

Read with read-only `gh api` calls on 2026-11-10.

| Item | Observed state |
| --- | --- |
| `repos/jihuayu/rootyard/branches/main/protection` | HTTP 404 "Branch not protected" |
| `repos/jihuayu/rootyard/rulesets` | `[]` (no rulesets, no required status checks configured) |
| `repos/jihuayu/rootyard/rules/branches/main` | `[]` |
| Default branch | `main` |
| Non-`codex/*` branches | `main`, `feat/pando-storage-cluster`, `feat/sha256-forge-ci`, `feat/tier1-to-tier4` only |
| Release / maintenance branches (`^release`, `^v[0-9]`) | none |
| Tags | none |
| Registered workflows | `ci.yml` (CI), `pando-lab.yml` (Pando synthetic lab), `redis-contract.yml` (Redis contract), `refstore-protocol-acceptance.yml`, `refcas-log.yml`, `native-kernel-acceptance.yml` (dispatch only), `candidate-release-acceptance.yml` (dispatch only) |

Note: the repository has no branch-protection setting, so the "required checks" are the
check-run names the repository treats as gates by convention: `verify` (`ci.yml`),
`container` (`ci.yml`), `isolated-lab` (`pando-lab.yml`), `redis-contract`
(`redis-contract.yml`), plus the path-filtered `native` / `log-storage` suites. This change keeps
all of those names and their trigger coverage; it does not and cannot edit protection settings.

### Trigger declarations at the baseline

```yaml
# ci.yml, pando-lab.yml, redis-contract.yml (identical)
on:
  push:
  pull_request:
```

Both `push` and `pull_request` are unfiltered, so every branch/tag push runs the full set and a
pull request opened from the same head SHA runs it again.

### Duplicate runs observed (same head SHA, 2026-11-10)

| Head SHA | Branch | `push` runs | `pull_request` runs | Duplicates |
| --- | --- | --- | --- | --- |
| `268e8b0ff` | `codex/msrv-floor-75` (PR #191) | `42783486160` CI, `42783486373` Redis, `42783486170` Pando | `42783651096` CI, `42783650768` Redis, `42783650771` Pando | 3 |
| `43eb416bb` | `codex/webhook-lossless-page1-70` (PR #192) | `42786608153` CI, `42786608255` Redis, `42786607977` Pando | `42786835185` CI, `42786835555` Redis, `42786835130` Pando | 3 |
| `fe91538ab` | `codex/ci-apt-regressions-20261110` (PR #190) | `42770086194` CI, `42770086135` Redis, `42770086426` Pando | `42770131652` CI, `42770131641` Redis, `42770131742` Pando | 3 |
| `4e0f80071` | `codex/rubicon-all-pr-merge` | `42766863555` CI, `42766863857` Redis, `42766863591` Pando | `42766869814` CI, `42766870151` Redis, `42766869931` Pando | 3 |
| `b22f30925` | `codex/rubicon-all-pr-merge` | 3 | 3 (+ RefStore, Ref-CAS) | 3 |

So every PR head produced 6 runs of the same three workflows instead of 3. The PR #191 and
PR #192 pull_request runs (`42783651096`, `42786835185`, `42783650768`, `42786835555`) were
still in progress when this change was prepared; they are left to finish and are not cancelled.

## Change (checkpoint 1: `ci.yml`; checkpoint 2: `pando-lab.yml`, `redis-contract.yml`)

The trigger block is now identical in `ci.yml`, `pando-lab.yml` and `redis-contract.yml`:

```yaml
on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:  # pando-lab.yml, redis-contract.yml only
```

* `pull_request` stays the single full-gate event for every PR head (the `verify` and `container`
  checks on the PR are unchanged).
* `push` now runs only for `main`, which keeps the post-merge full gate on the default branch.
  After a merge the PR head and the `main` push are different commits (a merge commit, or a
  new parent for a squash/rebase), so the `push` run is a real verification of the merged tree
  and not a duplicate of the PR run.
* Ordinary `codex/*` / `feat/*` feature branches get no separate `push` copy; their gate is the PR.
* No `paths:` filter is added, so a required check can never be left permanently pending.
* Tags and `workflow_dispatch` were not used by `ci.yml` at the baseline, so no meaning is lost.

## After: expected event matrix (not yet observed)

| Event | Head | `CI` (`verify`, `container`) | Pando (`isolated-lab`) | Redis (`redis-contract`) |
| --- | --- | --- | --- | --- |
| push (open/update PR) | `codex/*`, `feat/*` | none | none | none |
| pull_request | any PR head | 1 | 1 | 1 |
| push | `main` merge | 1 | 1 | 1 |
| push | tag | none (was: full gate on any tag) | none | none |
| workflow_dispatch | any | (not offered, as before) | 1 (new, manual specialised run) | 1 (new, manual specialised run) |

Per PR head this removes 3 duplicate runs (one per workflow), from 6 to 3 in the observed
2026-11-10 pattern. Nothing is *required less*: each PR still gets each check once, and each
merge to `main` still gets each check once on the merged commit. `workflow_dispatch` was added
to the two suites that had no other manual entry point (the other three workflows already had
it); it is additive and changes no existing event's meaning. Tags previously ran the full gate;
no tag exists in the repository and the project is unpublished, so no tag gate is lost in
practice — if release tags are adopted, add an explicit `tags:` trigger deliberately.

The reduction above is a *prediction*. No saving is claimed until Root pushes a feature branch,
opens a PR and the actual event counts are read from `actions/runs`.

## Layering policy while layered suites exist

See "专项与完整 candidate 分层" in `docs/ci-acceptance.md`: during development the affected
specialised workflows are dispatched manually on the branch, and the complete gate is the full
`pull_request` run plus the post-merge `main` push run. No new suite input or orchestrator was
added; `workflow_dispatch` is available on every workflow except `ci.yml`, which never offered
it, and it was added to the two suites that gained it here.

## Enforcement and limits

`tests/test_ci_workflow_triggers.py` pins the trigger contract (PR event plus `main`-only push,
no `paths`/`paths-ignore` on either event, dispatch preserved, unchanged job ids). It uses the
standard library only, because the repository declares no PyYAML dependency and the CI Python
environment installs none; it reads the block-style `on:`/`jobs:` keys by indentation. It is
not a YAML parser and does not validate the whole file: full YAML validity comes from GitHub
parsing the pushed workflow, and the event counts above stay *expected* until a real push and
PR are observed by Root.
