# Tasks: PKI Self-Signed CA

**Input**: Design documents from `/specs/001-pki-self-signed-ca/`  
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/

**Tests**: Included — the spec explicitly calls for integration tests and no regressions.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Ensure the development environment is ready and understand the existing codebase.

- [ ] T001 [P] Run `tox` in `vault-package/` to verify baseline tests pass
- [ ] T002 [P] Run `tox` in `k8s/` to verify baseline tests pass
- [ ] T003 [P] Run `tox` in `machine/` to verify baseline tests pass
- [ ] T004 Review existing PKI integration test in `k8s/tests/integration/test_pki.py` to understand current test patterns

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

### VaultClient — Self-Signed CA Generation

- [ ] T005 Add `generate_self_signed_ca()` method to `vault-package/vault/vault_client.py`
- [ ] T006 Add unit tests for `generate_self_signed_ca()` in `vault-package/tests/unit/test_vault_client.py`
- [ ] T007 Add mock for `generate_self_signed_ca()` to `vault-package/vault/testing/mocks.py`

### PKIManager — Self-Signed Mode Refactoring

- [ ] T008 [P] Add `self_signed_ca: bool = False` parameter to `PKIManager.__init__()` in `vault-package/vault/vault_managers.py`
- [ ] T009 [P] Add `SELF_SIGNED_CA_SECRET_LABEL` constant to `vault-package/vault/vault_managers.py`
- [ ] T010 Add `_generate_self_signed_ca()` method to `PKIManager` in `vault-package/vault/vault_managers.py`
- [ ] T011 Add `_configure_self_signed_ca()` method to `PKIManager` in `vault-package/vault/vault_managers.py`
- [ ] T012 Refactor `PKIManager.configure()` to branch between self-signed and external CA modes in `vault-package/vault/vault_managers.py`
- [ ] T013 Refactor `PKIManager.sync()` to skip relation check in self-signed mode in `vault-package/vault/vault_managers.py`
- [ ] T014 Refactor `PKIManager._generate_pki_certificate_for_requirer()` to get CA from secret in self-signed mode in `vault-package/vault/vault_managers.py`

**Checkpoint**: Foundation ready — `VaultClient` can generate self-signed CAs and `PKIManager` supports self-signed mode. Unit tests in `vault-package/` pass.

---

## Phase 3: User Story 1 — Enable PKI without external CA (Priority: P1) 🎯 MVP

**Goal**: When `pki_ca_common_name` is set and no `tls-certificates-pki` relation exists, the charm generates a self-signed CA and uses it to issue certificates.

**Independent Test**: Configure `pki_ca_common_name` on Vault with `vault-pki` relation but no `tls-certificates-pki` relation. Certificates should be issued to requirers.

### Tests for User Story 1

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [ ] T015 [P] [US1] Add unit test: `PKIManager.configure()` in self-signed mode generates CA when no secret exists in `k8s/tests/unit/lib/test_vault_managers.py`
- [ ] T016 [P] [US1] Add unit test: `PKIManager.configure()` in self-signed mode reuses existing CA when config unchanged in `k8s/tests/unit/lib/test_vault_managers.py`
- [ ] T017 [P] [US1] Add unit test: `PKIManager.configure()` in self-signed mode regenerates CA when config changed in `k8s/tests/unit/lib/test_vault_managers.py`
- [ ] T018 [P] [US1] Add unit test: `PKIManager.sync()` in self-signed mode issues certificates without relation in `k8s/tests/unit/lib/test_vault_managers.py`
- [ ] T019 [P] [US1] Add unit test: charm collect_status does NOT block when `vault-pki` exists but `tls-certificates-pki` does not and `pki_ca_common_name` is valid in `k8s/tests/unit/test_charm_collect_status.py`
- [ ] T020 [P] [US1] Add unit test: charm `_configure_pki_secrets_engine()` creates `PKIManager` with `self_signed_ca=True` when no external relation in `k8s/tests/unit/test_charm_configure.py`

### Implementation for User Story 1

- [ ] T021 [US1] Update `k8s/src/charm.py` `_on_collect_status()` to not block for missing `tls-certificates-pki` when `pki_ca_common_name` is valid
- [ ] T022 [US1] Update `k8s/src/charm.py` `_configure_pki_secrets_engine()` to detect self-signed mode and pass `self_signed_ca=True` to `PKIManager`
- [ ] T023 [US1] Update `k8s/src/charm.py` `_sync_vault_pki()` to detect self-signed mode and pass `self_signed_ca=True` to `PKIManager`
- [ ] T024 [US1] Update `machine/src/charm.py` with the same status and PKIManager changes as `k8s/src/charm.py`
- [ ] T025 [US1] Run `make vendor-shared-code` in `k8s/` to sync `vault-package/` changes
- [ ] T026 [US1] Run `make vendor-shared-code` in `machine/` to sync `vault-package/` changes
- [ ] T027 [US1] Run `tox` in `vault-package/` to verify all unit tests pass
- [ ] T028 [US1] Run `tox` in `k8s/` to verify all unit tests pass
- [ ] T029 [US1] Run `tox` in `machine/` to verify all unit tests pass

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently. The charm can issue certificates via self-signed CA.

---

## Phase 4: User Story 2 — Hybrid mode with external CA (Priority: P2)

**Goal**: When both external CA relation and `pki_ca_common_name` are present, external CA takes precedence. When external CA relation is removed, charm transitions to self-signed mode.

**Independent Test**: Relate Vault to external CA via `tls-certificates-pki`, verify intermediate CA from external provider is used. Remove relation, verify self-signed CA is generated.

### Tests for User Story 2

- [ ] T030 [P] [US2] Add unit test: `PKIManager.configure()` uses external CA when `self_signed_ca=False` in `k8s/tests/unit/lib/test_vault_managers.py`
- [ ] T031 [P] [US2] Add unit test: charm does not activate self-signed mode when `tls-certificates-pki` relation exists in `k8s/tests/unit/test_charm_configure.py`
- [ ] T032 [P] [US2] Add unit test: charm transitions to self-signed mode after external CA relation is removed in `k8s/tests/unit/test_charm_configure.py`

### Implementation for User Story 2

- [ ] T033 [US2] Verify `PKIManager` external CA path is unchanged and still functional (no code changes needed if Phase 2 was done correctly)
- [ ] T034 [US2] Update `machine/src/charm.py` with the same hybrid mode behavior as `k8s/src/charm.py`
- [ ] T035 [US2] Run `tox` in `k8s/` to verify no regressions in external CA mode
- [ ] T036 [US2] Run `tox` in `machine/` to verify no regressions in external CA mode

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently. External CA mode is unchanged; self-signed mode works when no external CA is present.

---

## Phase 5: User Story 3 — CA certificate lifecycle and rotation (Priority: P3)

**Goal**: CA rotation works when `pki_ca_common_name` changes. New CA is imported as new issuer, set as default.

**Independent Test**: Change `pki_ca_common_name`, verify new CA is generated and becomes the default issuer. Old issuer remains but is no longer used.

### Tests for User Story 3

- [ ] T037 [P] [US3] Add unit test: `PKIManager._generate_self_signed_ca()` creates new CA when common_name changes in `k8s/tests/unit/lib/test_vault_managers.py`
- [ ] T038 [P] [US3] Add unit test: `PKIManager.configure()` imports new CA as new issuer and makes it default in `k8s/tests/unit/lib/test_vault_managers.py`
- [ ] T039 [P] [US3] Add unit test: old issuer is not deleted after rotation in `k8s/tests/unit/lib/test_vault_managers.py`

### Implementation for User Story 3

- [ ] T040 [US3] Verify `PKIManager._generate_self_signed_ca()` compares stored CA attributes with current config to detect changes
- [ ] T041 [US3] Verify `PKIManager.configure()` calls `make_latest_pki_issuer_default()` after importing new CA
- [ ] T042 [US3] Run `tox` in `k8s/` to verify rotation tests pass
- [ ] T043 [US3] Run `tox` in `machine/` to verify rotation tests pass

**Checkpoint**: All user stories should now be independently functional. CA rotation works correctly.

---

## Phase 6: Integration Tests & Cross-Cutting Concerns

**Purpose**: End-to-end validation and ensuring both charms are in sync.

### Integration Tests

- [ ] T044 [P] Add integration test for self-signed CA mode in `k8s/tests/integration/test_pki.py`
  - Deploy Vault without external CA charm
  - Set `pki_ca_common_name`
  - Relate `vault-pki` requirer
  - Assert certificate is issued and valid
- [ ] T045 [P] Add integration test for hybrid mode transition in `k8s/tests/integration/test_pki.py`
  - Start with external CA, verify it works
  - Remove external CA relation
  - Verify charm transitions to self-signed mode
  - Assert new certificates are issued

### Cross-Cutting Concerns

- [ ] T046 [P] Verify `k8s/.vendored/vault-package/` and `machine/.vendored/vault-package/` are in sync with `vault-package/`
- [ ] T047 [P] Run `tox run -e lint` in `k8s/` and `machine/` to verify no linting errors
- [ ] T048 [P] Run `tox run -e static` in `k8s/` and `machine/` to verify no type errors
- [ ] T049 Update `specs/001-pki-self-signed-ca/quickstart.md` if any operator steps changed during implementation
- [ ] T050 Verify no secrets or private keys are logged anywhere in the changed code

**Checkpoint**: Integration tests pass, both charms are in sync, linting and static analysis pass.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion — BLOCKS all user stories
  - T005–T007 (VaultClient) can run in parallel with T008–T014 (PKIManager)
- **User Stories (Phase 3–5)**: All depend on Foundational phase completion
  - User stories should proceed sequentially in priority order (P1 → P2 → P3)
  - US2 and US3 can be worked on in parallel with US1 if team capacity allows, but US1 is the MVP
- **Integration & Polish (Phase 6)**: Depends on all user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) — No dependencies on other stories
- **User Story 2 (P2)**: Can start after Foundational (Phase 2) — Depends on US1 being complete for confidence, but technically independent
- **User Story 3 (P3)**: Can start after Foundational (Phase 2) — Depends on US1 being complete

### Within Each User Story

- Tests MUST be written and FAIL before implementation
- `vault-package/` changes before charm changes
- `k8s/` changes before `machine/` mirror changes
- Unit tests pass before integration tests

### Parallel Opportunities

- T001–T004 (setup verification) can all run in parallel
- T005–T007 (VaultClient) can run in parallel with T008–T014 (PKIManager refactoring)
- T015–T020 (US1 tests) can all be written in parallel
- T030–T032 (US2 tests) can all be written in parallel
- T037–T039 (US3 tests) can all be written in parallel
- T044–T045 (integration tests) can run in parallel
- T046–T048 (lint/static/vendor sync) can run in parallel

---

## Parallel Example: User Story 1

```bash
# Launch all tests for User Story 1 together:
Task: "T015 Add unit test: PKIManager.configure() in self-signed mode generates CA"
Task: "T016 Add unit test: PKIManager.configure() reuses existing CA"
Task: "T017 Add unit test: PKIManager.configure() regenerates CA when config changed"
Task: "T018 Add unit test: PKIManager.sync() issues certificates without relation"
Task: "T019 Add unit test: charm collect_status does NOT block"
Task: "T020 Add unit test: charm _configure_pki_secrets_engine() creates PKIManager with self_signed_ca=True"

# After tests are written and failing, launch implementation:
Task: "T021 Update k8s/src/charm.py _on_collect_status()"
Task: "T022 Update k8s/src/charm.py _configure_pki_secrets_engine()"
Task: "T023 Update k8s/src/charm.py _sync_vault_pki()"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL — blocks all stories)
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: Test User Story 1 independently
   - `tox run -e unit` in all three directories
   - Verify self-signed CA mode works end-to-end
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test independently → Deploy/Demo (MVP!)
3. Add User Story 2 → Test independently → Verify no regressions in external CA mode
4. Add User Story 3 → Test independently → Verify CA rotation works
5. Add Integration Tests → Verify end-to-end behavior
6. Each story adds value without breaking previous stories

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: User Story 1 (MVP — highest priority)
   - Developer B: User Story 2 (backward compatibility)
   - Developer C: User Story 3 (rotation) + Integration tests
3. Stories complete and integrate independently

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Verify tests fail before implementing
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Avoid: vague tasks, same file conflicts, cross-story dependencies that break independence
- **Critical**: `vault-package/` changes must be vendored to both `k8s/` and `machine/` before merging
