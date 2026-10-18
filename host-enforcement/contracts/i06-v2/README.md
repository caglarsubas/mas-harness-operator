# I06 backend profile v2 — W02g-F, round 3

Status: **CONTRACT_CANDIDATE_ROUND3_AWAITING_INDEPENDENT_REVIEW**. Round 1 (`review-round1.json`, reviewed bytes in
`round1/`) returned CHANGES_REQUIRED with 1 MINOR and 7 NOTE findings and closed N1-N3; "Round-1 findings and
dispositions" answers each. Round 2 (`review-round2.json`, reviewed bytes in `round2/`) returned
PASS_FOR_SOURCE_PUBLICATION with 5 NOTE findings. Round 3 is opened by the author after that pass: the round-2 model
could not be imported as `scripts.i06_backend_profile_v2`, the way the repository's tests import modules, because it
imported its two predecessor models by bare name only. "Round-2 findings and dispositions" lists the round-3 changes. DATA_CHECK_ONLY: no cluster, distribution, host or
kernel is observed, nothing is installed and no distribution is selected. All E01-E12 stay OPEN_UNPROVEN.

This is the successor of the adopted I06 backend profile (`architecture/i06-backend-profile/`, W02g, MET-ENFORCE-006,
main fe50b57). It answers the round-2 findings that W02g carried to W02g-F (`review-round2.json` there): N1 (bind the
evidence record to a backend that W02a accepts), N2 (no RBAC rule of any kind on the loopback user) and N3 (shared or
nested backend cgroups).

## Why a successor

The v1 bytes cannot change:
- `identity-closure.json` is a frozen input of the W02e SELinux matrix, the I07 policy-write contract and the W02a v3
  qualification record;
- the v1 model `scripts/i06_backend_profile.py` is imported by later layers and their tests (`validate_native_profile_v2`,
  `validate_verify_headroom` and the native-profile, I05, SELinux and projection-reuse tests).

So v2 adds this directory and `scripts/i06_backend_profile_v2.py`. v1's writer inventory, identity closure, upstream
facts, upstream bootstrap RBAC and model stay byte-identical. v2 reads them and reuses the v1 checks, adding rules only
in front of or after them.

## Files

| File | Content |
|---|---|
| `criteria.json` | v1's criteria with SC00, SC08 and IC03 restated (`planeon.internal.i06-selection-criteria/v2`) |
| `vectors.json` | evidence and snapshot positives, 7 accepted evidence variants, 5 accepted snapshot variants, 91 evidence negatives (all 71 v1 negatives replayed, plus G01-G20), 38 snapshot negatives (all 35 v1 negatives replayed, plus H01-H03) and 6 cross-version cases |
| `scripts/i06_backend_profile_v2.py` | the reference model: `check_evidence`, `check_rbac_snapshot`; `check_inventory` and `check_closure` are v1's |
| `REVIEW_BRIEF.md` | the brief for the independent review |
| `source-index.json` | digests of the subject and of the predecessor inputs at the base main a29c93c |
| `review-round1.json`, `round1/` | the verbatim round-1 review and the bytes it reviewed |

## What changes

### N1: evidence bound to an accepted W02a v3 record (SC00, SC08)

An evidence record (`planeon.internal.i06-distribution-evidence/v2`) adds one field, `w02aRecord`:
`{"schemaVersion": "planeon.internal.native-qualification/v3", "qualificationDigest": "sha256:<64 lowercase hex>"}`.
The digest is SHA-256 over W02a's canonical JSON form of the record (`native_qualification_v3.canonical`: sorted keys,
no whitespace, UTF-8), spelled exactly as W02a v3's captures spell their `qualificationDigest` (round-1 R1-6). The
record thereby names its backend; v1 only compared `implementationId` with whatever backend the caller passed.

The binding is per W02a record, not per distribution: a W02a record is one boot with one nonce set and one validity
window of at most 900 s, so the evidence is re-issued for each record. `check_record` is W02a's expected-data check,
not its acceptance decision. Combining `check_evidence` with `check_qualification`'s acceptance of the same record is
the caller's composition (W03). Callers of `check_evidence` inherit W02a v3's caller obligations 1 (the profile is
valid under the pinned proxy profile contract) and 4 (`test_fixture=True` only when qualifying a test fixture)
(round-1 R1-5).

`check_evidence(record, inventory, w02a_record, w02a_profile, w02a_endpoints, w02a_schema, test_fixture=False)`
checks, in this order:
1. the closed v2 record, its version and the closed reference with version v3;
2. W02a v3's `check_record` accepts `w02a_record` with its profile, endpoints and schema. Its refusal is reported as
   `SC00 W02a v3 refuses the backend record: <W02a rule>`;
3. the reference's qualification digest equals that of `w02a_record`;
4. the evidence's `testOnly` equals the backend's `backendProfile.testOnly`;
5. a test-only backend is accepted only when `test_fixture` is True. This mirrors W02a v3's `check_qualification`
   (P7(a));
6. v1's `check_evidence` on the v1 projection: the record without `w02aRecord`, under v1's version, against the backend's
   profile, implementationId and componentKeys and its `backendComponents`, with `production = not test_fixture`.

Step 2 brings in every W02a v3 backend rule that v1 never examined. The round-2 type sweep accepted 606 of 1341
substitutions because `cgroupPath`, `apiIdentities` and `filePaths` were not checked. The rules it brings in:
- each component's process label is its W02e slot constant;
- each component has its own domain, cgroup and API identity, and API identities are within the W02g closure entry for
  that component, except that KUBELET may also hold at most one `system:node:<node name>` identity, which the closure
  covers only through Group `system:nodes`, and APISERVER may hold none (round-1 R1-3);
- every backend file is owned and listed in W02a's artifact custody;
- cgroups are outside the planeon slice, never shared and never nested.

W02a v3 puts every backend component in one owner class, `backend`, so it lets components share code: one multi-call
executable for every component, or two backend files with one content digest. v1's SC08 rule, distinct executables with
distinct content (one entry type per confined domain), therefore stays an I06 rule. v2 reaches it through step 6, and
G19 and G20 pin it with backends that W02a v3 accepts (round-1 R1-1).

**No production evidence yet.** W02a v3's schema admits exactly one backend profile: the test-only `unit-distribution`
fixture with its eight components. Every production call (`test_fixture=False`) is therefore refused: at step 2 when
the backend is not the fixture (W02a's schema), and for the fixture backend at step 4 when the evidence claims
`testOnly` false or at step 5 when it claims `testOnly` true (round-2 R2-1). Under W02a v3, v1's production rules in step
6 are unreachable. v2 is also bound to W02a v3 itself: `W02A_VERSION` is fixed, and W02a's `check_record` pins its
schema digest, so a widened schema is refused as an unreviewed v3 schema. Production evidence therefore needs both a
reviewed W02a revision that adds a production backend profile and an I06 successor bound to that revision. The same
holds for any W02a successor, including W02a-F2 (round-1 R1-4). Until then, v2 has no non-fixture accepted variant, and
none can exist. Round 2 asked for non-fixture accepted variants; this is the reason v2 has
none. G09 and G10 pin the refusal of the two v1 accepted variants whose backends W02a never accepted, and X03 and X04
compare them across versions.

### N2: the loopback user holds no resource rule (IC03)

`check_rbac_snapshot` runs v1's check and then refuses any non-empty `effectiveRules` on User `system:apiserver`
(`IC03 the loopback user system:apiserver holds an RBAC rule`). v1 refused only policy-relevant grants on that name.
The v1 snapshot shape is closed over resource rules (`apiGroups`, `resources`, `verbs`, `resourceNames`, `scope`) and
cannot carry a non-resource-URL rule. Observer obligation, carried to W03: an observer that finds a non-resource-URL rule
bound to `system:apiserver` refuses to produce the snapshot instead of dropping the rule (round-1 R1-7).
H01-H03 pin the round-2 probes (configmap and secret reads in kube-system, `nodes/stats`) and a workload grant. B05
accepts the user listed with no rules. The snapshot record format is unchanged (`planeon.internal.i06-rbac-snapshot/v1`):
only the check is stricter.

### N3: shared and nested backend cgroups

These are refused by W02a v3's `check_record` (`backend components share a cgroup`, `backend cgroup nested in another
backend cgroup`), which N1 applies to every evidence check: G07 and G08. A09 accepts a sibling whose name only extends
the kubelet's unit name, so the nesting test is per path component. The P7 carry chain is now closed (round-1 R1-8):
- W02a v2's frozen status assigned P7 to "W02g and W03";
- W02g closed the I06 part of P7(a) and carried the W02a side of P7(a), P7(b), P7(c) and the network-policy agent
  identity to W02a-F (W02g round-2 review Q7 and the v1 README "Still open");
- W02a-F closed them (`architecture/native-profile-v3/status.json` closedFindings.P7 and NETWORK_POLICY_AGENT_IDENTITY).

The v2 status record states this when the contract is adopted.

## Replayed v1 cases

Every v1 evidence and snapshot negative is replayed under v2 with its v1 operations. A v1 `production` flag becomes
`testFixture = not production`. Backend operations apply to the W02a v3 record, and the evidence then names the mutated
record. 61 evidence negatives and all 35 snapshot negatives keep their v1 refusal. Ten evidence negatives now stop at
an earlier rule; `v1Refusal` keeps the old text:

| Vector | v1 refusal | v2 refusal | Why |
|---|---|---|---|
| E06 | SC08 component outside its confined type | W02a v3 schema, `processLabel` const | W02a v3 pins each backend label to its W02e slot constant |
| E35 | SC00 test-only profile cannot qualify production | test-only backend only in a fixture call | step 5 runs before v1's production rule; same outcome |
| E36 | SC00 unit-distribution is a test-only profile | evidence and backend disagree on test-only | step 4 runs first; same outcome |
| E38, E56 | SC08 distinct executables with distinct content | W02a v3 artifact custody | their v1 operations name an unlisted file (E38) or a digest that differs from the listed file's (E56). W02a v3 itself allows shared backend code, so SC08 distinctness stays an I06 rule, pinned by G19 and G20 (round-1 R1-1) |
| E55 | SC08 executable must be canonical | W02a v3 artifact custody | the operation names an unlisted path; W02a's path pattern and canonical-path rule subsume v1's canonical-executable rule |
| E60, E61 | SC00 fixture identity in production; identifier pattern | W02a v3 schema, `implementationId` const | W02a v3 admits only the fixture profile |
| E70, E71 | SC10 API client; SC08 component set | W02a v3 schema, `componentKeys` const | W02a v3 admits only the eight-component fixture |

The v1 accepted variants A01, A03, A04, A06 and A07 are replayed as accepted fixture calls. A02 and A05 moved to the
cross-version cases (X03, X04). Closure and inventory vectors are not replayed: their inputs and checks are v1's,
unchanged, and the v1 layer still replays them.

## Cross-version cases

| Case | v1 model | v2 model |
|---|---|---|
| X01: each version's positive under the other version | refuses (closed record) | refuses (closed record) |
| X02: each version's positive under its own version | accepts | accepts |
| X03: v1 A02, a production profile renamed `selected-distribution` | accepts | refuses: W02a v3 schema |
| X04: v1 A05, a six-component fixture | accepts | refuses: W02a v3 schema |
| X05, X06: the round-2 N2 probes | accept | refuse: IC03 |

No adopted v1 evidence or snapshot exists outside these vectors, so there is nothing to migrate.

## Round-2 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| N1 W02a binding | MINOR | Applied inside `check_evidence` (steps 1-5); the per-record scope and the inherited W02a caller obligations are stated (R1-5); SC00, SC08 restated; G01-G20, A08, A09, X03, X04 |
| N2 loopback user | NOTE | Any rule refused; IC03 restated; H01-H03, B05, X05, X06 |
| N3 nested or shared cgroups | NOTE | Refused through W02a v3's check_record (G07, G08); P7 carry chain recorded above and in the status at adoption |
| N4 sealed file vocabulary | NOTE | Unchanged carry to W02e and W03 |
| N5 kubernetesVersion as reported gitVersion | NOTE | Unchanged carry to W03 |
| N6 workload paths outside kube-system | NOTE | Unchanged carry to W02f and W02e |

## Round-1 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| R1-1 SC08 distinctness unpinned | MINOR | G19 (one multi-call executable for every component) and G20 (two files with one digest), both backends W02a v3 accepts, pinned to v1's SC08 distinctness rule; E38/E56 reason restated; SC08 states that distinctness is an I06 rule |
| R1-2 G18 reason | NOTE | G18's intent restated: a name borrowed from another component's closure entry, refused by the per-component closure enum; W02a's share rule is subsumed (W02a R70) |
| R1-3 KUBELET node identity, APISERVER none | NOTE | README N1 bullet and SC08 state both exceptions |
| R1-4 production path and version coupling | NOTE | "No production evidence yet" names the refusing steps (2, 4 and 5 since round 3) and says that production needs a reviewed W02a revision plus an I06 successor bound to it; "Still open" carries the pairing to W03 |
| R1-5 per-record binding, inherited obligations | NOTE | README N1 and the `check_evidence` docstring state the per-record scope, the composition with `check_qualification` (W03) and the inherited W02a caller obligations 1 and 4 |
| R1-6 digest spelling | NOTE | The reference is now `qualificationDigest: "sha256:<hex>"`, W02a's own spelling; G06 refuses the bare hex form |
| R1-7 non-resource-URL rules | NOTE | IC03 says "resource rule"; observer obligation (refuse, never drop) carried to W03 |
| R1-8 P7 chain wording | NOTE | The chain is restated with the W02a side of P7(a) and the network-policy agent identity |

## Round-2 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| R2-1 refusing steps | NOTE | "No production evidence yet" names step 4 (evidence claiming `testOnly` false) next to steps 2 and 5; the R1-4 row matches |
| R2-2 stale brief wording | NOTE | The brief's question 1 asks about W02a's `sha256:` prefix |
| R2-3 module docstring | NOTE | The module docstring says "no resource rule" and names the observer obligation, as IC03 does |
| R2-4 SHA-256-only distinctness | NOTE | Carried to W02g-F2 or W03: also require distinct `verityDigest` values for backend executables, or state that SHA-256 distinctness relies on the observed backend captures in the W03 composition |
| R2-5 carries in the status record | NOTE | The status record written at adoption carries R1-4, R1-5 and R1-7 next to the P7 chain and N4-N6 |
| Author: package import | — | The model imports its predecessors as `i06_backend_profile` and `native_qualification_v3`, and falls back to `scripts.i06_backend_profile` and `scripts.native_qualification_v3`, as the repository's validators do. No rule changed |

## Not claimed

- No cluster, distribution, host or kernel observation, and no selected distribution.
- No production backend profile: W03 adds it through a reviewed W02a revision.
- All E01-E12 stay OPEN_UNPROVEN.
- The v1 profile and its inputs, the W02a v2 and v3 contracts, the W02e matrix and the W01 resolution stay
  byte-identical.

## Still open

- Production evidence needs W03's production backend profile in a reviewed W02a revision and an I06 successor bound
  to that revision (round-1 R1-4).
- Observer obligation (W03): refuse to produce a snapshot when a non-resource-URL rule is bound to `system:apiserver`
  (round-1 R1-7).
- Callers compose `check_evidence` with `check_qualification`'s acceptance of the same record and keep W02a's caller
  obligations 1 and 4 (round-1 R1-5).
- N4 (W02e, W03), N5 (W03) and N6 (W02f, W02e), as carried by W02g.
