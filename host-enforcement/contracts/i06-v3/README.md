# I06 backend profile v3 — native-profile v4 binding, round 3

Status: **CONTRACT_CANDIDATE_ROUND3_AWAITING_INDEPENDENT_REVIEW**. DATA_CHECK_ONLY: no cluster, distribution, host or
kernel is observed, nothing is installed and no distribution is selected. All E01-E12 stay OPEN_UNPROVEN.

Contract review round 1 (with native-profile v4, of candidate `0a2ecd7157e732b8d7965ed6e985203e733b1d19`) returned
CHANGES_REQUIRED; its one I06 finding, N1-5 (NOTE), is answered in the contract text below: the sentence on v2's own
binding names W02a v3 again, and a sentence on v3's binding to W02a v4 follows it. Native-profile v4's new in-set census
rule (N1-1) and member-set rule (N1-2) change no I06 v3 result. Round 2 (of candidate
`3c34a3a5ff5879d2bcf5e6691bc08eeaf59dbf41`) returned CHANGES_REQUIRED; its one I06 finding, N2-3 (NOTE), moved this
title to round 3. Native-profile v4's canonical file labels and type-based census (N2-1, N2-2) change no I06 v3 result.

v3 is I06 backend profile v2 (`../i06-backend-profile-v2/`, W02g-F, MET-ENFORCE-012, adopted after three review rounds,
as corrected by the W02 notes errata) with the W02a binding moved to native-profile v4 (`../native-profile-v4/`), the
I06 successor that the owner accepted for the minimal native-profile successor (Q-NP4-10 (a): two I06 successors, this
one bound to native-profile v4 and a later one bound to the production revision). It is published in the same
primary-lane meta packet as native-profile v4 (Q-NP4-17 (a)) and is fixture-only: production calls are still refused.
OBS-RBAC-1's grants are not in v3 (lane-monitor decision Q-NP4D-7 (a)): Q-HE4-6 is decided with HE-004C, and the grants
go to the I06 successor after v3 that Q-HE4-6's decision names.

## Why a successor

I06 v2 is bound to W02a v3 itself: `W02A_VERSION` is fixed and W02a v3's `check_record` pins the v3 schema digest, so a
native-profile v4 record cannot pass I06 v2 even as a fixture. Every W02a successor needs an I06 successor bound to it
(I06 v2 round-1 R1-4), and later layers pin I06 v2's bytes. So v3 adds this directory and
`scripts/i06_backend_profile_v3.py` beside v2, which stays byte-identical, as do the v1 profile and its inputs.

## What v3 changes

The W02a binding, and nothing else:
- **Model.** `scripts/i06_backend_profile_v3.py` is v2's model with `W02A_VERSION`
  `planeon.internal.native-qualification/v4`, native-profile v4's model imported as `w02a` (so v4's `check_record`,
  which pins the v4 schema digest), and the SC00 refusal text naming W02a v4. The evidence record format
  (`planeon.internal.i06-distribution-evidence/v2`), SC00-SC15, the snapshot check IC00-IC05 and the v1 checks are v2's.
  The appended `check_vectors` replays the vectors below.
- **G19's refusal.** v4 refuses one executable shared by two components, so G19 (one multi-call executable for every
  component, a backend W02a v3 accepted) is now refused at step 2: `SC00 W02a v4 refuses the backend record: backend
  components share an executable`. G20 (two files with one content digest) stays an SC08 refusal, because v4 allows
  identical content.
- **SC08's paragraph** below and the SC00 and SC08 criteria name W02a v4, and SC08 states that W02a v4 refuses a shared
  executable but still lets two backend files share content (design review D2-11 (e)).
- **Text adopted.** The README and criteria start from the W02 notes errata's effective I06 v2 texts
  (`../w02-notes-errata/effective/i06-backend-profile-v2/`: README sha256
  `562b00852cb84dc44f4118f8449e19819b2b1dae4d683102b5a1b53890abdd9c`, criteria sha256
  `8d4f5d7837b0f68859f222dec8766d57c2b6cc5fe49f95fddd830836569940b4`), so the errata's R3-1, R3-2 and R2-4 corrections
  hold in v3. `criteria.json` is the effective v2 criteria with `schemaVersion`
  `planeon.internal.i06-selection-criteria/v3` and the SC00 and SC08 texts changed as above; every other criterion is
  byte-identical.

## Files

| File | Content |
|---|---|
| `criteria.json` | the effective v2 criteria with SC00 and SC08 bound to W02a v4 (`planeon.internal.i06-selection-criteria/v3`) |
| `vectors.json` | the v2 evidence and snapshot positives (the evidence bound to native-profile v4 positive 0), 7 accepted evidence variants, 5 accepted snapshot variants, 91 evidence negatives (v2's, re-derived against native-profile v4's positives), 38 snapshot negatives (v2's, carried) and 7 cross-version cases |
| `scripts/i06_backend_profile_v3.py` | the reference model: `check_evidence`, `check_rbac_snapshot` and `check_vectors`; `check_inventory` and `check_closure` are v1's |
| `REVIEW_BRIEF.md` | the I06 part of the brief for the independent contract review |
| `source-index.json` | digests of the subject and of the inputs at the base main b0635f8 |

## The contract text (I06 v2's effective README, binding moved)

The sections below are I06 v2's effective text with every W02a binding mention moved to v4 and the SC08 paragraph
restated; "v2" in them names the evidence rules that v3 keeps unchanged.

### N1: evidence bound to an accepted W02a v4 record (SC00, SC08)

An evidence record (`planeon.internal.i06-distribution-evidence/v2`) adds one field, `w02aRecord`:
`{"schemaVersion": "planeon.internal.native-qualification/v4", "qualificationDigest": "sha256:<64 lowercase hex>"}`.
The digest is SHA-256 over W02a's canonical JSON form of the record (`native_qualification_v4.canonical`: sorted keys,
no whitespace, UTF-8), spelled exactly as W02a v4's captures spell their `qualificationDigest` (round-1 R1-6). The
record thereby names its backend; v1 only compared `implementationId` with whatever backend the caller passed.

The binding is per W02a record, not per distribution: a W02a record is one boot with one nonce set and one validity
window of at most 900 s, so the evidence is re-issued for each record. `check_record` is W02a's expected-data check,
not its acceptance decision. Combining `check_evidence` with `check_qualification`'s acceptance of the same record is
the caller's composition (W03). Callers of `check_evidence` inherit W02a v4's caller obligations 1 (the profile is
valid under the pinned proxy profile contract) and 4 (`test_fixture=True` only when qualifying a test fixture)
(round-1 R1-5).

`check_evidence(record, inventory, w02a_record, w02a_profile, w02a_endpoints, w02a_schema, test_fixture=False)`
checks, in this order:
1. the closed v2 record, its version and the closed reference with version v4;
2. W02a v4's `check_record` accepts `w02a_record` with its profile, endpoints and schema. Its refusal is reported as
   `SC00 W02a v4 refuses the backend record: <W02a rule>`;
3. the reference's qualification digest equals that of `w02a_record`;
4. the evidence's `testOnly` equals the backend's `backendProfile.testOnly`;
5. a test-only backend is accepted only when `test_fixture` is True. This mirrors W02a v4's `check_qualification`
   (P7(a));
6. v1's `check_evidence` on the v1 projection: the record without `w02aRecord`, under v1's version, against the backend's
   profile, implementationId and componentKeys and its `backendComponents`, with `production = not test_fixture`.

Step 2 brings in every W02a v4 backend rule that v1 never examined. The round-2 type sweep accepted 606 of 1341
substitutions because `cgroupPath`, `apiIdentities` and `filePaths` were not checked. The rules it brings in:
- each component's process label is its W02e slot constant;
- each component has its own domain, cgroup and API identity, and API identities are within the W02g closure entry for
  that component, except that KUBELET may also hold at most one `system:node:<node name>` identity, which the closure
  covers only through Group `system:nodes`, and APISERVER may hold none (round-1 R1-3);
- every backend file is owned and listed in W02a's artifact custody;
- cgroups are outside the planeon slice, never shared and never nested;
- each component's executable is its own file, in its component's matrix v5 exec type (W02a v4).

W02a v4 puts every backend component in one owner class, `backend`, but refuses one executable shared by two components
(one file per component, each in its component's matrix v5 exec type), so G19's multi-call executable is now refused at
step 2 (`SC00 W02a v4 refuses the backend record: backend components share an executable`). W02a v4 still lets two
backend files carry one content digest, so v1's SC08 rule, distinct executables with distinct content (one entry type per
confined domain), stays an I06 rule. v2 reaches it through step 6, and G20 pins it with a backend that W02a v4 accepts
(round-1 R1-1; native-profile v4 design review D2-11 (e)).

**No production evidence yet.** W02a v4's schema admits exactly one backend profile: the test-only `unit-distribution`
fixture with its eight components. Every production call (`test_fixture=False`) is therefore refused: at step 2 when
the backend is not the fixture (W02a's schema), and for the fixture backend at step 4 when the evidence claims
`testOnly` false or at step 5 when it claims `testOnly` true (round-2 R2-1). Under W02a v4, v1's production rules in step
6 are unreachable. v2 is also bound to W02a v3 itself: `W02A_VERSION` is fixed, and W02a's `check_record` pins its
schema digest, so a widened schema is refused as an unreviewed v3 schema. v3 is bound to W02a v4 in the same way: its
`W02A_VERSION` names v4 and W02a v4's `check_record` pins the v4 schema digest, so a widened schema is refused as an
unreviewed v4 schema. Production evidence therefore needs both a
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

These are refused by W02a v4's `check_record` (`backend components share a cgroup`, `backend cgroup nested in another
backend cgroup`), which N1 applies to every evidence check: G07 and G08. A09 accepts a sibling whose name only extends
the kubelet's unit name, so the nesting test is per path component. The P7 carry chain is now closed (round-1 R1-8):
- W02a v2's frozen status assigned P7 to "W02g and W03";
- W02g closed the I06 part of P7(a) and carried the W02a side of P7(a), P7(b), P7(c) and the network-policy agent
  identity to W02a-F (W02g round-2 review Q7 and the v1 README "Still open");
- W02a-F closed them (`architecture/native-profile-v3/status.json` closedFindings.P7 and NETWORK_POLICY_AGENT_IDENTITY).

The v2 status record states this when the contract is adopted.

## Replayed I06 v2 cases

Every v2 evidence negative and accepted variant is replayed under v3 with its operations and flags; backend operations
apply to native-profile v4's positive record, and the evidence then names the mutated record. Refusals reported through
SC00 name W02a v4 instead of v3, including the W02a rule's own version name (G17: "not a v4 record"). One refusal
changes for a reason, recorded in its row as `v2Refusal`:

| Vector | v2 refusal | v3 refusal | Why |
|---|---|---|---|
| G19 | SC08 components must use distinct executables with distinct content (one entry type per confined domain) | SC00 W02a v4 refuses the backend record: backend components share an executable | W02a v4 refuses one executable shared by two components (one file per component) before I06's SC08 rule |

v2's `v1Refusal` fields are not carried (they record v2's replay of v1). Every v2 snapshot case is carried unchanged.

## Cross-version cases

| Case | v1 model (W02a v2 backend) | v3 model (W02a v4 backend) |
|---|---|---|
| X01: each version's positive under the other version | refuses (closed record) | refuses (closed record) |
| X02: each version's positive under its own version | accepts | accepts |
| X03: v1 A02, a production profile renamed `selected-distribution` | accepts | refuses: W02a v4 schema |
| X04: v1 A05, a six-component fixture | accepts | refuses: W02a v4 schema |
| X05, X06: the I06 v2 round-2 N2 probes | accept | refuse: IC03 |
| X07: the I06 v2 evidence positive, naming a W02a v3 record | refuses (closed record) | refuses: SC00 evidence names a W02a record of another version |

X01-X06 are v2's cases replayed with the v3 model; X07 is new. No I06 v2 or v3 evidence is adopted outside these
vectors, so there is nothing to migrate.

## Not claimed

- No cluster, distribution, host or kernel observation, and no selected distribution.
- No production backend profile: W03 adds it through a reviewed W02a revision.
- All E01-E12 stay OPEN_UNPROVEN.
- The v1 and v2 profiles and their inputs, the W02a v2 and v3 contracts, the W02e matrix and the W01 resolution
  stay byte-identical.

## Still open

- Production evidence needs W03's production backend profile in a reviewed W02a revision and an I06 successor bound
  to that revision (round-1 R1-4).
- Observer obligation (W03): refuse to produce a snapshot when a non-resource-URL rule is bound to `system:apiserver`
  (round-1 R1-7).
- Callers compose `check_evidence` with `check_qualification`'s acceptance of the same record and keep W02a's caller
  obligations 1 and 4 (round-1 R1-5).
- N4 (W02e, W03), N5 (W03) and N6 (W02f, W02e), as carried by W02g.
- W02-PROD (W02 notes errata): a distinct-`verityDigest` rule for the backend executables (round-2 R2-4) and the
  predecessor-import fallback narrowed to `ModuleNotFoundError` for the two bare names (round-3 R3-3).
- OBS-RBAC-1's grants go to the I06 successor after v3 that Q-HE4-6's decision names (Q-NP4D-7 (a)).
- The edge record `../artifact-edges/operator-harness-engineering-v5.json` registers v3's vectors, criteria and README
  with `providerPacket` `TBD`, assigned with the slot at adoption; the status record is written at adoption.
