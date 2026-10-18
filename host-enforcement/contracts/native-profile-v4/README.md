# Native qualification record v4 — capture routes and O-NATIVE-GATE-NOCAP (DATA_CHECK_ONLY)

Alpha 2A; 2026-10-16. Status: **CONTRACT_CANDIDATE_ROUND3_AWAITING_INDEPENDENT_REVIEW**.

Contract review round 1 (of candidate `0a2ecd7157e732b8d7965ed6e985203e733b1d19`, which keeps the reviewed bytes)
returned CHANGES_REQUIRED with 2 MAJOR (N1-1, N1-2), 1 MINOR (N1-3) and 3 NOTE (N1-4 to N1-6) findings. Round 2 (of
candidate `3c34a3a5ff5879d2bcf5e6691bc08eeaf59dbf41`) found N1-2 to N1-6 resolved and N1-1 partly resolved, and returned
CHANGES_REQUIRED with 1 MAJOR (N2-1) and 2 NOTE (N2-2, N2-3) findings. "Contract review round 1 findings and
dispositions" and "Contract review round 2 findings and dispositions" at the end answer each. The review records are
kept outside the repository with the coordinator and are added with the status record at adoption.

v4 is the successor of the adopted v3 record (`../native-profile-v3/`, ADOPTED_DATA_CONTRACT after six review rounds, as
corrected by the W02 notes errata). It is the minimal capture-route successor (owner decision Q-NP4-1 (a)): v3, plus
O-NATIVE-GATE-NOCAP, plus the capture routes of the P1 role captures, the P5 lifecycle capture and the backend captures,
plus the inspector obligation restated. It adopts the errata, migrates over the v1, v2 and v3 histories and states each
reader role's capture duties. It is one primary-lane meta packet with the I06 successor bound to it
(`../i06-backend-profile-v3/`, Q-NP4-17 (a)); the slot is assigned when the contract is adopted (Q-NP4-14 (a)).

Out of scope: the production backend profile (W02-PROD; NP-1 stays open); host-policy reads (HE-008 and T04, Q-NP4-13),
whose capture fields carry the class OUT_OF_SCOPE_HOST; a capture transport (captures stay detached model data,
Q-NP4-9); and whether the server needs CAP_NET_BIND_SERVICE at all (a later W01 question, Q-NP4-5). The roadmap's
W02-PROD step for O-NATIVE-GATE-NOCAP moves to this item (a roadmap edit under the lane monitor's lock).

The v1, v2 and v3 schemas, vectors, models and records, and I06 v2, are byte-identical; v4 never reinterprets earlier
data. Nothing here is a native result, installed profile, kernel observation or grant. Every vector and model result is
DATA_CHECK_ONLY, and all E01-E12 stay OPEN_UNPROVEN. T04 is named below as the owner of proofs; no T04 check is designed
here.

Accepted base: main `b0635f81e5ba3b6538fc0cfd28a78f0fea962f50` (MET-ENFORCE-031, 243 packets); the inputs are unchanged
since `fd362f9e` (MET-ENFORCE-030). Design: native-profile v4 design revision 2.2 (sha256 `9cd3a5f0…035039d`), after
three design review rounds (round 3 PASS_FOR_CONTRACT; its D3-1 to D3-6 are applied), and the owner and lane-monitor
decisions Q-NP4-1..17, Q-NP4D-1..10 and Q-NP4D-B.

## Text in force

- **Errata adopted (Q-NP4-12 (a)).** v4 adopts the effective v3 README of the W02 notes errata
  (`../w02-notes-errata/effective/native-profile-v3/README.md`, sha256
  `fd12a0ded9b7de557cb75a8bdeb01c2c3fa85c24035b174282d2274dc6000bd0`) for every v3 rule that v4 keeps. "Adopted v3 text"
  below reproduces its rule sections verbatim, with the R6-1 and R6-2 replacements; the sections before it replace the
  v3 statements they name. v4's model applies the errata's comment-only replacement (R6-1g) to its grammar comment, and
  v4's vectors replay the errata's 35 negatives and 4 accepted R6-3 cases.
- **HS43's replacement clause.** Native profile v2's README sentence "CAP_NET_BIND_SERVICE only with a signed port below
  1024" holds, in v4, "for the server only; EFFECT_GATE holds none, because its signed I04 port is 1024 or above (W01
  §5.3 as amended by HS43, H5; O-NATIVE-GATE-NOCAP)". HS43 states that a successor of each contract adopts the text; v4
  does, and enforces it (below).

## Files

- `qualification.schema.json`: JSON Schema 2020-12, `$id` `urn:planeon:internal:native-qualification:v4`, contract
  `planeon.internal.native-qualification/v4`, profile `SELINUX_FSVERITY_CGROUP_BPF_V4`. It is the v3 schema with the
  changes below and every version discriminator moved to v4, with the same four variants (`record`, `capture`,
  `lifecycleCapture`, `backendCapture`). New definitions: `fileEntry`, `observedRoleCgroup`, `observerCgroup`,
  `programInfo`, `roleProcess`, `member`, `memberSet`, `observerProcess`, `observerMember`, and `evidenceClasses`, a
  constant that no variant references: the class table below, as data.
- `vectors.json`: 5 positives (4 derived from v3's 4 and relabelled, plus a low-port server derived from v3's positive
  1); 444 negatives (all 207 v3 negatives, v3's A01 and A05, the errata's 35 R6-3 negatives and N01-N200); 18 accepted
  cases (v3's 7 other accepted cases, the errata's 4 and A10-A16); 15 cross-version cases; 22 migration cases. Each case
  is pinned to its exact result; the positives are JSON round-tripped before any case is pinned. `inputs` pins, by
  SHA-256, the v1, v2 and v3 schemas and vectors and the errata vectors that the replay reads.
- `../../scripts/native_qualification_v4.py`: the reference data model, v3's model with the changes below, so the
  v3-to-v4 diff is the review surface. `check_qualification` remains the only acceptance-shaped check. `check_vectors`
  replays every vector, checks every v3 case and every errata case against its v3 form, and returns the number of
  checks.
- `REVIEW_BRIEF.md`: the brief for the independent contract review. `source-index.json`: the subject and input digests.

Caller obligations (stated in the model, not checked by it):
1. The profile is valid under the pinned proxy profile contract (`scripts/validate_proxy_contract.py`).
2. `v1_records`, `v2_records` and `v3_records` are the host's complete retained v1, v2 and v3 enrollment histories,
   owned by the host's enrollment ledger (NP-2, now extended to v3 records; an HE-008 share), or `no_earlier_history` is
   set because all three are attested empty.
3. v3's obligation 3 is replaced by the inspector obligation below.
4. `test_fixture=True` is passed only when qualifying a test fixture.

## What v4 changes

| Item | v4 rule | Vectors |
|---|---|---|
| O-NATIVE-GATE-NOCAP | EFFECT_GATE `capabilities` is `const []`. "CAP_NET_BIND_SERVICE only for a signed port below 1024" holds for SERVER only. EFFECT_GATE gains "EFFECT_GATE holds no capability and its signed I04 port is 1024 or above". | R28, R29 (changed), N01, N02; A01 now a negative; A10 |
| Capturer | Every P1, P5 and backend capture carries `capturer: "OBSERVER"` (schema const, checked in every capture check). It is a declaration in detached data, not provenance. | N03-N08 |
| Evidence classes | The class of each capture field is a function of the role and its recorded capability set (table below). OBSERVED fields are required; LABEL_BOUND and DECLARED_T04 fields are absent from the capture. | N09-N46, N118-N191 |
| Declared fields | Labels (cgroups, pins, files, the seal marker), the seccomp filter digest and default action, and `rlimitCore` leave the captures; the checks use the record's declared values. | N47-N56; C27-C29, L05 (changed) |
| Seccomp_filters | Each non-observer capture reports `seccompFilters` for the process and every member: 2 for WORKER, 1 for every other role. | N57-N62 |
| Entrypoint labels | Every role and lifecycle subject declares `executableLabel` (a schema const: its domain's matrix v5 entrypoint type), interpreted roles declare `interpreterLabel` (`planeon_interpreter_exec_t`), and each backend component declares its matrix v5 exec type. Each executable file's recorded label must equal its constant. Every enrolled file label is the canonical context `system_u:object_r:<type>:s0`, compared by type. Inside the record's inventory, an entrypoint or exec type labels only its own subject's executable, and the interpreter type only files of the interpreted closures (the in-set half of the census). | N63-N72, N103-N110, N192-N200; A16 |
| Closures | OBSERVER and BROKER load their executable alone. Every executable-segment file of an interpreted role's closure, other than its script, carries the interpreter type. One executable file per backend component. | N73-N77; A05 now a negative; A12 |
| Proof list | The record carries `t04Proofs`, which must equal the schema's constant list. | N78-N80 |
| Inspector obligation | Member and thread sets are read before and after; each lists every key once, both are equal, and their keys are exactly the reported members' keys; a WORKER capture qualifies only inside a frozen bracket. | N81-N95, N97, N111-N117; A13, A15 |
| P5 | The P5 lifecycle capture carries the capturer, its seal marker without the label, and its counts as before. | N05, N06, N56, N96 |
| Migration | A v4 enrollment needs a maintenance reboot and fresh nonces against the complete v1, v2 and v3 histories; the v3 schema digest joins the v1 and v2 pins. | M15-M22 |

## O-NATIVE-GATE-NOCAP

W01 §5.3, as amended by HS43 (H5, Q-HE2S-9 (a)), gives the gate no capability and a signed I04 port of 1024 or above.
The v4 schema fixes EFFECT_GATE `capabilities` to `[]`, so v3's accepted A01 (a gate on a low signed port with exactly
CAP_NET_BIND_SERVICE) is now refused by the schema. The model keeps v3's rule for SERVER only and adds the gate rule: a
gate whose signed I04 port is below 1024 is refused whatever its capabilities (R29, N01). R27, the server case, is
unchanged; R28's refusal moves to the schema. A gate on port 1024 is accepted (A10). Matrix v5 already gives the gate no
capability (A68, O-MATRIX-GATE-NETBIND discharged in data).

## The capture routes

### The capturer (Q-NP4-6 (a))

Every P1, P5 and backend capture carries `capturer: "OBSERVER"`: the owner designated the observer for the P1 and P5
captures (OBSERVER-CAPTURE, Q-MX-2 (b), Q-MX-3 (b)), and Q-NP4-7 (a) and Q-NP4D-B (a) give it the backend captures. The
field is a declaration in detached data, not provenance: authenticating who captured is a residual owned by HE-004D1
and, when it is decided, I01's channel.

### Evidence classes (closed)

- **OBSERVED**: read by the observer from another process's `/proc` entry it may read (matrix v5 `procAccess` and the
  ptrace-read rule), from cgroupfs or bpffs, or by measuring an enrolled file (no-follow descriptor,
  `FS_IOC_MEASURE_VERITY`).
- **LABEL_BOUND** (owner Q-NP4-2 (a)): the observed domain label, plus the observed measurement of the role's entrypoint
  file, plus declared premises, each with a named proof:
  - (P-a) the installed policy grants `file entrypoint` into the captured domain on exactly the role's entrypoint
    constant type, in the policy whose digest the record carries, and the matrix assertions it relies on hold in that
    policy: A12 (no write or relabel of a sealed type in the enrolled boot), A32 (no dynamic transition), A33 (no
    setexec), A37 and A60.15-21 (no `execute_no_trans` for the planeon sources), and the observer's `/proc` access to
    every planeon and qualk8s domain as matrix v5 grants it (`procAccess`). The host-wide `/proc` label scan behind the
    P5 `domainProcessCounts` is complete only then: a process whose `attr/current` read fails cannot be told apart from
    one in another domain. Proof **T04-ENTRYPOINT**.
  - (P-b) no file outside the enrolled set carries any captured role's entrypoint type, `planeon_interpreter_exec_t` or
    any executable-segment type of a LABEL_BOUND closure, on any mounted filesystem, including mount-option contexts and
    images that carry stored labels, for the whole enrolled boot, including mounts the kubelet and the runtime make at
    run time (both hold CAP_SYS_ADMIN, matrix A47). Proof **T04-ENTRYPOINT-CENSUS**. Matrix v5 does not model the
    `filesystem` class that governs `context=` mounts, so a matrix successor's `filesystem` closure is a named residual.
    This extends HS43's O-W03-PEER-EXE from the broker to every LABEL_BOUND role. The census has two halves: inside the
    enrolled set it is the model's rule (`check_record`: each entrypoint or exec type labels only its own subject's
    executable, and `planeon_interpreter_exec_t` only files of the interpreted roles' closures); outside the enrolled
    set it is T04's.

  No self-report counts as evidence.
- **DECLARED_T04** (owner Q-NP4-4 (a)): no role can observe the field; the record declares it and names one T04 proof.
- **OUT_OF_SCOPE_HOST**: the host-policy reads outside v4's scope (Q-NP4-13): `selinuxBefore`, `selinuxAfter`,
  `kernelPolicyDigest`, `booleansObserved`, `hardeningObserved`, `host` and `bootEntryObserved`. How they are read is
  HE-008's and T04's; v3's equalities on them are kept.
- **ENTRY_BOUND** (backends, owner Q-NP4D-B (a)): LABEL_BOUND's observations and premises P-a and P-b applied to a
  qualk8s domain (exactly one entrypoint type per domain, the backend constant; the census over the qualk8s exec types),
  minus the `execute_no_trans` premise. It binds the domain's entry and the measured file, not the running image.
- **CONSISTENCY_ONLY**: capturer-supplied binding and timing fields (`qualificationDigest`, `observedAt`,
  `inspectionStartedMs`, `inspectionFinishedMs`, `deadlineMs`), checked for consistency with the record and each other
  only.

### Classes by role, recorded capability set and field

The class is a function of the role and its recorded capability set (`capture_class` in the model). The schema fixes the
role-only parts; the model decides the server's capability-dependent class from the record and refuses a LABEL_BOUND
capture where OBSERVED is required. POLICY_WRITER is a lifecycle subject, not a P1 target.

| Field | EFFECT_GATE; SERVER without CAP_NET_BIND_SERVICE | BROKER; WORKER; SERVER with CAP_NET_BIND_SERVICE | OBSERVER (its own capture) |
|---|---|---|---|
| `process.exe`, `cgroupMembers[].exe`, `executableMaps`, `process.namespaceInodes` | OBSERVED (required; v3's equalities) | forbidden (LABEL_BOUND) | forbidden (DECLARED_T04: T04-OBSERVER-IDENTITY) |
| uid, gid, capability sets, noNewPrivs, seccompMode, threadCount, threadsUniform, pid, startTicks, ppid, processLabel, cgroup path; the member sets | OBSERVED | OBSERVED | DECLARED_T04 (T04-OBSERVER-IDENTITY): absent |
| cgroup inode and limits, members, `pidsCurrent`, children; BPF programs; the effective census; the frozen bracket (WORKER) | OBSERVED (cgroupfs, bpffs) | OBSERVED | OBSERVED cgroup facts only: `cgroup.procs` holds exactly one pid, the limits, the programs and the census; no process-level claim |
| `rlimitCore` | DECLARED_T04 (T04-RLIMIT): absent | same | DECLARED_T04 (T04-OBSERVER-IDENTITY): absent |
| enrolled file measurements (`files[]`: device, inode, uid, gid, nlink, sha256, verity) | OBSERVED | OBSERVED | OBSERVED (the observer measures files; this is not its process identity) |
| `seccompFilterDigest`, `seccompDefaultAction` | DECLARED_T04 (T04-SECCOMP-INSTALLED): absent, corroborated by the OBSERVED `Seccomp_filters` count (`seccompFilters`) | same | DECLARED_T04 (T04-SECCOMP-INSTALLED) with no corroboration: the observer's own count would be a self-read |
| `selinuxLabel` of the role cgroup, pins, enrolled files and the seal marker in `hardeningObserved` | DECLARED_T04 (T04-LABELS): absent | same | same |
| host, policy and boot fields | OUT_OF_SCOPE_HOST | same | same |

`rlimitCore` is DECLARED_T04 for every role: `/proc/<pid>/limits` readability is not a v4 premise. The schema's
`evidenceClasses` constant holds this table, the P5 classes and the backend classes as data.

**v3 equalities that no longer run on the observer's own capture**: the process-field equalities (uid and gid,
capability sets, noNewPrivs, seccomp mode, threads, label, image, maps and namespaces), replaced by
T04-OBSERVER-IDENTITY; `pidsCurrent` equal to the members' thread sum (only `pidsCurrent <= pids.max` runs); and the
observer's (pid, start) in the cross-capture uniqueness rule of `check_qualification`. The cgroup-level equalities still
run: exactly one member, the cgroup inode and limits, the programs and the census.

**The observer's own image (owner Q-NP4D-6 (a))**: DECLARED_T04 with T04-OBSERVER-IDENTITY; HE-008's off-host enrollment
measures the observer's file; and a W03/T04 obligation covers the observer's same-domain `/proc` reads that the P5 count
of `planeon_observer_t` processes needs (matrix v5 leaves same-domain access to host policy, vector O03).

**The low-port server (Q-NP4-5 (a))**: a server that holds CAP_NET_BIND_SERVICE is LABEL_BOUND, since no reader role can
read its exe link. Positive 4 (signed port 443) qualifies with a LABEL_BOUND server capture, A11 accepts the same record
change on positive 1, and N18-N22 refuse each OBSERVED field in positive 4's server capture. W03 obligations carried:
the server stays dumpable (like O-W03-PEER-EXE for the gate), and `/proc` leaves the ungated entries readable (no
`hidepid` restriction).

**P5 lifecycle capture classes**: the seal marker's path, digest, uid and mode, `runFsType`, the containment cgroup
state, `sliceCgroups`, `domainProcessCounts` (a host-wide `/proc` label scan, complete only under P-a), `sliceMembers`
and `sliceDescendants` are OBSERVED; the marker's `selinuxLabel` is DECLARED_T04 (T04-LABELS) and absent; the
`planeon_observer_t` count is OBSERVED under the W03/T04 same-domain obligation; booleans and the boot entry are
OUT_OF_SCOPE_HOST; binding and timing are CONSISTENCY_ONLY.

### Entrypoints and labels (Q-NP4D-9 (a))

- **File-label constants.** The schema fixes, per key, each executable's label:

  | Key | `executableLabel` (matrix v5 type) |
  |---|---|
  | SERVER, OBSERVER, BROKER, WORKER, EFFECT_GATE | `planeon_server_exec_t`, `planeon_observer_exec_t`, `planeon_broker_exec_t`, `planeon_worker_exec_t`, `planeon_gate_exec_t` |
  | HOST_CONTAINMENT, POLICY_WRITER | `planeon_contain_exec_t`, `planeon_policy_writer_exec_t` |
  | the interpreter (`interpreterLabel` of SERVER and WORKER) | `planeon_interpreter_exec_t` |
  | APISERVER, DATASTORE, CONTROLLER_MANAGER, SCHEDULER | `qualk8s_apiserver_exec_t`, `qualk8s_datastore_exec_t`, `qualk8s_controller_manager_exec_t`, `qualk8s_scheduler_exec_t` |
  | KUBELET, CONTAINER_RUNTIME, SERVICE_PROXY, NETWORK_POLICY_AGENT | `qualk8s_kubelet_exec_t`, `qualk8s_runtime_exec_t`, `qualk8s_proxy_exec_t`, `qualk8s_netpol_exec_t` |

  Each label is `system_u:object_r:<type>:s0`. v3's positives use `planeon_code_t` and `qualification_k8s_exec_t`, which
  matrix v5 does not declare; v4's positives are relabelled (N63 and N69 refuse the v3 labels). The constants are schema
  constants, to be cross-checked against matrix v5 by v4's layer validator; v4's model does not pin the matrix file, so
  a later matrix revision that changes a type needs a v4 successor or errata.
- **The entrypoint file is the role's executable for every role.** For the interpreted roles (SERVER, WORKER) the
  executable is the script, whose type is the domain's entrypoint type. The image binding is stated separately: the
  domain was entered through the measured script; the image is the interpreter its first line names, which must equal
  the record's `interpreterPath`; that file is measured; and the domain maps only files it may EXECUTE: proof
  **T04-MAPS-INTERPRETER**, defined over the full loaded closure (the interpreter, its shared libraries and loader, its
  extension modules). Every executable-segment file of that closure carries a dedicated planeon type,
  `planeon_interpreter_exec_t` for the whole interpreter tree, its shared libraries, loader and extension modules
  included, never a host-shared type such as `lib_t`, which the census could never cover (W03 ships private copies).
  P-b's census covers that type. The model checks that every executable-segment file of an interpreted role's closure,
  other than its script, carries `interpreterLabel` (N68, N75, N76; A12 accepts a library in the dedicated type). The
  first-line check needs the script's bytes, which the record holds only as digests, so it is HE-008's, at the off-host
  enrollment that reads the files.
- **The script the interpreter reads** stays declared (v3's residual). The server, started by systemd, has its
  interpreter reopen the script by path. Under W01's W5 the worker is executed with `execveat(fd, "", ...,
  AT_EMPTY_PATH)` on an O_PATH descriptor of the worker executable; for a script the kernel hands the interpreter
  `/dev/fd/<fd>` and refuses the exec with ENOENT if that descriptor is close-on-exec, so the worker's interpreter reads
  its script through the inherited descriptor, not by path (design review D2-11 (h); author's kernel reading, for W03
  and T04 to confirm).
- **Static native roles** (BROKER, and the observer's file): `filePaths == [executable]`, a single-file static closure.
  v3's accepted A05 (a shared library with an executable segment in the observer's and the broker's closures) is now a
  negative (N73, N74 too). Proof **T04-MAPS-STATIC**: the role's executable mappings are its executable's segments only,
  bounded by the domain's EXECUTE grants and the exec-memory denials (matrix A35: no execmem, execstack or execheap;
  A36: no execmod).
- The model checks that each entrypoint file's recorded label equals the role's constant (N63-N66), that no two roles
  share an entrypoint label (the schema's distinct constants refuse it first, N67), and that no backend executable
  serves two components (N77).
- **Canonical labels.** Every enrolled planeon and backend file label (`files[].selinuxLabel`,
  `backendFiles[].selinuxLabel`) is the canonical context `system_u:object_r:<type>:s0` (schema pattern), so one type
  has one spelling: another user, role or MLS level is refused (N192-N200). Where the design fixes the type, it is a
  closed constant: the subjects' `executableLabel` and `interpreterLabel` (schema `const`), which the files must carry.
  The model compares labels by their type field (`_type`), as SELinux grants entry and execution by type.
- **The in-set census** (`check_record`), by type: a file of the record's inventory (`files` and `backendFiles`) whose
  type is any subject's entrypoint type (the five roles' and the two lifecycle subjects' `executableLabel`) or any
  backend exec type of the schema's eight component constants must be that subject's executable (N103-N108); an exec
  type whose component the record does not list labels no file. A file in `planeon_interpreter_exec_t` must be in an
  interpreted role's closure and in no native, lifecycle or backend closure, and must be no subject's executable (N109,
  N110). So, inside the record's inventory, no file but a subject's executable carries that subject's entrypoint or exec
  type under any spelling, and a record cannot declare a second entry file for any domain; P-b's out-of-set half stays
  T04's. The rule runs after every earlier record rule; A16 accepts an ordinary library in its own type.
- I06's SC08 keeps content distinctness: G19, I06 v2's multi-call backend, is now refused by v4's `check_record` inside
  I06 v3's step 2, and G20 (two files with one digest) stays an SC08 refusal, because v4 allows identical content.

### Namespaces

T04-NS-SHARED is scoped to the controls that stop namespace creation at run time: SELinux `user_namespace create` denied
to the planeon and worker domains, the unprivileged user-namespace sysctl, and the broker's W-rules (no namespace flags
in its clone3 use, a W02d/W03 obligation beside CLONE_INTO_CGROUP). Its owner is T04 with W03. For OBSERVED targets v3's
namespace equality still runs (N100).

### Backends (owner Q-NP4D-B (a))

Backend captures are ENTRY_BOUND and claim only "domain entry plus measured file": the observer reads each `qualk8s_*`
component's ungated fields and domain label and measures its enrolled executable. v4 does not claim that the captured
process still runs that executable, because matrix v5 has no `execute_no_trans` closure for the qualk8s sources
(D-HELPER-TYPES open). Named residual: an `execute_no_trans` closure for the qualk8s sources goes to a matrix successor
(parallel lane), plus T04. Backend capabilities stay "declared, not observed". Each component's executable is its own
file in its own exec type (N69-N71, N77).

### Capture shapes and the proof list

- Label and seccomp-value fields leave the captures: `process.cgroup.selinuxLabel`, `bpfPrograms.*.pinLabel` and the pin
  label inside each observed program (`programInfo`), `files[].entry.selinuxLabel` (`fileEntry`), the seal marker label
  in `hardeningObserved` and in the lifecycle capture, `process.seccompFilterDigest` and `process.seccompDefaultAction`;
  `process.rlimitCore` leaves too. The checks compare with the record's declared values.
- For LABEL_BOUND targets `exe`, `executableMaps` and `namespaceInodes` are absent; for the observer's own capture the
  process block holds only the cgroup inode and limits (`observerCgroup`) and each member row only its pid.
- New capture fields: `capturer`; `seccompFilters` in the process and in each member row; `memberSetBefore` and
  `memberSetAfter` (each member's pid, start ticks and thread set of (tid, start ticks)); `cgroupFrozenBefore` and
  `cgroupFrozenAfter` (`cgroup.events` `frozen`, WORKER only).
- The record carries `t04Proofs`, which must equal exactly the schema constant `["T04-ENTRYPOINT",
  "T04-ENTRYPOINT-CENSUS", "T04-MAPS-STATIC", "T04-MAPS-INTERPRETER", "T04-NS-SHARED", "T04-SECCOMP-INSTALLED",
  "T04-LABELS", "T04-RLIMIT", "T04-OBSERVER-IDENTITY", "T04-BROKER-SPAWN"]`.
- The `Seccomp_filters` corroboration expects 2 for WORKER and its members (the broker's inherited filter and the
  worker's own; HS43 HOST_INTERFACE_SPEC.md, BROKER row) and 1 for every other role. Negatives: each forbidden field
  present, with an equal and with a different value (N18-N56 with V08, V22, V45, C27-C29 and L05 for the first values,
  N118-N191 for the other halves: every LABEL_BOUND target's image, maps, namespaces and member image, the observer's
  image, maps, namespaces, member image and every process-level field and member field, the declared labels and seccomp
  values, and the frozen flags and member sets outside the worker leaf); each OBSERVED field missing; a proof missing or
  extra; a LABEL_BOUND capture where OBSERVED is required; each wrong filter count.

## The inspector obligation (Q-NP4-8 (a); owner Q-NP4D-8 (a))

The observer never freezes and never writes any `cgroup.freeze` (Q-HE4-3/4 (a): no cgroup write grant). Per leaf:
- **No-fork roles** (EFFECT_GATE, SERVER): the full `(pid, startTicks)` member set and each member's `(tid, start)`
  thread set are read before and after the process reads, through pidfds or a held `/proc/<pid>` directory descriptor
  (the I05 v4 precedent; the observer row allows `pidfd_open`), and must be equal; `threadsUniform` holds over the whole
  thread set. Each read lists every `(pid, startTicks)` key and every `(tid, start)` key once (and each tid once), the
  two reads are equal, and their member keys are exactly the reported members' keys, with each member's thread count
  (N111-N117; an exact repeat inside one thread list is refused by the schema, N114). The same holds inside the worker's
  frozen bracket. Residual: a thread that starts and ends wholly inside the window is not seen; acceptable because these
  roles' filters allow only thread-flag clones, and such a thread shares the process's credentials and filter.
- **The observer's own leaf** gets only the OBSERVED cgroup facts above.
- **Broker leaf**: a W02d/W03 obligation has the broker spawn with `CLONE_INTO_CGROUP`, so its children never enter the
  broker leaf, which is then read like a no-fork role. This rests on a declared premise (W02d/W03 conformance, proof
  **T04-BROKER-SPAWN**): a non-conforming broker that forks into its own leaf transiently is not excluded by the
  observer. A capture taken while a spawn is in flight (a pre-exec broker-domain child in the worker leaf) is refused
  (N95), as expected, and retried later.
- **Worker leaf**: a frozen bracket. `cgroup.events` shows `frozen 1` before and after the reads (the observer may read
  `cgroup.events`, matrix v5), and inside the bracket the `(pid, startTicks)` member set and each member's `(tid,
  start)` thread set are equal before and after, so a broker-side change during the bracket is refused (N91, N92). Owner
  decision Q-NP4D-10 (a), "Frozen bracket only": "A WORKER capture qualifies only inside a frozen bracket: frozen=1
  before and after, AND equal (pid, start) member sets and (tid, start) thread sets before and after." An unfrozen
  capture makes no member-level claim and does not qualify: `check_capture` refuses it, and so `check_qualification`
  does (N88, N89, N97). A W03 obligation has the broker freeze the probe-worker leaf at quiescent points so that
  qualification can be taken; the residual is availability, not safety. Further residuals: a member added and removed
  while the leaf is frozen, which never ran in the leaf; a thread wholly inside a thaw and refreeze gap; and the P5
  worker count and the WORKER capture taken at different moments, as in v3.

v3's "a change is a refusal, not a race" claim is removed. NP-3's "never writes the broker leaf's cgroup.freeze" is
structural.

## T04 proofs and residuals

The record's `t04Proofs` names the proofs a v4 record relies on. T04 owns each; none is designed here.

| Proof | What it must show |
|---|---|
| T04-ENTRYPOINT | P-a: the installed policy (the record's policy digest) enters each captured domain only through its entrypoint constant type; A12, A32, A33, A37 and A60.15-21 hold; the observer's `procAccess` to every planeon and qualk8s domain holds as matrix v5 grants it |
| T04-ENTRYPOINT-CENSUS | P-b, its out-of-set half (`check_record` holds the in-set half): no file outside the enrolled set carries an entrypoint, interpreter or closure executable-segment type, on any filesystem, for the whole enrolled boot, runtime mounts included |
| T04-MAPS-STATIC | the static roles' executable mappings are their executable's segments only (EXECUTE grants, A35, A36) |
| T04-MAPS-INTERPRETER | the interpreted roles map only their full loaded interpreter closure |
| T04-NS-SHARED | no namespace creation at run time: `user_namespace create` denied, the unprivileged user-namespace sysctl, no namespace flags in the broker's clone3 (with W03) |
| T04-SECCOMP-INSTALLED | the installed filter of each role equals its declared digest and default action (W02d-Q3) |
| T04-LABELS | the role cgroups, pins, enrolled files and the seal marker carry their declared labels |
| T04-RLIMIT | each role runs with its declared core limit |
| T04-OBSERVER-IDENTITY | the observer's own process identity, image, maps, namespaces, threads and filter |
| T04-BROKER-SPAWN | the broker spawns with CLONE_INTO_CGROUP and no namespace flags (with W02d/W03) |

Residuals and obligations carried (each with its owner):
- **T04**: the ten proofs above; the observer's same-domain `/proc` reads for the P5 observer count (with W03).
- **HE-008**: the observer's file measured at off-host enrollment; NP-2's ledger extended to v3 records; the interpreted
  roles' first-line check.
- **W02d/W03**: the broker spawns with CLONE_INTO_CGROUP and no namespace flags.
- **W03**: the server stays dumpable; `/proc` without a `hidepid` restriction; the broker freezes the probe-worker leaf
  at quiescent points; private interpreter copies in the dedicated type.
- **Matrix successor (parallel lane) + T04**: an `execute_no_trans` closure for the qualk8s sources, and a `filesystem`
  class closure for `context=` mounts.
- **HE-004D1 / I01**: authenticating the capturer.
- **The worker leaf**: the unfrozen-member and bracket residuals above.
- **W01**: whether the server needs CAP_NET_BIND_SERVICE.
- **W02-PROD**: the production profile, W02G-F2, D-HELPER-TYPES.
- **A later I06 successor**: OBS-RBAC-1's grants (owner-delegated Q-NP4D-7 (a): not in I06 v3; the I06 successor that
  Q-HE4-6's decision names).

## Reader duties (Q-NP4-16 (a))

| Reader role | Capture duties under v4 |
|---|---|
| OBSERVER | every P1 role capture (its own leaf included), the P5 lifecycle capture and every backend capture |
| SERVER | none |
| BROKER | none |

MATRIX-READER-NARROWING can therefore evaluate the server's and the broker's remaining `/proc` reads against their other
duties.

## Minimum kernel versions

The enrolled kernel is Linux v6.12 (v3's census basis). The fields v4 adds or relies on were introduced, by the author's
reading of the kernel history (for T04 to confirm on the enrolled kernel), in: `Seccomp_filters` in
`/proc/<pid>/status`, 5.9; `cgroup.events` `frozen` (the cgroup v2 freezer), 5.2; `pidfd_open`, 5.3;
`CLONE_INTO_CGROUP`, 5.7; `FS_IOC_MEASURE_VERITY`, 5.4; `BPF_LSM_CGROUP`, 6.0. The version that added the SELinux
`user_namespace` class and its `create` permission is not asserted here: the author's reading (6.0) and the round-1
reviewer's (6.1) differ, so it is an author's reading for T04 to verify on the enrolled kernel; v6.12 has it under
either reading.

## Replayed v3 cases

All 207 v3 negatives, 9 accepted cases, 14 cross-version cases and 14 migration cases are replayed under v4 against the
derived positives (each keeps its id and positive index). The derived positives carry v4's discriminators, fresh boot
IDs (`42345678-…`) and nonces (`unit-nonce-v4`, `unit-capacity-nonce-v4`), so that v3's positives serve as v4's v3
history; the matrix v5 labels; the declared fields; and the v4 capture shapes.

**Mechanical changes** (version names only): R01 "not a v3 record" becomes "not a v4 record", the migration cases' "v3
enrollment without a maintenance reboot" and "earlier nonce carried into v3 data" name v4, and the cross-version cases
X01-X14 move one version up (v3 data under the v4 model, v4 data under the v3 schema).

**Re-derived operations** (9; each row records why): C14-C18 and V18 (the appended member row gains its role's
Seccomp_filters count, a LABEL_BOUND role's row drops its image, and the member sets read before and after list it); Q03
(the duplicated server capture is v4's); V08 (the observer's own capture has no image to alter, so the case sets one);
V56 (the LABEL_BOUND worker capture has no image or maps, so only its file observation moves).

**Changed refusals** (10, plus v3's accepted A01 and A05, now negatives), each recorded in its row as `v3Refusal` with a
`reason`:

| Case | v3 result | v4 refusal | Reason |
|---|---|---|---|
| R28 | CAP_NET_BIND_SERVICE only for a signed port below 1024 | schema $.roles.EFFECT_GATE.capabilities const | O-NATIVE-GATE-NOCAP: the schema fixes EFFECT_GATE capabilities to [] (const), so the capability is refused before any port rule |
| R29 | CAP_NET_BIND_SERVICE only for a signed port below 1024 | EFFECT_GATE holds no capability and its signed I04 port is 1024 or above | O-NATIVE-GATE-NOCAP: a gate on a signed port below 1024 is refused by the v4 gate rule, whatever its capabilities |
| C13 | capture binding | schema $.cgroupFrozenBefore not | the capture schema's role-conditional shapes (the frozen bracket belongs to WORKER only) refuse the worker capture under another role before the binding rule |
| C27 | process/kernel custody differs | schema $.process additionalProperties | the seccomp filter digest is DECLARED_T04 (T04-SECCOMP-INSTALLED) and absent from v4 captures; the schema refuses it, equal or different |
| C28 | process/kernel custody differs | schema $.process.cgroup additionalProperties | role cgroup labels are DECLARED_T04 (T04-LABELS) and absent from v4 captures; the schema refuses the field |
| C29 | effective kernel filter differs | schema $.bpfPrograms.INET4_BIND additionalProperties | pin labels are DECLARED_T04 (T04-LABELS) and absent from v4 captures; the schema refuses the field |
| L05 | seal marker differs | schema $.sealMarker additionalProperties | the seal marker's label is DECLARED_T04 (T04-LABELS) and absent from the v4 lifecycle capture; the schema refuses the field |
| V08 | running image is not the role's executable or interpreter | schema $.process additionalProperties | the observer's own image is DECLARED_T04 (T04-OBSERVER-IDENTITY): an observer capture carrying any image is refused by the schema |
| V22 | unenrolled cgroup member | schema $.cgroupMembers[0] additionalProperties | the observer's own capture carries no thread count (T04-OBSERVER-IDENTITY); the schema refuses the member field |
| V45 | running image is not the role's executable or interpreter | schema $.cgroupMembers[1].exe not | WORKER is LABEL_BOUND: a member image in a worker capture is refused by the schema, whatever its value |
| A01 | accepted | schema $.roles.EFFECT_GATE.capabilities const | O-NATIVE-GATE-NOCAP: EFFECT_GATE capabilities are const [] in the v4 schema (v3 accepted case, now a negative) |
| A05 | accepted | static native role closure is its executable alone | static native closures (DESIGN 3.4, D1-7): OBSERVER and BROKER load their executable alone, so a shared library is refused (v3 accepted case, now a negative) |

v3's binding rule, which C13 no longer reaches, is pinned by N98 and N99. v3's executable-map rule had no vector in v3;
N101 and N102 pin it for OBSERVED targets.

**Second defects by construction**: V21 (a gate with more threads than its `pids.max`) also leaves its member sets'
thread count unchanged, so the member-set rule would refuse it too; C13's role change breaks two schema keywords
(`cgroupFrozenBefore` and `cgroupFrozenAfter` under a non-worker role), the one schema-level refusal in the vectors with
two errors. Every other schema-level refusal is a single error.

**Rules no JSON case can reach**: the schema-digest pins (v1 to v4), the `migration inputs` type guard and the capture,
lifecycle and backend version discriminators (cross-version X09-X11), as in v3; and "two roles share an entrypoint
label", which the schema's distinct constants refuse first (N67); "malformed SELinux context", since the schema admits
only canonical file labels; and the census entries for backend exec types whose component is absent, since the only
backend profile lists all eight components (they guard a successor that admits fewer). With canonical labels, comparing
types and comparing whole labels give the same results, so no case separates them. By the author's probe, disabling any
other model rule that v4 adds or changes changes the result of at least one case.

## The errata's R6-3 cases

The errata's 35 negatives (R63-01 to R63-35) and 4 accepted cases (R63-A01 to R63-A04) are replayed under v4 against
v4's positive 1 with their operations and refusals unchanged: v4 keeps v3's boot-entry rules.

## v4 cases

| Rule | Negatives | Accepted |
|---|---|---|
| O-NATIVE-GATE-NOCAP | N01, N02 (and R28, R29, A01) | A10, A11 |
| The capturer | N03-N08 | |
| OBSERVED fields required (gate by the schema, server by the model) | N09-N17 | |
| LABEL_BOUND fields forbidden (low-port server by the model, broker and worker by the schema) | N18-N31 | positive 4 |
| The observer's own capture | N32-N46 | A14 |
| Declared fields absent | N47-N56 | |
| Seccomp_filters | N57-N62 | |
| Entrypoint and backend label constants | N63-N72 | |
| The in-set census of entrypoint and interpreter types | N103-N110 | A16 |
| Canonical file labels (another user, role or level; a non-canonical form) | N192-N200 | |
| Closures and one file per backend component | N73-N77 (and A05) | A12 |
| The proof list | N78-N80 | |
| The inspector obligation and the frozen bracket | N81-N95, N97 | A13, A15 |
| Member-set keys unique and equal to the reported members' keys | N111-N117 | |
| Forbidden fields with their other value (LABEL_BOUND targets N118-N126; the observer's image, maps, namespaces and member image N127-N131; declared labels N132-N135; frozen flags and member sets outside the worker leaf N136-N145; the observer's process-level and member fields N146-N191) | N118-N191 | |
| The P5 observer count | N96 | |
| v3 rules kept and re-pinned | N98-N102 | |

## Cross-version and migration

X01-X14 are v3's cross-version cases moved one version up: v3 records, captures, lifecycle and backend captures under
the v4 model ("not a v4 …"), and v4 data under the v3 schema (each must include the version-discriminator errors). X15
adds the low-port positive under the v3 schema.

A v4 enrollment needs a maintenance reboot and fresh nonces against every earlier version: its boot ID differs from
every retained v1, v2 and v3 record, and no v1, v2 or v3 nonce appears anywhere in v4 data. Predecessors must be valid
under their pinned schemas, or all three histories must be attested empty. M01-M14 are v3's cases, replayed with an
empty v3 history; M15-M22 add the v3 history (a full history, a v3-boot enrollment, reused v3 run and capacity nonces, a
v3 nonce elsewhere in the profile, an invalid v3 predecessor, a v3-only host and attested-empty history with v3
records).

## Representation choices (author's, for the contract review)

The design fixes the rules; these encodings are the author's and are flagged for review:
1. The entrypoint constants are record fields with schema `const` values (`executableLabel`, `interpreterLabel`),
   compared by the model with the file rows, rather than schema conditionals on file paths, because backend executable
   paths are not constants.
2. The observer's own capture keeps `process` and `cgroupMembers` with cgroup-level content only: `process.cgroup` holds
   the inode and limits read at the record's cgroup path, without the path (a process-level fact), and each member row
   holds only the pid that `cgroup.procs` lists.
3. The member sets and the frozen bracket are capture fields (`memberSetBefore`, `memberSetAfter`, `cgroupFrozenBefore`,
   `cgroupFrozenAfter`); each read is keyed by `(pid, startTicks)` and `(tid, start)`, lists each key once, and its
   member keys must equal the reported members' keys, with their thread counts.
4. An unfrozen WORKER capture is refused by `check_capture` itself, so `check_qualification` refuses it and no
   member-level claim survives.
5. The seal marker label inside each P1 capture's `hardeningObserved` leaves the capture too (T04-LABELS); the rest of
   `hardeningObserved` keeps v3's equality (OUT_OF_SCOPE_HOST).
6. "One file per component" is by executable path (G20's identical content stays I06's SC08); `t04Proofs` is an exact,
   ordered constant.
7. The new record rules run after v3's ownership rules, so every v3 record negative keeps its refusal.
8. `sliceMembers` and `delegatedServiceMembers` keep v3's row shape: both must be empty.
9. The capture class table is also published as data, the schema constant `evidenceClasses`, for the layer validator.
10. Enrolled file labels are canonical contexts in the schema and are compared by type in the model; the census reads
    the backend exec types from the schema's component constants, the one place the model reads a constant from the
    schema it pins.

## Adopted v3 text (effective, W02 notes errata)

The sections below are the effective v3 README's rule sections, verbatim. They remain v4's text for every v3 rule that
v4 keeps. v4 replaces: P1's running-image row for LABEL_BOUND targets and the observer (Classes table above); caller
obligation 3 (the inspector obligation above); and, in the W02e label-slot row, the seal marker and pin labels inside
captures (now declared; the record's slot constants are unchanged).

### What v3 changes

| Item | v3 rule | Vectors |
|---|---|---|
| P1: role closures | No declared closure lists another role's executable, by path or by content (sha256 or verity); only the role's own executable may appear. A native-only role (`interpreterPath` null: OBSERVER, BROKER, EFFECT_GATE) lists no enrolled interpreter, by path or content, and nothing from the interpreter's installation tree `/opt/planeon/python/`, by path or by content: a copy of a tree file elsewhere is refused too. A native-only role therefore shares no byte string with any file under the tree, including non-Python libraries the tree bundles (OpenSSL, libffi, zlib); W03 links Python against shared copies outside the tree rather than bundling them. A Python runtime the record does not carry under the tree (other bytes, installed elsewhere) is not recognised by the data; it would need that role's own enrolled binary to load it. | V01-V06, V46, V55; A05 |
| P1: running image | Each role capture records the process image (`/proc/<pid>/exe`: path, device, inode) of the inspected process and of every cgroup member. Each must be the role's interpreter if it has one, otherwise its executable, with the device and inode observed for that file. Across all role captures, one (device, inode) names one path with one content, and one path one (device, inode). For the interpreted roles (SERVER, WORKER) the script is declared, not observed: the image is the interpreter. | V07-V09, V43-V45 |
| P3: census and captures | `check_qualification` refuses a census entry below any role cgroup. The direct children of `planeon-capacity-broker.service` must be exactly `broker` and `probe-worker`. The slice, the broker service and every role cgroup must be reported populated: each holds a captured process. Census paths must be canonical, and every listed cgroup's parent must be listed. | V10-V17, V41 |
| P4: one process, one report | (pid, start ticks) is unique over every role cgroup member and every backend process. | V18 |
| P5: the slice's own members | The lifecycle capture lists the processes directly in `planeon.slice` (`cgroup.procs`), required empty. This is observed rather than inferred from cgroup v2's no-internal-process rule. | V19 |
| P6: tasks and `pids.max` | Each cgroup member reports its thread count. The capture reports the role cgroup's `pids.current`, which must equal the members' total and not exceed `pids.max` (the pids controller counts tasks, and a role cgroup has no descendants). The positives' SERVER `pidsMax` is now 16 for its 4 threads. | V20-V22 |
| P7(a): fixture profile | Implementation profiles carry `testOnly`. `unit-distribution` is bound to `testOnly: true`, and `check_qualification` refuses a test-only profile unless the caller passes `test_fixture=True`. No production profile exists until W03 adds one through a reviewed schema revision. | V24, V25 |
| P7(b): type names | The confined backend types are fixed per component: `qualk8s_apiserver_t`, `qualk8s_datastore_t`, `qualk8s_controller_manager_t`, `qualk8s_scheduler_t`, `qualk8s_kubelet_t`, `qualk8s_runtime_t` (CONTAINER_RUNTIME), `qualk8s_proxy_t` (SERVICE_PROXY) and `qualk8s_netpol_t` (NETWORK_POLICY_AGENT). That they are confined is a W02e/W03 policy obligation. | unchanged R61-R66 |
| P7(c): nested backend cgroups | No backend cgroup lies inside another backend cgroup. | V23 |
| Network-policy agent identity | Each backend component's `apiIdentities` lists the identities of the reviewed W02g closure that the component holds, by holder: a subset of those names, not every identity it authenticates as (controller service accounts outside the closure are not listed). KUBELET may also use one `system:node:<node name>`, and DATASTORE and CONTAINER_RUNTIME have none. The fixture's agent is now the host-component user `planeon:netpol-agent`. | V26-V28, V51; A07 |
| W02e label slots | The schema fixes the W02e values: each role cgroup's label (`planeon_cgroup_server_t`, `_observer_t`, `_broker_t`, `_worker_t`, `_gate_t`), `planeon_bpf_pin_t` for every pin and `planeon_seal_t` for the seal marker. | V29-V32 |
| W02e E1: effective-program census | Each role capture reports the effective program IDs (BPF_PROG_QUERY with BPF_F_QUERY_EFFECTIVE, command 16, already in the reader set) for every other cgroup attach type of Linux v6.12 (22 types, listed below), each required empty. The seven containment hooks are observed per hook as in v2. | V33-V36 |
| W02e K1: boot entries | The record pins the enrolled and the maintenance boot entry: the loader entry ID and the kernel command line as `/proc/cmdline` reports it for that entry (for a systemd-boot v256 type #1 entry, `initrd=<path>` followed by the entry's options). The entry IDs must differ. The command line contains no quote character and is split on single spaces. Every word of the enrolled entry must be one of `initrd=<path>`, `root=UUID=`/`PARTUUID=`/`LABEL=<id>` or `root=/dev/<name>`, `ro`, `rw`, `security=selinux`, `selinux=1`, `enforcing=1`, `lockdown=integrity`, `quiet` and `loglevel=<0-7>`, and `lockdown=integrity` must be present (W01 §5.2 S1). The maintenance entry is the enrolled entry with `systemd.unit=planeon-maintenance.target` added exactly once and nothing else changed. What this guarantees, in decision 2's terms: no word of either entry names a unit or carries a unit-bearing value, apart from the maintenance entry's own unit word; `root=`, `ro` and `rw` only drive systemd's fixed root-mount units (in a systemd initrd, `root=` makes the fstab generator write `sysroot.mount` and, for a device path, `systemd-fsck-root.service`, and turns off gpt-auto root discovery; `ro` and `rw` set `sysroot.mount`'s mount flag, and on the host they suppress gpt-auto's remount drop-in); no allowlisted word reaches init's arguments; the two command lines differ only by the maintenance unit word, so both name the same `initrd=` files and the same `root=` device, in the same order; and SELinux and lockdown can only be enabled. The kernel image or UKI that an entry loads is not on its command line, so the binding does not fix it (K1 statement). Refused, among others: `--` and every later word, every `systemd.*`, `rd.*` and `SYSTEMD_*` word, runlevel words, `rootflags=` (`x-systemd.*` options add initrd unit dependencies; `subvol=` and `X-mount.subdir=` pick another tree), `rootfstype=`, `console=` (systemd's getty generator adds a serial login getty; W03 may admit it through review, ordered after containment per W01 §5.2 S2) and any `selinux=`, `enforcing=` or `lockdown=` value other than the enabling one. On a kernel built without the handler of an allowlisted key, that word reaches init's environment, where it is an inert name for systemd: `selinux=`, `enforcing=` and `lockdown=` without the SELinux boot-parameter, SELinux develop or lockdown LSM handlers, `initrd=` without `CONFIG_BLK_DEV_INITRD` and `security=` without `CONFIG_SECURITY`. No allowlisted bare word reaches init's arguments, because the `ro`, `rw` and `quiet` handlers are always built. The grammar is widened only through a reviewed revision of this contract (`KERNEL_PARAMETERS` in the model). On a non-confidential VM, systemd-boot v256 appends the SMBIOS string `io.systemd.boot.kernel-cmdline-extra` to the command line of a type #1 entry with a `linux` key, and systemd-stub appends `io.systemd.stub.kernel-cmdline-extra`, regardless of Secure Boot. Those words appear in `/proc/cmdline`, so they are part of both declared entries and must be inside the grammar; the hypervisor controls that part of the bound text. Every role and lifecycle capture reports the boot entry it observed (`entryId`, and SHA-256 of the command line text without its trailing newline), which must be the enrolled one. | V37-V40, V42, V47-V49, V52-V54, V57-V76; A08, A09 |

**Counts row, reworded (P5).** The lifecycle capture counts processes per planeon domain. The containment domain must be
0, and each role domain must equal its role cgroup's membership, so no role-domain process exists outside its role
cgroup. The policy-writer count is informational: writer processes run outside the slice by design (decision 8 of v2).

**K1 statement.** The maintenance domain is a trusted installer. With `load_policy` and boolean preservation it can reach
any boolean state, so v2's boolean pins alone cannot tell a maintenance boot from an enrolled one. The recorded boot
entries tell an honest maintenance boot apart, within these limits:
- the two entries are declared data, not tied to the installed loader configuration;
- `LoaderEntrySelected` is a volatile EFI variable with runtime access, so a privileged domain could rewrite it; the
  command line in `/proc/cmdline` is fixed for the boot, and the two command lines must differ;
- `kernelCmdline` is the `/proc/cmdline` text, which may include bootconfig keys and init arguments;
- the enrolled entry names no unit, so systemd starts the installed default target. Which units start is otherwise
  installed and firmware state, which W03 must fix and T04 check:
  - the root tree's `default.target` link, unit aliases, generators and its init binary;
  - the initramfs contents and its own command-line handling;
  - the kernel image or UKI that each entry loads (the type #1 `linux` or `efi` key), which the command line
    does not name: its built-in initramfs, which the kernel unpacks before the `initrd=` files; a UKI's embedded
    `.initrd`; under Secure Boot, a UKI's embedded `.cmdline`, which replaces the loader options; and its addons;
  - systemd-stub's sysext and confext sidecars (`/.extra/sysext`, `/.extra/confext`), which an initramfs that
    ships `systemd-sysext.service` or `systemd-confext.service` merges;
  - a network root: `root=/dev/nfs` is inside the grammar and hands root selection to the initramfs;
  - without Secure Boot, every word of the `SystemdOptions` EFI variable (`systemd.unit=`, `systemd.wants=`,
    `systemd.mask=`, credentials and root mount options alike);
  - system credentials that define units or drop-ins (`systemd.extra-unit.*`, `systemd.unit-dropin.*`) from SMBIOS
    type 11 strings and qemu fw_cfg, which systemd v256 imports regardless of Secure Boot; and from
    `/.extra/credentials` and `/.extra/global_credentials` (from `\loader\credentials`), which systemd-stub
    packs (systemd-boot v256 packs none) and systemd v256 imports into the encrypted, untrusted credential
    directory, so they take effect only if they decrypt; a credential sealed with systemd's null key, which
    anyone able to write the ESP can produce, decrypts unless the machine has a TPM2 and Secure Boot is on;
- nothing is measured. Measuring the entry and command line (TPM event log) is a T04 obligation.

The observed `hardening.lockdown` value, pinned to `integrity`, remains the evidence of the lockdown state itself.

**E1 census, scope.** Every process inside the planeon slice is in a role cgroup: the slice's and the broker service's
own members are observed empty, unenrolled slice cgroups must be unpopulated, and the census must list every live
descendant of the slice (its `cgroup.stat` `nr_descendants`). Task-selected programs (DEVICE, SYSCTL, LSM on the current
task) are therefore effective at the role cgroup. Socket-attached programs (INGRESS/EGRESS, SOCK_OPS, the sock_addr and
sockopt types, LSM socket hooks) select by the cgroup the socket was created in, so the census covers sockets a role
creates in its role cgroup. A descriptor created elsewhere and passed in (socket activation, SCM_RIGHTS) or created
before a cgroup move is out of this census; W03 must not hand planeon roles such sockets. The policy writer runs outside
the slice by design and is not covered. This narrowing of owner decision E1's "every planeon cgroup" to role cgroups
(decision 3) will be carried to W03 and T04 in the status record written when this contract is adopted; W02e's adopted
status record is not changed. It sees only cgroup attachments, and only when it
runs. The runtime's other BPF use, and attachments made and removed between census points, rest on W03 runtime
selection and T04 (W02e owner decision E1).

#### Cgroup attach types (Linux v6.12)

The list comes from `to_cgroup_bpf_attach_type` in `include/linux/bpf-cgroup.h`, plus `BPF_LSM_CGROUP`, whose
effective query spans the ten LSM slots (`kernel/bpf/cgroup.c` `__cgroup_bpf_query`). The source files are tag v6.12,
read as published:

| File | SHA-256 |
|---|---|
| `include/uapi/linux/bpf.h` | `7d67e542c00f833a99b4c4e465aa3bc6bc785bc490d4969e879e931907af4807` |
| `include/linux/bpf-cgroup.h` | `c0b27f271619c1b2ab6b15b6572c0b6db472e676ac08017db6b589452cdc5319` |
| `include/linux/bpf-cgroup-defs.h` | `724cf75eb56d6069abb00b09d36c6109548ea8f11a83c24930d8ee75ca37bf5c` |
| `kernel/bpf/cgroup.c` | `362592cccd78cc900f93a3662c14aae836d12687baff024b1c8650e8f2610afa` |

The seven containment hooks are BPF_CGROUP_INET_SOCK_CREATE, INET4_BIND, INET6_BIND, INET4_CONNECT, INET6_CONNECT,
UDP4_SENDMSG and UDP6_SENDMSG. The census covers the other 22:

| Group | Attach types |
|---|---|
| Socket and SKB | INET_INGRESS, INET_EGRESS, SOCK_OPS, INET_SOCK_RELEASE |
| Bind, connect and send | INET4_POST_BIND, INET6_POST_BIND, UNIX_CONNECT, UNIX_SENDMSG |
| Receive and names | UDP4_RECVMSG, UDP6_RECVMSG, UNIX_RECVMSG, INET4_GETPEERNAME, INET6_GETPEERNAME, UNIX_GETPEERNAME, INET4_GETSOCKNAME, INET6_GETSOCKNAME, UNIX_GETSOCKNAME |
| Other | DEVICE, SYSCTL, GETSOCKOPT, SETSOCKOPT, BPF_LSM_CGROUP |

All names except BPF_LSM_CGROUP take the `BPF_CGROUP_` prefix.

### Decisions made in this contract

1. The process image is observed through `/proc/<pid>/exe`. An interpreted role's image is its interpreter.
2. Boot-entry observation is loader-reported, not measured (T04 measures). The maintenance entry selects
   `planeon-maintenance.target` with `systemd.unit=`; W01 leaves the mechanism open, and W02e K1 names the systemd target.
   The command line has a closed grammar of kernel parameters that neither name units nor carry unit-bearing values,
   and the maintenance entry is bound to the enrolled one. The guarantee is limited to the command line; which units
   start is installed and firmware state (rounds 2-5).
3. The effective census covers role cgroups only. Every other planeon cgroup is observed to hold no process.
4. Test-only implementation profiles qualify only in an explicit fixture call.

## Not claimed

No real kernel, SELinux policy, bpffs, cgroup, boot loader or TPM was observed, and no capture route was exercised on a
host. The kernel facts come from the reviewed W01, HS43 and matrix v5 texts and stay T04 obligations. The exact seccomp
filters (W02d), the backend policy module and the distribution (W03), the production backend profile (W02-PROD), and
native, installation and tenant acceptance remain separate.

## Open items

- The edge record `../artifact-edges/operator-harness-engineering-v5.json` registers this contract's files with
  `providerPacket` `TBD`: the packet id is assigned with the slot at adoption.
- v4's layer validator (packet mechanics) cross-checks the label constants against matrix v5 and the `evidenceClasses`
  constant against the model.
- The status record is written when this contract is adopted.
- The roadmap edit (W02-PROD's O-NATIVE-GATE-NOCAP step moves to this item) is the lane monitor's.
- The review records are added to this directory with the status record at adoption; the round-1 subject is commit
  `0a2ecd7157e732b8d7965ed6e985203e733b1d19` and the round-2 subject `3c34a3a5ff5879d2bcf5e6691bc08eeaf59dbf41`.
- Not done (optional in N1-1): refusing matrix v5's other ENTRYPOINT types (`planeon_maint_exec_t`,
  `qualk8s_container_file_t`) on enrolled files; the model does not pin the matrix file.

## Contract review round 1 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| N1-1 second entry files inside the inventory | MAJOR | New `check_record` rule, the in-set half of the census: each entrypoint or exec type labels only its own subject's executable, and `planeon_interpreter_exec_t` only files of the interpreted closures, never an executable or a file in a native, lifecycle or backend closure. N103-N109 are the reviewer's probes (a)-(g); N110 adds an interpreter-type file shared with the gate. P-b, T04-ENTRYPOINT-CENSUS and "Entrypoints and labels" say which half is the model's. No I06 v3 vector changes: no I06 case reaches the new rule |
| N1-2 member sets not keyed | MAJOR | `_member_sets` keys each read by `(pid, startTicks)` and `(tid, start)`, refuses a key (or a tid) listed twice (`member set lists a process or thread twice`), compares the keyed reads, and requires their member keys to equal the reported members' keys and their thread counts. N111-N117 (a duplicated member with another omitted inside the frozen bracket, a member listed twice with different thread lists, the no-fork roles and the broker); N87's refusal now names the duplicate rule |
| N1-3 forbidden fields with a different value | MINOR | N118-N191 add every missing half: different values of the LABEL_BOUND targets' maps, namespaces and member images (and the worker's image), equal and different values for the observer's image, maps, namespaces, member image, process-level and member fields, the declared labels in programs, file entries and `hardeningObserved`, and the frozen flags and member sets outside the worker leaf. The "Capture shapes" sentence names the cases |
| N1-4 `user_namespace` version | NOTE | Not asserted: kept as an author's reading for T04 to verify, with both readings named |
| N1-5 I06 v3 README sentence on v2's binding | NOTE | I06 v3's README restores v2's sentence (bound to W02a v3) and adds v3's (bound to W02a v4) |
| N1-6 edge v4 not yet merged | NOTE | README-v5 states that the mechanics re-check edge v4's merged digest and its 45 rows and re-derive v5 if they differ, alongside the six `providerPacket` values |

## Contract review round 2 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| N2-1 the census compared whole label strings | MAJOR | Both parts: (a) the schema admits only the canonical context `system_u:object_r:<type>:s0` for every enrolled planeon and backend file label, and (b) the model compares the type field in the entrypoint, exec and interpreter rules and in the in-set census. N192-N197 are the reviewer's six probes (another user, an MCS category, role `system_r` on a planeon and on a backend file, the interpreter type with a category, the range `s0-s0`); N198-N200 add non-canonical spellings of a file's own type and of an ordinary type; A16 is the control. "Entrypoints and labels" states the sentence on second entry files as the rule now enforces it |
| N2-2 backend exec types of absent components | NOTE | The census reads all eight backend exec types from the schema's component constants; a type whose component the record does not list labels no file |
| N2-3 I06 v3 README title | NOTE | The title, the status lines and the briefs of both contracts and of the edge record move to round 3 |
