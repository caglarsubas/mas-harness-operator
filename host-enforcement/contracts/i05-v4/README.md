# I05 broker-gate channel v4 — I05-OBSERVED-WORKERS contract (DATA_CHECK_ONLY)

Alpha 2A; 2026-10-16. Status: **CONTRACT_CANDIDATE_ROUND5_AWAITING_INDEPENDENT_REVIEW** (brief: `REVIEW_BRIEF.md`).

v4 succeeds the adopted I05 v3 contract `../i05-gate-channel-v3/` (`planeon.internal.effect-gate-frame/v3`,
ADOPTED_DATA_CONTRACT) and its supplement `../i05-gate-channel-v3-supplement/`. Later layers pin the v3 bytes
(`architecture/enforcement-test-plan/traceability.json`), so v3 and the supplement stay byte-identical. v4 is published
beside them as a model, vectors and README successor. **The wire does not change.** Frames keep the v3 schema and version
string (`planeon.internal.effect-gate-frame/v3`), the outcome mapping is v3's, and there is no new operation, field or
refusal reason. v4 changes one thing: how the gate knows that the worker a BIND_EXECUTION names is the broker's probe
worker.

- **v3** took that from a static configuration list (`observedWorkers`). v3's own source table (README "Where each
  request value comes from") already names the source as KERNEL, "a live member of the broker's probe-worker cgroup".
- **The merged R10 gate** (HE-003D) holds that list empty and refuses a non-empty one, so every production BIND fails
  closed until this successor (owner decision Q-HE3D-2 (a)).
- **v4** defines the observation: the gate reads the kernel at every BIND.

Nothing here opens a socket, reads `/proc` or installs a gate; all E01-E12 stay OPEN_UNPROVEN.

Accepted base: main `5e83b257` (MET-ENFORCE-028, 239 packets). Publication slot 241, after slot 240 merges (lane monitor
sequencing decision SEQ-241-242).

## Files

| File | Content |
|---|---|
| `vectors.json` | `planeon.internal.effect-gate-model-vectors/v4`: v3 inputs pinned by SHA-256, three configurations (OBSERVING and two for the order transcripts), 20 observation transcripts O01-O20 (each with outputs, final snapshot and local observation log), 18 order transcripts OB01-OB18, 9 configuration refusals C01-C09 and 9 model-event refusals M01-M09 |
| `../../scripts/i05_gate_channel_v4.py` | Reference model: the v3 model with the gate's observation (`Gate._observe_worker`), `convert_v3_config`, `replay_observed` and `check_vectors` |
| `../i05-gate-channel-v3/channel.schema.json`, `outcome-mapping.json` | Unchanged; v4 uses them as they are |

The v4 model is a copy of the v3 model with the changes below. The v3-to-v4 diff of `scripts/i05_gate_channel_v3.py` and
`scripts/i05_gate_channel_v4.py` is the review surface. Every function that checks or renders the wire (`decode_frame`,
`check_frame`, `render_request`, `template_digest`, `identity_of`, `check_agreement`) is unchanged.

`check_vectors(vectors, files)` makes 277 checks:

- **v3 replay (221 checks).** Every v3 transcript (120) and supplement transcript (6), with its configuration converted by
  `convert_v3_config`, replays under v4 to the same outputs and final snapshot. Every v3 configuration refusal (5), frame
  check (34), byte check (14) and agreement case (42) gives v3's expected answer.
- **v4 vectors (56 checks).** The 20 observation transcripts, 18 order transcripts, 9 configuration refusals and 9
  model-event refusals.

## What v4 changes

| Area | v3 | v4 |
|---|---|---|
| Worker source | `observedWorkers`, a static list of (pid, start ticks) pairs in the gate's configuration | No list. The configuration lists no workers. The model takes a `kernel` table (`processes`: pid, start ticks, cgroup) that stands for the kernel the gate reads. A configuration with `observedWorkers` is refused (C01). |
| BIND check | (pid, start) in the list, else WORKER_NOT_OBSERVED | The observation below, at every BIND, else WORKER_NOT_OBSERVED |
| Refusal cause | None recorded | A local diagnostic log (`Gate.observations`): pid, start ticks, result and the failing step per observation. It is not the durable journal, not in the snapshot and not on the wire. |
| Model-only events | v3's injections | Also KERNEL_SPAWN, KERNEL_EXIT and KERNEL_MOVE (the kernel moves on), OBSERVATION_FAIL_NEXT {step} (a read fails) and OBSERVATION_RACE_NEXT {after, event} (a kernel event lands between two reads). These are test inputs, never channel frames, and their shapes are closed (M01-M09). |
| Conversion | — | `convert_v3_config`: each v3 `observedWorkers` pair becomes a live process in the probe-worker leaf. |

## The observation

The gate observes only for a BIND that passes every v3 check before it (peer, state, outstanding actions, replay,
generation, binding, certificate, manifest reuse). So the answer to a BIND that fails one of those checks is v3's, whatever
its worker, and nothing is observed for it (order transcripts OB01-OB18). Frame-level refusals (an invalid frame,
CHAIN_BROKEN, CHALLENGE_MISMATCH and the other fatal frame answers) come earlier still: the BIND handler is not reached
(OB01 and OB02 pin one of them, OPENING_FRAME_REQUIRED). The gate holds a directory fd on the cgroup2 mount and one on `/proc`,
and opens every file with `openat` relative to one of them (Q-HE2S-G (b)). It closes every fd the observation opens,
the pidfd included, on every path, a failure path included.

| Step | Read | Pass condition | Failure (local cause) |
|---|---|---|---|
| 1 CGROUP_PROCS | `openat` `planeon.slice/planeon-capacity-broker.service/probe-worker/cgroup.procs` from the cgroup2 root fd, then `read` and `close` | The BIND's workerPid is listed | Unreadable: CGROUP_PROCS_UNREADABLE. Not listed: NOT_A_MEMBER |
| 2 PIDFD_OPEN | `pidfd_open(workerPid, 0)` | A pidfd is returned | ESRCH: PROCESS_GONE. Any other error: PIDFD_OPEN_FAILED |
| 3 STAT | `openat` `<pid>/stat` from the `/proc` fd, `read`, `close`; starttime is field 22 | starttime equals workerStartTicks | Unreadable or malformed: STAT_UNREADABLE. Gone (ENOENT or ESRCH): PROCESS_GONE. Other value: START_MISMATCH |
| 4 CGROUP_RECHECK | `cgroup.procs` of the leaf again, as in step 1 | workerPid is still listed | Unreadable: CGROUP_RECHECK_UNREADABLE. Not listed: NOT_IN_PROBE_WORKER_CGROUP |
| 5 PIDFD_ALIVE | `ppoll` (or `poll` or epoll) on the pidfd requesting POLLIN, with a zero timeout, then `close` the pidfd | The poll returns 0, with no event at all: the held process has not exited | Poll error: PIDFD_POLL_FAILED. Any returned event (POLLIN, POLLHUP, POLLERR or POLLNVAL): PIDFD_EXITED |

Rules:

1. **Race-free identity (Q-I5-3).** A PID number is freed only when its process is reaped (`release_task`, `free_pid`).
   If the pidfd from step 2 shows no exit at step 5, the PID named the held process for the whole span of steps 3 and 4.
   So the start time and membership that the gate read are the held process's.
   - Step 1 runs before the pidfd exists and only selects candidates. Step 4 re-proves membership for the held process.
   - An exit anywhere in the span refuses, even when nothing else takes the PID (O16).
   - A reuse with the same start ticks in the same leaf is caught only by step 5 (O13).
   - Under B6, a reuse of the same (pid, start ticks) before step 2 is the named identity. It would need a PID wrap
     within one clock tick, or a privileged process choosing the PID (`clone3` `set_tid`, or `ns_last_pid`, which need
     CAP_SYS_ADMIN or CAP_CHECKPOINT_RESTORE over the pid namespace) and then getting into the leaf. Only init, the
     broker and, before the seal, containment can write the leaf's `cgroup.procs` (matrix v5 A42, A43); a child forked
     by a leaf member starts in the leaf, and is a member under B4.

   The kernel facts behind this are stated from knowledge of Linux v6.12, not from a run (the author's, confirmed by the
   round-1 review), with the functions named:
   - `pidfd_open` (`pidfd_prepare`) succeeds on a zombie thread-group leader, and refuses a non-leader thread ID with
     EINVAL unless `PIDFD_THREAD` is given.
   - `pidfd_poll` reports readable once the leader has exited and its thread group is empty, for any holder, child or
     not. A zero-timeout poll needs no wakeup.
   - `cgroup.procs` skips a dying leader (`css_task_iter_advance`), so a zombie never passes step 4. A leader that has
     exited while other threads still run is listed and the pidfd is not readable, which correctly counts the process
     as alive.
   - An exec by a non-leader thread keeps the TGID and start time (`de_thread`).

   The model's KERNEL_EXIT stands for exit and reap together. On a real kernel, an exited but unreaped worker stays
   visible to `pidfd_open` and `/proc/<pid>/stat`, so the local cause can differ from the vectors'. For example, O11's
   cause there is NOT_IN_PROBE_WORKER_CGROUP or PIDFD_EXITED until the broker reaps the worker. The wire answer is the
   same.
2. **Membership (Q-I5-4, owner).** The BIND's (pid, start ticks) must be a member. Other members of the leaf do not
   refuse (O02). The BIND's workerPid must be a thread-group ID, because `pidfd_open` without `PIDFD_THREAD` refuses a
   thread ID.

   What `cgroup.procs` lists depends on the leaf's type (`cgroup_procs_start`, `css_task_iter_next_css_set`; v6.12
   knowledge from the round-1 review, matching the cgroup v2 admin guide):
   - **A domain leaf** lists its own thread-group leaders, not those of domain children. A worker in a domain child is
     NOT_A_MEMBER, which fails closed.
   - **A threaded domain** also lists the processes of its threaded descendants.
   - **A threaded leaf** refuses the read with EOPNOTSUPP, giving CGROUP_PROCS_UNREADABLE, which fails closed.

   v4 therefore requires the probe-worker leaf to stay a domain cgroup with no threaded descendants. This is an
   obligation on the broker, and W03/T04 checks it.
3. **A fresh read at every BIND (Q-I5-1).** The gate keeps no worker list and caches no earlier answer.
   - A worker spawned after the generation started is observed at its BIND (O15).
   - A worker that has exited is not (O05).
   - A worker observed at one BIND and then exited (O17), or moved out of the leaf (O18), is refused at the next BIND
     that names it. `check_vectors` requires such a case.
4. **Every failure is WORKER_NOT_OBSERVED (Q-I5-2).** Every step's failure, a kernel read error included, gives the
   existing refusal `{"result": "REFUSED", "reason": "WORKER_NOT_OBSERVED"}`.
   - It is non-fatal: the channel stays OPEN and the generation keeps its state.
   - It is retryable: a later BIND with the same values may bind (O06-O10).
   - It writes nothing durable: the gate's whole snapshot, the durable journal and the failure marker included, is
     unchanged by the refused BIND. `check_vectors` checks this for every refused observation.
   - The cause and the failing step go to the local diagnostic log. The wire answer does not say which step failed.
   - The log is best effort. A failed or full log write is dropped (R10 may count drops). It never becomes a
     STORAGE_FAILURE, never closes the channel and never changes the answer.
5. **Reading and parsing.** The gate reads with plain `read(2)` calls into a bounded buffer and does not size the read
   from file metadata. The gate's runtime base is static musl (W01-AMEND-QW4), where Rust std's `read_to_end` adds
   `fstat` and `lseek`, both allowed; there the risk is an unbounded read, which the bounds below rule out. On a
   linux-gnu build the same call would use `statx`, and glibc's x86_64 `fstat` is `newfstatat`: neither is allowed, and
   the default action would kill the gate (constraint C1). Each file is read until a `read` returns 0, because
   `cgroup.procs` is a seq_file that
   returns about one page per call.
   - **Bounds.** `cgroup.procs` is read to at most 65536 bytes and `stat` to at most 4096 bytes. Content beyond either
     bound is unreadable.
   - **`cgroup.procs`.** One TGID per line, each line ending in a newline. A TGID is ASCII digits with no sign and no
     leading zero. A PID may appear more than once and in any order, and both are accepted. A `0` line (a task outside
     the reader's pid namespace) never matches, because workerPid is at least 2 in the v3 schema. Anything else is
     unreadable.
   - **`stat`.** The gate parses the whole content, not one line, because the command name can contain a newline as
     well as spaces and parentheses. It takes the fields after the last `)`: they are separated by single spaces and end
     in one newline. starttime is the 20th of them (field 22), a decimal integer. Content that does not parse is
     STAT_UNREADABLE.
   - **Fields without ptrace access.** `do_task_stat` prints `start_time` with no permission check. For a reader without
     ptrace access it withholds other fields: for example, it prints `start_code` and `end_code` as 1, and it withholds
     `wchan` and `exit_code`.
6. **Reachable reads only.** The observation reads the leaf's `cgroup.procs`, the worker's ungated `/proc/<pid>/stat`,
   `pidfd_open` and a poll. It does not read `/proc/<pid>/cgroup`, `status`, `exe` or any ptrace-gated entry. It does not
   list directories (`getdents64`), watch files (inotify) or wait on a child (`waitid`).
7. **Cgroup namespace.** Steps 1 and 4 open the leaf by its path below the cgroup2 root the gate holds. A gate whose
   cgroup2 root fd is not the host's root (a private cgroup namespace or mount) reaches another directory, or none. Every
   BIND then fails closed, with CGROUP_PROCS_UNREADABLE or NOT_A_MEMBER.
8. **Pid namespace and procfs (preconditions).** workerPid is the broker's number, so v4 requires the following. W03/T04
   checks them.
   - The gate, the broker and the worker share one pid namespace.
   - They share one time namespace, or at least one boottime offset. `/proc/<pid>/stat` shifts starttime by the reader's
     boottime offset (`do_task_stat`, `timens_add_boottime_ns`), so different offsets give START_MISMATCH at every BIND,
     which fails closed.
   - The gate's `/proc` fd is the procfs instance of that namespace.
   - That `/proc` is mounted with `hidepid=0`. HS43 already requires this for the writer case (O-W03-WRITER-EXE), and
     v4 depends on it more strictly because the worker runs as another uid.

   The kernel basis (v6.12 knowledge from the round-1 review): `pidfd_open` resolves the number in the caller's pid namespace,
   `cgroup.procs` prints numbers in the reader's (`task_pid_vnr`, and 0 for an invisible task), and `<pid>/stat` resolves
   in the procfs instance's (`proc_pid_lookup`).

   Two failures are closed:
   - A gate in a private pid namespace sees `0` or other numbers in `cgroup.procs`, giving NOT_A_MEMBER.
   - Under `hidepid` other than 0 (`noaccess`, `invisible` or `ptraceable`), the other-uid worker's entry is refused
     (`has_pid_permissions`, which requires ptrace access), since the gate holds no capability (matrix v5 A68). The one
     exemption, membership of the mount's `gid=` group, is not given to the gate; W03/T04 checks this. Every BIND then
     fails: STAT_UNREADABLE, or PROCESS_GONE where the entry is invisible. systemd's `ProtectProc=` on the gate's unit
     does this.

   A `/proc` fd of another pid namespace is excluded by precondition, not detected: a step-3 read there could be of
   another process, guarded only by the start-time equality.
9. **Host edges.**
   - **Root fds.** R10 obtains the two root directory fds at start, under C2. The cgroup2 root's own type is host policy
     outside matrix v5, so the gate's dir search there is a W03/T04 check, like the two planeon parents' narrowed search.
   - **The worker's label.** A BIND that arrives before the worker's exec (HS43 W2-W4, the child still
     `planeon_broker_t`) reads `stat` through the gate's `procAccess` to `planeon_broker_t`, which matrix v5 also grants.
     After the exec it is `planeon_worker_t`. A fork's start time does not change at exec.
   - **A replaced leaf.** Steps 1 and 4 open the leaf by path at each BIND, so a leaf the broker removed and recreated
     with the same path and label passes them. Matrix v5's control for this is the readers' census, which refuses a
     replaced leaf whose sealed programs are gone (matrix v5 README, review N8).

## Decisions (verbatim)

- **Q-I5-DECISIONS (2026-10-16).** Owner (Q-I5-4) and lane monitor (owner-delegated Q-I5-1..3), relayed by the lane
  monitor:

  > I05 v4 decisions, 2026-10-16. Owner: Q-I5-4 = (a). The BIND's (pid, starttime) must be a member; other members
  > don't refuse. Monitor (owner-delegated): Q-I5-1 = (a): a fresh read at every BIND_EXECUTION. Q-I5-2 = (a): every
  > observation failure refuses with the existing WORKER_NOT_OBSERVED, non-fatal and retryable, journaled locally, with
  > no wire change. Q-I5-3 = (a): pidfd-confirmed: cgroup.procs → pidfd_open → stat starttime and cgroup check → pidfd
  > still not exited. Defaults B1, B4 and B6 hold as you stated. So I05 v4 is a model, vectors and README successor; the
  > v3 frame schema bytes and its supplement stay byte-identical.

- **B1-B6, as v4 defines them.** The monitor relayed that v4 defines B1-B6 and R10 follows. The author sent B1-B6 with
  defaults (recorded as B-DEFAULTS in the author's decision record). The monitor's text holds the defaults B1, B4 and B6
  "as you stated"; Q-I5-1 and Q-I5-2 decide B2, B3 and B5 as their defaults proposed:
  - B1, the mechanism: `cgroup.procs` plus `/proc/<pid>/stat` starttime, pidfd-confirmed (steps 1-5, Q-I5-3);
  - B2, the timing: a fresh read at every BIND, no cache (Q-I5-1, rule 3);
  - B3, failure: every failure refuses with WORKER_NOT_OBSERVED, non-fatal and retryable (Q-I5-2, rule 4);
  - B4, membership: any member of the leaf may be named; the named one must be a member (Q-I5-4, rule 2);
  - B5, the wire: no change; the frames stay v3 (Q-I5-2);
  - B6, the identity: (pid, starttime) (rule 1).
- **SEQ-241-242 (lane monitor, 2026-10-16).** Slot 241 is I05-OBSERVED-WORKERS (I05 v4, observedWorkers from the
  probe-worker cgroup, KERNEL) in the parallel lane.

- **Q-I5-READINGS (lane monitor, 2026-10-16).** The monitor confirmed v4's reading of two phrases:

  > 241: both readings are correct, so record them as the monitor's confirmations.
  > (i) "Journaled locally" means a local diagnostic log, NOT the I05 durable journal, because that digest is on the wire.
  > (ii) The cgroup check as a second cgroup.procs read with the pidfd held is what I meant. It's within C3 and the
  > leaf-only grant, and it's race-free.

What the two readings mean in v4:
- **"Journaled locally."** The cause goes to the gate's local diagnostic log, not the I05 durable journal. The durable
  journal's digest is on the wire (GENERATION_STATUS `journalDigest`), so a refused BIND writes nothing durable; this
  keeps "no wire change" and the v3 replay. The log's storage, retention and format belong to the R10 implementation.
  The model keeps it as an in-memory list.
- **"Stat starttime and cgroup check."** The cgroup check is a second read of the leaf's `cgroup.procs` (step 4), not a
  read of `/proc/<pid>/cgroup`. It needs no cgroup-path parsing and is not affected by cgroup namespaces.

## Constraints (relayed by the lane monitor as decision texts and published pointers)

| Constraint (SLOT241-FACTS, 2026-10-16) | How v4 meets it |
|---|---|
| C1 "Seccomp allowlists v4 (main), EFFECT_GATE: only syscalls on that allowlist are usable." | The observation's syscalls are `openat`, `read`, `close`, `pidfd_open` and a poll. `openat`, `read` and `close` are in the EFFECT_GATE duty rows (`architecture/seccomp-allowlists-v4/allowlists.json`; `fstat` and `lseek`, which musl's std read adds, are there too). `pidfd_open` is in the row "peers qualified with pidfd, SO_PEERCRED and same-uid /proc reads". `ppoll`, `epoll_*` and (x86_64) `poll` come from the NATIVE_STATIC runtime base. No `getdents64`, `statx`, `newfstatat`, `inotify_*`, `waitid` or `pidfd_getfd`. |
| C2 "Owner Q-HE2S-G (b): the gate opens files only via openat on dir fds (no std::fs opens)." | Every open is an `openat` relative to the held cgroup2-root or `/proc` directory fd. |
| C3 "Matrix v5 (main): only the probe-worker leaf READ, search on its two parents, and procAccess to planeon_worker_t; the worker is other-uid, so only cgroup.procs, stat and status are reachable." | The path walk crosses `planeon.slice` and `planeon-capacity-broker.service` (search only) to the `probe-worker` leaf (READ: `cgroup.procs`). `/proc/<pid>/stat` uses procAccess on `planeon_worker_t`. The `status` entry is not needed. |
| C4 "HS43 precedent (owner Q-HS43-1 (a)): the identity is pid plus the start time from /proc/<pid>/stat, race-free where possible (pidfd); a pidfd for another process needs pidfd_open." | The identity is (workerPid, workerStartTicks), with the start time from `/proc/<pid>/stat` field 22. `pidfd_open` gives the pidfd, and rule 1 makes the reads race-free. |

The monitor also relayed: "Nothing in R10 fixes B1-B6. ... That rule is removed by the R10 packet that adopts your I05
v4. So I05 v4 DEFINES B1-B6, and R10 follows it."

## Vectors

The main configuration is **OBSERVING**:
- v3's ACTIVE, converted: its two workers 4100 (start 900001) and 4200 (900002) become leaf members;
- a third leaf member, 4300 (900003);
- a process outside the leaf, 5100 (800001), in `/planeon.slice/planeon-proxy-server.service`.

The order transcripts also use **OBSERVING_INSPECTING** and **OBSERVING_LATER**: v3's INSPECTING and LATER, converted,
plus only the process outside the leaf (v3's LATER already lists 4300). `check_vectors` refuses a configuration that is
not exactly its v3 source's converted processes followed by the model's listed ones (`V4_CONFIGS`), with the other keys
v3's.

| ID | Case | Result |
|---|---|---|
| O01 | The worker is a live leaf member with that start time | OBSERVED, binds |
| O02 | Another leaf member is named | OBSERVED (Q-I5-4) |
| O03 | A process outside the leaf | NOT_A_MEMBER; the journal digest is unchanged |
| O04 | The right PID with another start time | START_MISMATCH |
| O05 | The worker exited before the BIND | NOT_A_MEMBER |
| O06-O10 | Each step's read fails once; the retried BIND binds | CGROUP_PROCS_UNREADABLE, PIDFD_OPEN_FAILED, STAT_UNREADABLE, CGROUP_RECHECK_UNREADABLE, PIDFD_POLL_FAILED, then OBSERVED |
| O11 | Race: the worker exits after step 1 | PROCESS_GONE at step 2. On a real kernel, an exited worker that is not yet reaped gives NOT_IN_PROBE_WORKER_CGROUP or PIDFD_EXITED instead (rule 1) |
| O12 | Race: after step 1 the PID is reused outside the leaf with another start | START_MISMATCH |
| O13 | Race: after step 2 the PID is reused in the leaf with the same start | PIDFD_EXITED |
| O14 | Race: the worker is moved out of the leaf after step 3 | NOT_IN_PROBE_WORKER_CGROUP |
| O15 | A worker spawned after the generation started | OBSERVED |
| O16 | Race: the worker exits after step 4 | PIDFD_EXITED |
| O17 | The worker observed at one BIND exits; the next BIND (run two) names it | OBSERVED, then NOT_A_MEMBER |
| O18 | The worker observed at one BIND moves out of the leaf; the next BIND names it | OBSERVED, then NOT_A_MEMBER |
| O19 | Race: the held worker exits after step 2, with no reuse | PROCESS_GONE at step 3 |
| O20 | The worker is observed, then the BIND record's write fails | OBSERVED in the log, v3's STORAGE_FAILURE answer |

`check_vectors` requires all of the following:
- Every (failing step, cause) pair the observation can give occurs at least once: eleven pairs (the model's
  `OBSERVATION_OUTCOMES`), and OBSERVED.
- Some transcript refuses, at a later BIND, a worker it observed earlier (Q-I5-1).
- Some transcript's observed BIND fails at its record and keeps its log entry (O20).
- Observation transcripts send unmutated frames.
- Every injection is consumed by the end of its transcript.
- The observation log pairs, in order, with exactly the BINDs that reach the observation: those answered OK,
  WORKER_NOT_OBSERVED or STORAGE_FAILURE (a BIND record that fails after the observation). A BIND answered before it
  has no entry.

**OB01-OB18** pin the order. Each names its v3 source (`from`, an unmutated v3 BIND) and must be exactly that
transcript's prefix, ending in a BIND answered before the observation, with only that BIND's worker replaced. Each answer
is pinned twice, with the two workers the observation would refuse at different steps (`worker`):
- OUTSIDER: the process outside the leaf (5100), refused at step 1;
- WRONG_START: the configuration's first leaf member with a start time that is not its own (900009), listed at step 1
  and refused at step 3.

The checker also requires that, in the kernel at that BIND, the worker would not be observed (not a member, or a member
with another start), that every injection is consumed, and that the answer is v3's. Nothing is observed for that BIND.
Each pair, in order (OUTSIDER first):

| ID | Answer before the observation | From v3 |
|---|---|---|
| OB01, OB02 | Fatal OPENING_FRAME_REQUIRED (a frame-level answer) | T15 |
| OB03, OB04 | Fatal PEER_QUALIFICATION_MISMATCH | T14 |
| OB05, OB06 | NOT_ACTIVE | T37 (INSPECTING) |
| OB07, OB08 | ACTION_OUTSTANDING | T42 |
| OB09, OB10 | EXECUTION_REPLAY | T75 |
| OB11, OB12 | GENERATION_MISMATCH | T13 |
| OB13, OB14 | UNKNOWN_BINDING | T13 |
| OB15, OB16 | CERTIFICATE_MISMATCH | T13 |
| OB17, OB18 | MANIFEST_REUSED | T95 (LATER) |

`check_vectors` requires every answer of `BEFORE_OBSERVATION` to be pinned with both workers. A model that observes
first, or that runs a step-1 or step-3 check before any one of these checks, gives a different answer for one of these
rows and is refused. Other reorderings that no worker in these rows can reveal are not pinned.

**C01-C09** refuse malformed configurations:
- a static `observedWorkers` list;
- a missing, open or non-list kernel table;
- a process with another field;
- a duplicate PID, a boolean PID, a relative cgroup path or a negative start time.

**M01-M09** refuse malformed model events (named M so as not to be read as the E01-E12 claims):
- an exit of an unknown PID;
- a spawn on a live PID;
- open spawn or move shapes, or a move to a relative cgroup;
- an unknown failure step, or a failure injection with another field;
- a race after the last step, or a race carrying a malformed event.

## Spec mapping

| Spec | Encoded by |
|---|---|
| HOST-INTERFACE-DRAFT-002 §7 BIND_EXECUTION (workerPid, workerStartTicks) | The observation; rules 1-4 |
| I05 v3 source table, workerPid/workerStartTicks: KERNEL, a live member of the probe-worker cgroup | Steps 1 and 4, rule 2 |
| Owner Q-HE3D-2 (a): BIND fails closed until the I05 successor | v4 defines the source. R10 removes its empty-list rule when it adopts v4 (monitor). |
| SELinux matrix v5, Q-HE3D-2 grant | Constraint C3, rule 6 |

## Still open

- All E01-E12 and T01-T08. The observation on a real kernel (pidfd and `stat` behaviour, the bounds in rule 5) is native
  work for R10's adoption and T04.
- The local diagnostic log's storage, rotation and access control (R10).
- How R10 adopts v4 and removes its empty-`observedWorkers` rule (R10, relayed by the monitor).
- Wording only, since the syscalls are already allowed. A later seccomp or HS43 revision may reword:
  - the seccomp row "peers qualified with pidfd, SO_PEERCRED and same-uid /proc reads", and HS43 §5.3's EFFECT_GATE row
    with the same words, to cover the gate's other-uid `stat` read;
  - the row labelled for the durable journal and failure marker, which holds the observation's `openat`.
- The host preconditions of rules 2, 8 and 9 (W03/T04):
  - the leaf stays a domain cgroup with no threaded descendants;
  - one pid namespace and one time namespace (or boottime offset);
  - the gate's `/proc` fd is that pid namespace's procfs instance (excluded by precondition, not detected);
  - `hidepid=0`, and the gate outside the mount's `gid=` group;
  - the cgroup2 root's dir search.

## Round-1 findings and dispositions

| Finding | Disposition |
|---|---|
| IR1-1 MINOR, OBSERVING | The README names all four processes (4200 included). `check_vectors` requires exactly v3's converted processes plus `OBSERVING_EXTRA`, and refuses an added, moved or deleted process |
| IR1-2 MINOR, unpinned behaviours | O17 and O18 re-BIND after an observed worker exits or moves out, and `check_vectors` requires such a case. O19 reaches PROCESS_GONE at step 3. The observation log records the failing step, and every (step, cause) pair is required. A caching gate and a step-3 mutant are now refused |
| IR1-3 MINOR, threaded subtrees | Rule 2 states what `cgroup.procs` lists for domain, threaded-domain and threaded leaves, with the kernel functions. The leaf must stay a domain cgroup with no threaded descendants (broker obligation, W03/T04) |
| IR1-4 MINOR, pid namespace and hidepid | Rule 8 states both preconditions, the fail-closed cases, the excluded foreign procfs, the kernel basis, and HS43's `hidepid=0` |
| IR1-5 NOTE, zombies | Rule 1 states the reap, zombie and poll facts. The model documents KERNEL_EXIT as exit plus reap, and O11's real-kernel cause is given |
| IR1-6 NOTE, reading and parsing | Rule 5: read until EOF; duplicate and unordered PIDs accepted; the TGID form; `0` never matches; the whole `stat` content parsed; every fd closed on every path; exact wording on the fields withheld without ptrace access |
| IR1-7 NOTE, host edges | Rule 9 covers the root fds, the worker's label before exec, and a replaced leaf (the census, review N8). "Still open" names the duty-row wording |
| IR1-8 NOTE, confirmations | The monitor's confirmation is quoted verbatim (Q-I5-READINGS) |

## Round-2 findings and dispositions

| Finding | Disposition |
|---|---|
| IR2-1 MINOR, order not pinned | P01-P08 (round 3 renamed them OB02-OB09 and added OB01; round 4 pinned each answer with two workers, OB01-OB18) pin every answer before the observation with a non-member worker. The log is paired only with the BINDs that reach the observation. The observe-first and observe-before-MANIFEST_REUSED mutants are refused |
| IR2-2 NOTE, time namespace | Rule 8: one time namespace or boottime offset, with the kernel basis; different offsets fail closed |
| IR2-3 NOTE, log write failure | Rule 4: the log is best effort; a failed write is dropped and never becomes a STORAGE_FAILURE |
| IR2-4 NOTE, B1-B6 | "Decisions" defines all six, B2, B3 and B5 by the decided Q-I5 answers |
| IR2-5 NOTE, wording | Step 5 passes only on a poll with no event. Rule 1 names `set_tid` and `ns_last_pid`. Rule 8 names the `gid=` exemption and `hidepid=ptraceable` |
| IR2-6 NOTE, E-prefix | The model-event refusals are M01-M09 |
| IR2-7 NOTE | Summary only; no change |

## Round-3 findings and dispositions

| Finding | Disposition |
|---|---|
| IR3-1 MINOR, order rows could be tampered | Each order row names its v3 source and must equal that prefix with only the worker replaced; the worker's non-membership is checked in the kernel at the BIND; injections must be consumed. The mutate, KERNEL_MOVE and unconsumed-injection tampers are refused |
| IR3-2 NOTE, frame-level answers | The README says they come earlier still; OB01 pins OPENING_FRAME_REQUIRED, which is in `BEFORE_OBSERVATION` |
| IR3-3 NOTE, STORAGE_FAILURE after observation | O20, and `check_vectors` requires such a case with its log entry |
| IR3-4 NOTE, poll events | Step 5 requests POLLIN |
| IR3-5 NOTE, C1 pitfall | Rule 5: plain `read(2)` and no metadata; why `read_to_end` and glibc `fstat` would be killed |
| IR3-6 NOTE, Still open | Adds the time namespace, the procfs instance and the `gid=` group |
| IR3-7 NOTE, wording | CAP_CHECKPOINT_RESTORE and forked children (rule 1); O11's real-kernel cause; order rows renamed (P01-P08 became OB02-OB09; OB01 new); the B1-B6 attribution names the B-DEFAULTS record |
| IR3-8 NOTE | Summary only |

## Round-4 findings and dispositions

| Finding | Disposition |
|---|---|
| IR4-1 MINOR, order pinned for one worker kind | Each answer is pinned with two workers, OUTSIDER (refused at step 1) and WRONG_START (listed, refused at step 3): OB01-OB18. The start-first and observe-first-if-listed variants are refused. The README now says exactly what the rows pin |
| IR4-2 NOTE, malformed `from`; mutate | `from` is type-checked before use (ValueError), and its v3 BIND must be unmutated |
| IR4-3 NOTE, musl | Rule 5 is stated for the static musl base (`fstat` and `lseek`, allowed; the bound matters); the C1 row lists the observation's own syscalls |
| IR4-4 NOTE, rename wording | Corrected: P01-P08 became OB02-OB09 and OB01 was new; round 4 doubled them |
| IR4-5 NOTE | Summary only |
