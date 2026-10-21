# Contract data provenance (HE-002)

Contract data and contract text copied byte for byte (owner decision A on HE-002 DESIGN revision 3, Q-HE2-A (a)). No
model, validator or other implementation code or comment text is copied (HE-002 PR review round 1, finding R1-1: an
8-word span search of the files HE-002 adds or changes against the I05 and I07 models and validators at `a2eab93`,
contract text excluded, finds no shared span apart from a two-line hashing helper in `tools/gate.py` that HE-001 merged). Source repository `caglarsubas/harness-onion`, commit
`a2eab9365c8663cc1ae23a666e864b821f600fa6`, read with `git show a2eab93:<path>`. One line per file: R10 path, source
path, sha256, bytes.

- `contracts/i05-v3/channel.schema.json` from `architecture/i05-gate-channel-v3/channel.schema.json`, sha256 `3bfee13c9d32e82fe5ab908eb6f716bc11881f9d57b324f8ea4a21a3ad35356f`, 26557 bytes
- `contracts/i05-v3/outcome-mapping.json` from `architecture/i05-gate-channel-v3/outcome-mapping.json`, sha256 `4466f379f1cc669e047cffd8afa5fa88b2cc7648a51e2d38b17f0bd5e2252a3a`, 6832 bytes
- `contracts/i05-v3/vectors.json` from `architecture/i05-gate-channel-v3/vectors.json`, sha256 `ab75d86fe54ade7ee2695ef84b200d0473e14e4112e64e7702032593658763ed`, 817047 bytes
- `contracts/i05-v3/README.md` from `architecture/i05-gate-channel-v3/README.md`, sha256 `f82f43330125640d3ac946d2afc9a1804a21e5e60a7ac4b94e5d6cb6ed2ea3aa`, 33078 bytes
- `contracts/i07-v3/channel.schema.json` from `architecture/i07-policy-write-v3/channel.schema.json`, sha256 `c68721a1002fccc7d6e59eeee9016a0a0f4a7428fad714e5a3d90a362d30ce09`, 22739 bytes
- `contracts/i07-v3/policy-kinds.json` from `architecture/i07-policy-write-v3/policy-kinds.json`, sha256 `4e427204b89959cb855d8641c3fa6f95d358b0b6a6a7730bfc7776adc4a173c0`, 6541 bytes
- `contracts/i07-v3/vectors.json` from `architecture/i07-policy-write-v3/vectors.json`, sha256 `c4c24c5ff15618aa2f0fe0f016011359bc4316220c6e40d5168f9ee24b6f736d`, 470344 bytes
- `contracts/i07-v3/README.md` from `architecture/i07-policy-write-v3/README.md`, sha256 `a8c51a725b99d84351aba7a326196e7078c239ba4e28d3eaec1cf09fb3dca43d`, 12729 bytes
- `contracts/i05-v1/README.md` from `architecture/i05-gate-channel/README.md`, sha256 `dc9aa22017b2cdf71f886fb7890aff3f6e7095b9afc25bd37645cb0dee23b498`, 25927 bytes
- `contracts/i05-v2/README.md` from `architecture/i05-gate-channel-v2/README.md`, sha256 `1cb07cef90b0881c42370d8bbaeea08c6abc48478bed3939286b651601d2cca3`, 30736 bytes
- `contracts/i07-v1/README.md` from `architecture/i07-policy-write/README.md`, sha256 `9e5cb3d1023bc12b9e2643ae42dde5a87640cf04fc8ac1aa88350c65b12ba2dc`, 18817 bytes
- `contracts/i07-v2/README.md` from `architecture/i07-policy-write-v2/README.md`, sha256 `cde20d7fee8661cd9314350849870fe5b0838b7914a60237d0eeb1f5dca39d39`, 12929 bytes

## I05 v3 supplementary vectors (W03-AMEND)

Copied byte for byte from `caglarsubas/harness-onion` commit `93d32e1cc5125b5878f51de31c61ada29e1fa6da` (MET-ENFORCE-024,
W03-AMEND; owner decision Q-HE2-E (b)), read with `git show 93d32e1:<path>`. The file is registered before use in that
commit's edge record `architecture/artifact-edges/operator-harness-engineering.json` (status REGISTERED_BEFORE_USE,
relation BYTE_IDENTICAL, consumer packet HE-002). Its six transcripts (S01-S06) use the v3 transcript format and the v3
ACTIVE configuration of `contracts/i05-v3/vectors.json`; S01-S04 close AF2-I05-1 (plan obligation I05-4).

- `contracts/i05-v3-supplement/vectors.json` from `architecture/i05-gate-channel-v3-supplement/vectors.json`, sha256 `1c00bdb3ea112af6098a09158cce3e4a7a6098c9670f490ead4ca65d8bdbb5ac`, 29077 bytes

## Compiled seccomp programs (HE-002S)

Copied byte for byte from `caglarsubas/harness-onion` `architecture/compiled-filter-programs/programs/`, packet
MET-ENFORCE-025 (slot 232; owner decisions Q-HE2S-1 (a) and Q-HE2S-2 (a)), which publishes all 14 programs recompiled
by its layer with the pinned v3 compiler (`scripts/seccomp_allowlists_v3.py`, MET-ENFORCE-020, `5fab673e`) and checked
against v3's `filterDigests` and `programLengths`. Read at that packet's merge commit
`5da126570973293e1075459efe7cf99038f378c9` (harness-onion PR #186); the two files are unchanged since its first review
round. Both are registered before use in that packet's edge registry record v2,
`architecture/artifact-edges/operator-harness-engineering-v2.json` (status REGISTERED_BEFORE_USE, relation
BYTE_IDENTICAL, consumer packet HE-002S). Each file is the kernel's `struct sock_filter` array, 8 bytes per instruction;
`crates/effect-gate/src/seal.rs` embeds both and installs the running architecture's.

- `contracts/seccomp-v3/EFFECT_GATE.aarch64.bpf` from `architecture/compiled-filter-programs/programs/EFFECT_GATE.aarch64.bpf`, sha256 `0ccbd7d090212fe52d366a2d68515670de40557cbc6fd07531653b404bb7105a`, 1464 bytes (183 instructions)
- `contracts/seccomp-v3/EFFECT_GATE.x86_64.bpf` from `architecture/compiled-filter-programs/programs/EFFECT_GATE.x86_64.bpf`, sha256 `ee85e9d225ad687aec82f83cb7d7c1be95f16df5f68eec5b56ee913d6cd86115`, 1552 bytes (194 instructions)

Since HE-003A2 both files are held, still pinned by `tools/gate.py`, but no longer embedded (owner decision Q-A2-1 (a)):
edge record v3 carries v2's two HE-002S rows as recorded, and its rule that the consumer holds exactly those bytes stays
true. The seal embeds the seccomp-v4 programs below.

## Compiled seccomp programs v4 (HE-003A2)

Copied byte for byte from the harness-onion repository's `architecture/compiled-filter-programs-v2/programs/`, packet
MET-ENFORCE-029 (slot 240, PROGRAMS-REPUBLISH; owner decisions Q-HE3A-1 (c), Q-HE3A-1b (a), Q-HE3D-3 (a) and Q-PR-1..10
(a)), which republishes EFFECT_GATE's two programs from seccomp allowlists v4 (MET-ENFORCE-027, merged as `e7516160`:
v3 plus one rule, EFFECT_GATE may call `readlinkat` only with a non-negative dirfd, `(arg0 & 0x80000000) == 0`), compiled
by v4's pinned model and checked against v4's `filterDigests` and `programLengths`. Each program is MET-ENFORCE-025's v3
program with exactly one 6-instruction block inserted (x86_64 at index 173 for call 267, aarch64 at index 34 for call
78). Read at that packet's merge commit `d2ef7083d241a6bc1adb8ef923cc558d550fcd2b` (harness-onion PR #194, tree
`611553eca1874d86eaff27d5ff9f11ae8b3117c0`, verified locally) with `git show d2ef7083:<path>`, mode 100644. Both are
registered before use in that packet's edge registry record v3, `architecture/artifact-edges/operator-harness-engineering-v3.json`
(status REGISTERED_BEFORE_USE, relation BYTE_IDENTICAL, consumer packet HE-003A2, provider packet MET-ENFORCE-029, consumer
paths exactly these). `crates/effect-gate/src/seal.rs` embeds both and installs the running architecture's.

- `contracts/seccomp-v4/EFFECT_GATE.aarch64.bpf` from `architecture/compiled-filter-programs-v2/programs/EFFECT_GATE.aarch64.bpf`, sha256 `8de80a2b597b84d9f5ace818e76ef15d4b15a5b02013bb479ca4fdf73df3d044`, 1512 bytes (189 instructions)
- `contracts/seccomp-v4/EFFECT_GATE.x86_64.bpf` from `architecture/compiled-filter-programs-v2/programs/EFFECT_GATE.x86_64.bpf`, sha256 `4e516f1682098c90edd568f8f214d3de01b404a2c144104596fc4e3262f6e7a3`, 1600 bytes (200 instructions)

## Compiled OBSERVER programs (HE-004A)

Copied byte for byte from the harness-onion repository's `architecture/compiled-filter-programs/programs/`, packet
MET-ENFORCE-025 (merge commit `5da126570973293e1075459efe7cf99038f378c9`), the same 14-program publication as the
HE-002S section above; seccomp allowlists v4 left the OBSERVER row as v3 had it, so these are the current OBSERVER
programs. Read at harness-onion `d2ef7083d241a6bc1adb8ef923cc558d550fcd2b` with `git show d2ef7083:<path>` (the bytes
are equal at `5da1265`), mode 100644. Both are registered before use in edge registry records v2 and v3
(`architecture/artifact-edges/operator-harness-engineering-v3.json`: status REGISTERED_BEFORE_USE, relation
BYTE_IDENTICAL, provider packet MET-ENFORCE-025, consumer packet "HE-004", consumer paths exactly these). HE-004A
consumes them as HE-004's first part (owner decisions Q-HE4-2 (a), the A/B/C/D split, and Q-HE4A-4 (a): the edge rule
binds bytes, modes and versions, not the packet label). `crates/observer/src/seal.rs` embeds both and installs the
running architecture's.

- `contracts/seccomp-v3/OBSERVER.aarch64.bpf` from `architecture/compiled-filter-programs/programs/OBSERVER.aarch64.bpf`, sha256 `d31c841042de456bb784e8412f61429be7700aea2ffa508af2637283ebcb3707`, 1816 bytes (227 instructions)
- `contracts/seccomp-v3/OBSERVER.x86_64.bpf` from `architecture/compiled-filter-programs/programs/OBSERVER.x86_64.bpf`, sha256 `e793aae5ad04a7c82a67d3f102b837064e645a585b83ace0586169a1746eb25a`, 1904 bytes (238 instructions)

## I05 gate channel v4, the gate's worker observation (HE-003A3)

Copied byte for byte from the harness-onion repository's `architecture/i05-gate-channel-v4/`, packet MET-ENFORCE-030
(the 242nd packet, I05-OBSERVED-WORKERS; owner decision Q-I5-4 (a); Q-I5-1 to Q-I5-3 (a) decided by the lane monitor
under the owner's delegation),
read at its merge commit `fd362f9eb64d6e9928f26fac5e339a50b8dee516` (tree `ffcf45231c9c65f75ad8cd5810e5ff685963b420`)
with `git show fd362f9e:<path>`, mode 100644. v4 has no schema or outcome mapping of its own: its frames are v3's, and
its vectors pin the four v3 files above by sha256, which R10 already holds byte-exact (no v3 file changes). Both files
are registered before use in edge registry record v4, `architecture/artifact-edges/operator-harness-engineering-v4.json`
(W03-PLAN-AMEND-2, MET-ENFORCE-032, merged as `c69e55f8`: status REGISTERED_BEFORE_USE, relation BYTE_IDENTICAL,
provider packet MET-ENFORCE-030, consumer packet HE-003A3, consumer paths exactly these). HE-003A3 replays the vectors
through effect-gate's observation driver and its fake kernel (owner decisions Q-A3-1..15 (a)).

- `contracts/i05-v4/README.md` from `architecture/i05-gate-channel-v4/README.md`, sha256 `b0af1f8784c7e9bcdd3793a1002d1000e222a13e5a7613b50b04ce5a116ed04d`, 32574 bytes
- `contracts/i05-v4/vectors.json` from `architecture/i05-gate-channel-v4/vectors.json`, sha256 `f314610f7ee3feb08533cb535f0a4c19fc991384b852b99a50a1646b0739b1e9`, 141491 bytes

The v4 model is pinned by digest, not copied, and read as specification only where the README is silent (each such
point is listed in `crates/effect-gate/MODEL_DEFINED.md`'s HE-003A3 section), at the same commit:

- `scripts/i05_gate_channel_v4.py`, sha256 `95c690cdb0744833f16fa6ac5372c2d8e3404fde9fb19a8fa4e9a0334246ae0d`, 77323 bytes

## I06 backend profile and admission semantics v3, the observer's RBAC snapshot and ADM-4 (HE-004B1)

Copied byte for byte from the harness-onion repository, each file at the provider commit its edge row names, read with
`git show <providerCommit>:<providerPath>`, mode 100644: the I06 backend profile v2 (`architecture/i06-backend-profile-v2/`,
MET-ENFORCE-012, `4f75dedd20f1ebbe262799651abed8f5ee2fe502`), the I06 backend profile v1 data it keeps reading
(`architecture/i06-backend-profile/`, MET-ENFORCE-006, `fe50b57c0e6b6d5e5732b1b346bbad8727959a6f`) and the admission
semantics v3 (`architecture/admission-semantics-v3/`, MET-ENFORCE-015, `4196dae972f2a2636a5176e2cef440c01bf03a98`). All
ten are registered before use in edge registry record v4, `architecture/artifact-edges/operator-harness-engineering-v4.json`
(W03-PLAN-AMEND-2, MET-ENFORCE-032, merged as `c69e55f8`; read at harness-onion `75669de`, the same bytes, sha256
`e30772ff8826650c46d1a8d384625929975e47f2de5cc9030680b5fdb5e7fc86`): its rows 34-43, status REGISTERED_BEFORE_USE, relation
BYTE_IDENTICAL, consumer packet "HE-004" (the edge rule binds bytes, modes and versions, not the packet label; HE-004B1
is HE-004's second part under owner decision Q-HE4-2 (a)), consumer paths exactly these. Each sha256, length and mode was
checked against those rows before use. `crates/observer/src/contracts.rs` embeds the closure, the writer inventory and
the bootstrap RBAC for the snapshot check; the vectors, criteria, READMEs and the manifest are read by the tests only.

- `contracts/i06-v2/vectors.json` from `architecture/i06-backend-profile-v2/vectors.json`, sha256 `1a5e168f0d8fff233f5072b1440e75a633b38e428f87b2893a96e579122a430e`, 213022 bytes
- `contracts/i06-v2/criteria.json` from `architecture/i06-backend-profile-v2/criteria.json`, sha256 `026206c57d3025c0f0129b6615e46c83d5a8000ddc3288f000a1fe4570050cda`, 10154 bytes
- `contracts/i06-v2/README.md` from `architecture/i06-backend-profile-v2/README.md`, sha256 `553880b957586dbfa50eabc4a99d51735eef2a1b0a82641ea51d8e3ea8cf72eb`, 15911 bytes
- `contracts/i06-v1/identity-closure.json` from `architecture/i06-backend-profile/identity-closure.json`, sha256 `0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb`, 46703 bytes
- `contracts/i06-v1/writer-inventory.json` from `architecture/i06-backend-profile/writer-inventory.json`, sha256 `8e6b3b7565cfc93a61162b84d740cffb2871eb66ab85e8c4e80ac813f1af3077`, 40914 bytes
- `contracts/i06-v1/upstream-bootstrap-rbac-v1.37.1.json` from `architecture/i06-backend-profile/upstream-bootstrap-rbac-v1.37.1.json`, sha256 `7529c2a713af2fb90163175924c264d95f4242d7e0c26b1452c77febb13ed50e`, 88532 bytes
- `contracts/i06-v1/README.md` from `architecture/i06-backend-profile/README.md`, sha256 `ccf952d40b4f6229c0cdea79f976253cd4abb19438c1eebc5794e748a708e4b7`, 19633 bytes
- `contracts/admission-v3/vectors.json` from `architecture/admission-semantics-v3/vectors.json`, sha256 `a3e2dc9818742ae2188e0e83cf91bb833be836115975b3fb23d5f280f6928cc1`, 249833 bytes
- `contracts/admission-v3/README.md` from `architecture/admission-semantics-v3/README.md`, sha256 `c3106482b4ff79649cbef7c65797c6fcd6b64f8419e871ae7d89eecad3ff98ab`, 25310 bytes
- `contracts/admission-v3/admission-manifests/planeon-a2.json` from `architecture/admission-semantics-v3/admission-manifests/planeon-a2.json`, sha256 `1096b3cc71c4fe6b5a17ed61e8bf8c17ee17fcf52b192503534d60aed9ce4741`, 8126 bytes

The models are pinned by digest, not copied, and read as specification only where the READMEs are silent (each such
point is listed in `crates/effect-gate/MODEL_DEFINED.md`'s HE-004B1 section), at harness-onion `75669de` (the same bytes
as at `3cba1171`, the design's read pin):

- `scripts/i06_backend_profile.py`, sha256 `bea3c953573478be5b03ab81b4ebd859da62d1eaa2a1be8f361b9dd39a98555e`, 44806 bytes
- `scripts/i06_backend_profile_v2.py`, sha256 `58ceb7a6817aab512a56f9f2a614868ce27660d174be353c5629cc8de335e426`, 6349 bytes
- `scripts/admission_semantics_v3.py`, sha256 `3db8f51ab55f49dc33cf6f028306bfb6d7aa1c5d7d96f264cfe709dae925ad22`, 38172 bytes

## Native profile v4 (HE-004D1)

Copied byte for byte from the harness-onion repository at `887cbe7` with `git show 887cbe7:<providerPath>`, mode
100644, each sha256 and length checked before use. All four are registered before use in edge registry record v5,
`architecture/artifact-edges/operator-harness-engineering-v5.json` (sha256
`89b47ef8f865b31911eb8da2b08a5a3c22b2d92a62599cb6fdfccbfe7f79e3c0`, 27595 bytes), status REGISTERED_BEFORE_USE, relation
BYTE_IDENTICAL, consumer paths exactly these. The three native-profile v4 rows name consumer packet HE-004D1 and provider
packet MET-ENFORCE-033 (their `providerCommit` is null in the record). `crates/observer/src/contracts.rs`
embeds the v4 schema for the observer's capture checks; the vectors and the README are read by the tests and as contract
text only.

- `contracts/native-profile-v4/qualification.schema.json` from `architecture/native-profile-v4/qualification.schema.json`, sha256 `c3e91c087ebc6a13e8a96a066f80710ac968c8def434d1d1b97415811715ed10`, 93041 bytes
- `contracts/native-profile-v4/vectors.json` from `architecture/native-profile-v4/vectors.json`, sha256 `dede64ab3202a9e28094f062b5dad868c13ca02423e2380af8666ecf2e7a86e6`, 802048 bytes
- `contracts/native-profile-v4/README.md` from `architecture/native-profile-v4/README.md`, sha256 `a4205a5388dc83827bb39670bcc9477b030f29829128abf19f7578321c170174`, 62643 bytes

The native-profile v3 schema's row in the same record names provider commit `a29c93c7` (MET-ENFORCE-010) and consumer
packet HE-004D2. The edge rule binds bytes, modes and versions, not the packet label, and owner decision Q-HE4D1-11 (a)
replays the cross-version cases X12-X14 under the v3 schema's registered bytes, so HE-004D1 is the row's first consumer
under that byte rule (as HE-004B1 consumed rows labelled HE-004); the file at `887cbe7` equals the row (the same sha256 and
length), and HE-004D2 relies on the same bytes. The tests read it only.

- `contracts/native-profile-v3/qualification.schema.json` from `architecture/native-profile-v3/qualification.schema.json`, sha256 `ae5cbb6aa39f4edfa2d9919f25e55bad9ab214a99ca927c5afe7e2d943946ac5`, 78375 bytes

The four rows are unchanged in edge registry record v6 (`operator-harness-engineering-v6.json` at harness-onion
`a3b9e6e7`). The v4 model is pinned by digest, not copied, and read as specification only where the README is silent
(each such point is listed in `crates/effect-gate/MODEL_DEFINED.md`'s HE-004D1 section), at the same commit `887cbe7`; it
pins the schema by the sha256 of its canonical encoding, `3bf244b21f91e30062ad56a7a21f3f0b4554daa71a0c3b624bcac058fee58d80`,
which the observer checks at load:

- `scripts/native_qualification_v4.py`, sha256 `f7c718072d1ffbb9b8bbc310e6141d476ea5f25296f70ff8c1bc9ada3db02387`, 67218 bytes

## Native-profile v5, I06 v3 and the predecessor contracts (HE-004D2)

Phase A: the five rows edge registry record v6 labels HE-004D2,
`architecture/artifact-edges/operator-harness-engineering-v6.json` (sha256
`0ac7c2da62de87837f5a36a967a2c5b9c286ecab2e03f335a8eebbd32df9d24d`, 30225 bytes, MET-ENFORCE-036, read by exact path at
harness-onion `35b733b`), status REGISTERED_BEFORE_USE, relation BYTE_IDENTICAL, mode 100644, consumer packet HE-004D2,
consumer paths exactly these. Each was copied byte for byte with `git show <commit>:<providerPath>` from the local
harness-onion clone and its sha256 and length checked before use: the two predecessor schemas at their rows' provider
commits (`3f52d53c` for v1, `46bcc3e3` for v2), and I06 v3's three files, whose rows name provider packet MET-ENFORCE-033
with a null `providerCommit`, at harness-onion main `35b733b`. None is embedded: `check_migration`'s predecessor schemas
and I06 v3's vectors reach the observer only from its tests (`tools/gate.py`, G-D2-2).

- `contracts/native-profile-v1/qualification.schema.json` from `architecture/native-qualification-inputs/qualification.schema.json`, sha256 `bef248bfa82b234124c014f98e40c5791bced3171bb118b7ed1bb7b8daaf95c3`, 37185 bytes
- `contracts/native-profile-v2/qualification.schema.json` from `architecture/native-profile-v2/qualification.schema.json`, sha256 `55bd641fd229f21e04ec00813bcfe600890584e982e290a210720ac5cb160ab0`, 65003 bytes
- `contracts/i06-v3/vectors.json` from `architecture/i06-backend-profile-v3/vectors.json`, sha256 `4752b648abdd82d21ea622a1b26c721143577478c0a2491204e0d584c1d6f081`, 213011 bytes
- `contracts/i06-v3/criteria.json` from `architecture/i06-backend-profile-v3/criteria.json`, sha256 `752533c57b5f93e4c4158a9c17b52eb88d236a3632ab0b66b669e8f8041f57c7`, 10561 bytes
- `contracts/i06-v3/README.md` from `architecture/i06-backend-profile-v3/README.md`, sha256 `9ee406f43060f266a7b5dd2679aa8352f0815584c45e33d0ab193ea7f90c0c77`, 14910 bytes

The native-profile v3 schema, the sixth row record v6 labels HE-004D2, is already held under the byte rule (the HE-004D1
section above); `check_migration` pins it too. The I06 v3 model is pinned by digest, not copied, and read as
specification only where the README is silent (each such point is listed in `crates/effect-gate/MODEL_DEFINED.md`'s
HE-004D2 section), at harness-onion `35b733b`; the v4 model and I06 v1's model are the ones pinned above:

- `scripts/i06_backend_profile_v3.py`, sha256 `dfb00e90199d436ae63b79261f2e04870d7861cb0f7a424971657a4d777754de`, 18283 bytes

Unit B1: the six rows edge registry record v7 labels HE-004D2,
`architecture/artifact-edges/operator-harness-engineering-v7.json` as merged (sha256
`6af45e361a66331a9ee0216d3eea42f3a17770fd3c7d33e78e2a025d301bfa92`, 31448 bytes, MET-ENFORCE-038, read by exact path at
harness-onion main `27c54605`; it supersedes record v6, `0ac7c2da…`, and holds 62 rows), status REGISTERED_BEFORE_USE,
relation BYTE_IDENTICAL, mode 100644, consumer packet HE-004D2, consumer paths exactly these. Before any byte was copied,
each row's sha256, size, mode, provider path, consumer path and consumer packet were compared with HE-004D2's design and
with the provider's bytes; all six agreed. Each file was then copied byte for byte with `git show <commit>:<providerPath>`
and its sha256 and length checked: native-profile v5's three files at `27c54605` (their rows name provider packet
MET-ENFORCE-038 with a null `providerCommit`), and the three predecessor vector sets at their rows' provider commits
(`3f52d53c`, `46bcc3e3`, `a29c93c7`; owner decision Q-HE4D2-3 (a) widened the record by these three rows).
`crates/observer/src/contracts.rs` embeds the v5 schema, from which the capture validators are built (the record
validator stays native-profile v4's); the vectors and the README are read by the tests and as contract text only.

- `contracts/native-profile-v5/qualification.schema.json` from `architecture/native-profile-v5/qualification.schema.json`, sha256 `70bda12463cee83301bc10fa6285023dc0e07b281a87ca70d44ec746cf262113`, 46190 bytes
- `contracts/native-profile-v5/vectors.json` from `architecture/native-profile-v5/vectors.json`, sha256 `b630c362b20bfa7b362bb2ee28734a403303a0dc54b2d627c11a332b226333a1`, 630987 bytes
- `contracts/native-profile-v5/README.md` from `architecture/native-profile-v5/README.md`, sha256 `76b584ca769f0afdd5142fcf3f96e3b5b2d053a172d5713f970dc77594e77692`, 32146 bytes
- `contracts/native-profile-v1/vectors.json` from `architecture/native-qualification-inputs/vectors.json`, sha256 `cd1be009b721bb596887335184a33ab8e1f24aed8215477b63e28f058110748f`, 212215 bytes
- `contracts/native-profile-v2/vectors.json` from `architecture/native-profile-v2/vectors.json`, sha256 `6d58d1f36b7bce5739b94dd89512d358b96878c70e1de7cf8f399050b881b396`, 481933 bytes
- `contracts/native-profile-v3/vectors.json` from `architecture/native-profile-v3/vectors.json`, sha256 `14af47a69c972039294be8659c31332acd5326bfb0a3a38384a2c6bf9d11fe6d`, 560411 bytes

The v5 model is pinned by digest, not copied, and read as specification only where the README is silent, at
harness-onion `27c54605`; it pins the capture schema by the sha256 of its canonical encoding,
`5f6703ca38d0919f6446772e8edd75e92609a9a3971b8cb052b53a7e9ab50393`, which the observer checks at load:

- `scripts/native_qualification_v5.py`, sha256 `d9926f4d18c82a5da31b903fea47c42319d29268a63a26171a7e71aa4c2480a5`, 39747 bytes

## Compiled OBSERVER programs v5 and I06 v4, the observer's I01 listener and role pin (HE-004-I01a)

Unit U1: the two seccomp-v5 OBSERVER rows edge registry record v8 labels HE-004-I01,
`architecture/artifact-edges/operator-harness-engineering-v8.json` (sha256
`623cf10bf19cfba1806f5699007f39c7f6ba38f72d92069548421c4dccd21573`, 33209 bytes, read by exact path at harness-onion
`29c84b36`, MET-ENFORCE-039's merge), status REGISTERED_BEFORE_USE, relation BYTE_IDENTICAL, mode 100644, provider
packet MET-ENFORCE-036 with a null `providerCommit`, consumer paths exactly these. Before any byte was copied, each
row's sha256, mode, provider path and consumer path were compared with DESIGN-I01A section 3; then each file was copied
byte for byte with `git show 29c84b36:<providerPath>` and its sha256 and length checked. They are the OBSERVER programs
of harness-onion's compiled filter programs v3 (seccomp allowlists v5), which add the I01 listener's `bind`, `listen`
and `accept4` to the OBSERVER row. `crates/observer/src/seal.rs` embeds both and installs the running architecture's;
the seccomp-v3 OBSERVER programs above stay pinned and are no longer embedded (Q-P2-3 (a)). HE-004-I01a consumes the
rows labelled HE-004-I01 (the edge rule binds bytes, modes and versions, not the label).

- `contracts/seccomp-v5/OBSERVER.aarch64.bpf` from `architecture/compiled-filter-programs-v3/programs/OBSERVER.aarch64.bpf`, sha256 `887bf07824d7c1e6ec6db991473935d31500e0c78fac345058972a0f777ad184`, 1936 bytes (242 instructions)
- `contracts/seccomp-v5/OBSERVER.x86_64.bpf` from `architecture/compiled-filter-programs-v3/programs/OBSERVER.x86_64.bpf`, sha256 `a20d2a956393b3af72799eaad5fa2c4a3cd82f38bf3842c0dea7c42012e525b9`, 2024 bytes (253 instructions)

Unit U6: two of the four I06 v4 rows of the same record v8, labelled HE-004-I01 (the observer's own pin, Q-RBAC-4 (a)),
status REGISTERED_BEFORE_USE, relation BYTE_IDENTICAL, mode 100644, provider packet MET-ENFORCE-039 with a null
`providerCommit`, consumer paths exactly these. Each row's sha256, mode, provider path and consumer path were compared
with the record before any byte was copied; then each file was copied byte for byte with `git show 29c84b36:<providerPath>`
and its sha256 and length checked. The criteria are read by the replay for their ids only; the vectors drive the
139-case replay (`crates/observer/tests/observer_i01_role_pin.rs`) and hold the role pin's compiled constants
(`crates/observer/src/observer_rbac.rs`) through `tools/gate.py`. The record's other two I06 v4 rows, the role document
`observer-rbac.json` and the README, are HE-008's (its manifest check, RB00, and the objects it provisions) and are not
vendored here.

- `contracts/i06-v4/criteria.json` from `architecture/i06-backend-profile-v4/criteria.json`, sha256 `10aa3a8fe08a930e3a4a13f7a11b38404cd82bd1a12164a40ef13141af37d09a`, 14592 bytes
- `contracts/i06-v4/vectors.json` from `architecture/i06-backend-profile-v4/vectors.json`, sha256 `27aba3bf7296a08b90adef1663d6498fda9ae98499707d0c0950aa6c4ba14eb7`, 150922 bytes

The I06 v4 model is pinned by digest, not copied, and read as specification only where DESIGN-I01A section 10 and the
vectors are silent (each such point is listed in `crates/effect-gate/MODEL_DEFINED.md`'s HE-004-I01a section), at
harness-onion `29c84b36`:

- `scripts/i06_backend_profile_v4.py`, sha256 `7f97acfe9060e79c101f264f5bf61610bf421326c689216cbaf41df7e38e6d2a`, 31161 bytes

## The I01 wire's channel schema and vectors, the observer's request replay (HE-004-I01A2)

HE-004-I01a's unit U7 (DESIGN-I01A sections 3, 7 and 15; owner decisions Q-HE4I1-10 (a), Q-I01A-1 and Q-U7-1..3 (a)):
the two rows edge registry record v9 adds, rows 67 and 68 of
`architecture/artifact-edges/operator-harness-engineering-v9.json` (sha256
`197f30e4e1e0be1dcacd71f1095c91e2333fe9d6ea05b8194578160e471605d7`, 35124 bytes; harness-onion MET-ENFORCE-040, PR #210,
read by exact path from its adopted bytes before that PR merged), labelled HE-004-I01, status REGISTERED_BEFORE_USE,
relation BYTE_IDENTICAL, mode 100644, `providerCommit` `108e61953d522106db7c8de65ee19120a952853b` (each file's last
change, already on harness-onion main, so no provider packet), consumer paths exactly these. Before any byte was
copied, each row's sha256, size, mode, provider path and consumer path were compared with the build brief; then each
file was copied byte for byte with `git show 6835a6ed:<providerPath>` (harness-onion
`6835a6edf7137ba11d4aed4b93c02be4c8694369`, whose bytes of both files are the rows' sha256) and its sha256, length and
mode checked. The vectors drive U7's replay of their request cases, and the schema's request definition is held to
`crates/observer/src/i01_request.rs`'s constants, in `crates/observer/tests/observer_i01_pv_replay.rs`. The vectors'
binding and observation cases also read `architecture/proxy-contract-inputs/vectors.json`, which no edge record
registers, so they are not replayed (edge record v9's replay-scope note).

- `contracts/i01-v1/channel.schema.json` from `architecture/policy-observation-inputs/channel.schema.json`, sha256 `fb69b77201d9b6275a19667a5f5770537f382ddb11309095733628c8430bdc0e`, 41771 bytes
- `contracts/i01-v1/vectors.json` from `architecture/policy-observation-inputs/vectors.json`, sha256 `1bfb46776636f800e38ab6a8f94a0989aa38513fb4a28ef18e61e732a115c124`, 14486 bytes

Not vendored: `docs/alpha-2/POLICY_OBSERVATION_READINESS.md` (sha256 `65778040…`), which MET-REPAIR-010 pins beside
the two files and which states the wire's rules, is deliberately unregistered: a specification document that R10 reads
and cites but does not copy (Q-EV9-1b (a)). The validators are pinned by digest, not copied, and read as specification
only where DESIGN-I01A and the vectors are silent (each such point is listed in `crates/effect-gate/MODEL_DEFINED.md`'s
HE-004-I01A2 section), at harness-onion `6835a6ed`:

- `scripts/validate_policy_observation.py`, sha256 `ed0008be32c75b4b03a74e6361d84b2b2e9a830f19f8d1ae5a00dbf1792c5a44`, 12952 bytes
- `scripts/validate_proxy_contract.py`, sha256 `130194464c6271e8033cda32f166fa07d0dac774f2c48510da28093a3b9ab77e`, 16007 bytes

## NIST CAVP SHA-256 test vectors

Byte-oriented SHA-256 response files from NIST CAVP `shabytetestvectors.zip` (csrc.nist.gov; CAVS 11.0 for ShortMsg and LongMsg, 11.1 for Monte), archive sha256
`929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8`, copied unchanged (CRLF line ends kept):

- `crates/i05-protocol/tests/cavp/SHA256ShortMsg.rsp`, sha256 `75e1cb83994638481808e225b9eb0c1ebd0c232d952ac42b61abce6363be283c`, 10299 bytes
- `crates/i05-protocol/tests/cavp/SHA256LongMsg.rsp`, sha256 `6fac36f37360bcf74ffcf4465c18e30d6d5a04cc90885b901fc3130c16060974`, 426209 bytes
- `crates/i05-protocol/tests/cavp/SHA256Monte.rsp`, sha256 `29ea30c6bb4b84e425fb8c1d731c6bb852dac935825f2bd1143e5d3c4f10bfb9`, 8751 bytes

## Pinned by digest, not copied (DESIGN §1)

At the same commit, read as specification only where the READMEs are silent (each such point is listed in
`crates/effect-gate/MODEL_DEFINED.md`):

- `scripts/i05_gate_channel_v3.py`, sha256 `2c7985b539c0ce8eb79eaabfa1f1ab7d43bdca7515defc590a76ecb1697ca959`
- `scripts/validate_admission_channel_v3.py`, sha256 `7bd762d3069ad6add891063c5b5cd16c75534adb88b1afa245f050b5856dc247`
- `scripts/i07_policy_write_v3.py`, sha256 `6cc7ea0d3df0c7f2966184bb6d322189de3b49b5b02dfe2429911121973afe08`
