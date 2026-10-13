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
