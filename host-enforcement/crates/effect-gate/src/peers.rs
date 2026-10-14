//! The expected peers of the two channel listeners and the listeners' own constants (HE-003A DESIGN §3 and §4.1,
//! owner decision Q-HE3A-3 (a)): R10 constants, each cited, handed to the substrate as an [`ExpectedPeers`] argument so
//! that a signed or enrolled source (HE-003D, HE-004) can replace them without touching the substrate. T04 confirms
//! them on the real broker and writer.
//!
//! Sources (harness-onion, read at `5da1265`):
//! - The process labels are `architecture/selinux-matrix-v2/matrix.json` `domains[]` entries `planeon_broker_t`
//!   (subject BROKER) and `planeon_policy_writer_t` (subject POLICY_WRITER); the broker's is also the `processLabel`
//!   constant of native-profile-v3's BROKER role (`qualification.schema.json`, `$defs` `roles`).
//! - The uids are `HOST_INTERFACE_SPEC.md` §5.3's BROKER and POLICY_WRITER rows (0). The broker's gid 0 is
//!   native-profile-v3's `$defs/roles/properties/BROKER/properties/gid` constant (§5.3 has a uid column only); the
//!   writer's gid is recorded at accept and compared on every frame.
//! - The broker's cgroup is its leaf: the cgroup v2 line `0::` followed by native-profile-v3's
//!   `$defs/roles/properties/BROKER/properties/cgroup/properties/path` constant without the cgroup filesystem's mount
//!   point (spec §4.2). The line is the one the gate reads from the root cgroup namespace, so HE-008 gives the gate's
//!   unit no private cgroup namespace (T04 confirms). A broker child between W2 and W4 is still `planeon_broker_t` and
//!   may connect, but it runs in the probe-worker leaf, so this check refuses it. The writer's cgroup (an admin
//!   session's, not pinned by W02) is recorded at accept and compared on every frame.
//! - The socket contexts (design review round 1, A11) are the user and level of the matrix's domain labels, the socket
//!   object types of `selinux-matrix-v2` `sockets[].object` (`planeon_i05_socket_t`, `planeon_i07_socket_t`), and the
//!   role `object_r`, which the policy accepts with any type. HE-008 builds the policy for them.
//! - The socket paths are contract candidates (HE-003A DESIGN §3); each socket file's mode comes from the unit's
//!   `UMask=0177` and its type from the policy's named type transitions.

/// The broker's process and socket label (without the NUL the kernel delivers).
pub const BROKER_LABEL: &str = "system_u:system_r:planeon_broker_t:s0";
/// The broker's uid.
pub const BROKER_UID: u32 = 0;
/// The broker's gid.
pub const BROKER_GID: u32 = 0;
/// The broker leaf's cgroup v2 line.
pub const BROKER_CGROUP: &str = "0::/planeon.slice/planeon-capacity-broker.service/broker";

/// The policy writer's process and socket label (without the NUL).
pub const WRITER_LABEL: &str = "system_u:system_r:planeon_policy_writer_t:s0";
/// The policy writer's uid.
pub const WRITER_UID: u32 = 0;

/// The I05 listener's socket context (sockcreate) and path.
pub const I05_SOCKET_CONTEXT: &str = "system_u:object_r:planeon_i05_socket_t:s0";
pub const I05_SOCKET_PATH: &str = "/run/planeon/live-proxy/effect-admission.sock";

/// The I07 listener's socket context (sockcreate) and path.
pub const I07_SOCKET_CONTEXT: &str = "system_u:object_r:planeon_i07_socket_t:s0";
pub const I07_SOCKET_PATH: &str = "/run/planeon/maintenance/policy-write.sock";

/// One listener's expected peer: its label (written without a NUL), its uid, and the gid and cgroup lines it must
/// have, or `None` where they are recorded at accept and compared on every frame after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedPeer {
    pub label: Vec<u8>,
    pub uid: u32,
    pub gid: Option<u32>,
    pub cgroup: Option<Vec<u8>>,
}

/// The expected peers of both listeners.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedPeers {
    pub i05: ExpectedPeer,
    pub i07: ExpectedPeer,
}

impl ExpectedPeers {
    /// The R10 constants above (owner decision Q-HE3A-3 (a)).
    pub fn r10() -> ExpectedPeers {
        ExpectedPeers {
            i05: ExpectedPeer {
                label: BROKER_LABEL.as_bytes().to_vec(),
                uid: BROKER_UID,
                gid: Some(BROKER_GID),
                cgroup: Some(BROKER_CGROUP.as_bytes().to_vec()),
            },
            i07: ExpectedPeer { label: WRITER_LABEL.as_bytes().to_vec(), uid: WRITER_UID, gid: None, cgroup: None },
        }
    }
}

/// One listener's place and socket context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenerPlan {
    pub path: String,
    pub context: Vec<u8>,
}

impl ListenerPlan {
    /// The I05 listener of the constants above.
    pub fn i05() -> ListenerPlan {
        ListenerPlan { path: I05_SOCKET_PATH.to_string(), context: I05_SOCKET_CONTEXT.as_bytes().to_vec() }
    }

    /// The I07 listener of the constants above.
    pub fn i07() -> ListenerPlan {
        ListenerPlan { path: I07_SOCKET_PATH.to_string(), context: I07_SOCKET_CONTEXT.as_bytes().to_vec() }
    }
}
