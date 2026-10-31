//! HOLD (DESIGN-HE005 section 3.4; the frozen seam note, section 6, "The standing HOLD" and "The derived HOLD"; C3-5).
//!
//! - **The derivation** reads the leaf with no write, at serve's start and before every W1. A read failure counts as
//!   HOLD (`HoldRead`, C3-5), as does a failed open of the leaf's handles at serve's start (SM-R2-2). A populated leaf is
//!   `HoldPopulated`. A frozen leaf is `HoldFrozen`: at each point the derivation runs, no step of this process holds a
//!   freeze (H5F-4's "held by the broker" read as a freeze written by the step now running and not yet released by
//!   it, SM-R2-1), so any frozen leaf is one the broker does not itself hold. A set standing flag over a leaf that reads
//!   empty and unfrozen is `HoldStanding` (SM-R3-1).
//! - **The standing state** is serve-owned (SM-R3-6): the flag, set by every `Held` and `CapacityHeld` outcome and
//!   cleared only by a restart, and the children `Held` keeps, each with its pidfd, for the process's life, with no
//!   further reap. The derivation and the run borrow it. The broker never writes the leaf again while it is set.

use crate::lifecycle::ops::{LeafFile, LeafOps};
use crate::lifecycle::outcome::Step;
use crate::lifecycle::text;

/// serve's standing HOLD: the first step that set it, and the kept children.
pub struct Standing<C> {
    held: Option<Step>,
    kept: Vec<C>,
}

impl<C> Standing<C> {
    /// No HOLD and no kept child: the state at a restart.
    pub fn new() -> Standing<C> {
        Standing { held: None, kept: Vec::new() }
    }

    /// The step that set the standing flag, if it is set.
    pub fn held(&self) -> Option<Step> {
        self.held
    }

    /// Sets the standing flag (a later step keeps the first one's name); only a restart clears it.
    pub fn hold(&mut self, step: Step) {
        if self.held.is_none() {
            self.held = Some(step);
        }
    }

    /// Keeps a child `Held` hands over, with its pidfd, for the process's life; none is ever dropped here.
    pub fn keep(&mut self, child: C) {
        self.kept.push(child);
    }

    /// How many children are kept.
    pub fn kept_children(&self) -> usize {
        self.kept.len()
    }
}

impl<C> Default for Standing<C> {
    fn default() -> Standing<C> {
        Standing::new()
    }
}

/// The derived HOLD (see the module documentation): the step that makes it HOLD, or `None`. `standing` is whether the
/// standing flag is set. No write.
pub fn derive<L: LeafOps>(leaf: &mut L, standing: bool) -> Option<Step> {
    let Some(events) = leaf.read(LeafFile::Events).ok().and_then(|bytes| text::events(&bytes)) else {
        return Some(Step::HoldRead);
    };
    if events.populated {
        return Some(Step::HoldPopulated);
    }
    if events.frozen {
        return Some(Step::HoldFrozen);
    }
    if standing {
        return Some(Step::HoldStanding);
    }
    None
}
