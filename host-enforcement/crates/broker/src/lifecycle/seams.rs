//! Delta C3's two stand-in seams (DESIGN-HE005 delta C3 revision 2, "C's two stand-ins", C3-1 and C3-2; G-HE5C-10):
//! `GateQualifier`, section 3.3 step 2 (qualify the gate on I05 and open the generation's channel), and `Binder`,
//! step 7 (BIND_EXECUTION). In C their production implementations are the two stand-ins below, each answering
//! `core::hint::black_box` of its `Unavailable` value by that value's full path. D replaces both with the I05 client.
//!
//! Each answer's success variant carries a concrete, non-zero-sized, inhabited payload with exact fields, so the
//! compiler cannot prove the success arm dead from the type alone (C3-2): the code past each stand-in stays linked, and
//! G-HE5C-9's markers check it per binary. Each trait has one method, no default body and no other item; the stand-ins
//! are their only implementations outside the test blocks.

/// Step 2's success payload: the gate qualified on I05 and the generation its channel serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateTicket {
    pub generation: u64,
}

/// Step 2's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateAnswer {
    Qualified(GateTicket),
    Unavailable,
}

/// Step 7's success payload: the frozen child the gate bound, by pid and start ticks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindTicket {
    pub pid: i32,
    pub start_ticks: u64,
}

/// Step 7's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindAnswer {
    Bound(BindTicket),
    Unavailable,
}

/// Step 2's seam.
pub trait GateQualifier {
    fn qualify(&mut self) -> GateAnswer;
}

/// Step 7's seam: the frozen child's pid and start ticks, under the qualified gate's ticket.
pub trait Binder {
    fn bind(&mut self, gate: &GateTicket, pid: i32, start_ticks: u64) -> BindAnswer;
}

/// C's step-2 stand-in.
pub struct QualifierStandIn;

/// C's step-7 stand-in.
pub struct BinderStandIn;

impl GateQualifier for QualifierStandIn {
    fn qualify(&mut self) -> GateAnswer {
        core::hint::black_box(crate::lifecycle::seams::GateAnswer::Unavailable)
    }
}

impl Binder for BinderStandIn {
    fn bind(&mut self, _gate: &GateTicket, _pid: i32, _start_ticks: u64) -> BindAnswer {
        core::hint::black_box(crate::lifecycle::seams::BindAnswer::Unavailable)
    }
}
