//! The I06 evidence composition (HE-004D2 DESIGN-D2 section 8; owner decisions Q-HE4D2-6 (a) and Q-HE4D2-7 (a);
//! MODEL_DEFINED R143, R144): the two entry points that take the acceptance tokens of `i06_evidence::check_evidence` and
//! `qualification::check_qualification`. [`compose_fixture`] composes two fixture-minted tokens bound to the same record
//! into [`Composed`]; [`compose_production`] refuses a fixture-minted token and otherwise answers
//! [`Production::Unavailable`] until W02-PROD wires the production composition. A logic module: pure, no panic. Nothing
//! outside the four HE-004D2 modules names it, so `serve` cannot reach it (G-D2-5).
//!
//! The tokens are moved, never copied: each has private fields, `&self` getters only and one literal in its minting
//! function, so only those two checks make a token and nothing here can turn a fixture token into a production one
//! (G-D2-8, D2-1). No production token can exist today: native-profile v4's schema admits only the test-only backend,
//! so `check_qualification` without the fixture flag refuses ("test-only implementation profile"), and I06 v3 refuses
//! every production evidence record. The caller obligations: the profile valid under the pinned proxy profile contract
//! (1) and the complete v1-v3 histories (2) are carried to W02-PROD and HE-008, the inspector obligation (3) is D1's, and
//! the fixture flag (4) is enforced here by the tokens' flags.

use crate::i06_evidence::EvidenceAccepted;
use crate::qualification::QualificationAccepted;

/// The production entry's one answer while the production composition is not wired.
const NOT_WIRED: &str = "W02-PROD";

/// A fixture composition: the record both tokens bind, the evidence record's digest and the record's validity window
/// (Unix seconds). Only [`compose_fixture`] makes one.
#[derive(Debug, PartialEq, Eq)]
pub struct Composed {
    record_digest: String,
    evidence_digest: String,
    valid_from: u64,
    expires_at: u64,
}

impl Composed {
    /// `sha256:` and the hex of the bound record's canonical encoding.
    pub fn record_digest(&self) -> &str {
        &self.record_digest
    }

    /// `sha256:` and the hex of the evidence record's canonical encoding.
    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    /// The record's `validFrom`, in Unix seconds.
    pub fn valid_from(&self) -> u64 {
        self.valid_from
    }

    /// The record's `expiresAt`, in Unix seconds.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// The production entry's answer.
#[derive(Debug, PartialEq, Eq)]
pub enum Production {
    /// The production composition is not wired yet; the reason names the packet that wires it.
    Unavailable(&'static str),
}

/// Why a composition refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositionRefusal {
    /// A fixture-minted token reached the production entry.
    FixtureTokenInProduction,
    /// A token minted without the fixture flag reached the fixture entry.
    ProductionTokenInFixture,
    /// The two tokens bind different records.
    RecordMismatch,
}

/// The fixture entry's decision: both tokens fixture-minted, then the same record.
fn fixture_branch(evidence_fixture: bool, qualification_fixture: bool, same_record: bool) -> Result<(), CompositionRefusal> {
    if !(evidence_fixture && qualification_fixture) {
        return Err(CompositionRefusal::ProductionTokenInFixture);
    }
    if !same_record {
        return Err(CompositionRefusal::RecordMismatch);
    }
    Ok(())
}

/// The production entry's decision: a fixture-minted token refuses; otherwise the composition is unavailable.
fn production_branch(evidence_fixture: bool, qualification_fixture: bool) -> Result<Production, CompositionRefusal> {
    if evidence_fixture || qualification_fixture {
        return Err(CompositionRefusal::FixtureTokenInProduction);
    }
    Ok(Production::Unavailable(NOT_WIRED))
}

/// Composes two fixture-minted tokens bound to the same record. The tokens are consumed.
pub fn compose_fixture(evidence: EvidenceAccepted, qualification: QualificationAccepted) -> Result<Composed, CompositionRefusal> {
    fixture_branch(evidence.fixture(), qualification.fixture(), evidence.record_digest() == qualification.record_digest())?;
    Ok(Composed {
        record_digest: qualification.record_digest().to_string(),
        evidence_digest: evidence.evidence_digest().to_string(),
        valid_from: qualification.valid_from(),
        expires_at: qualification.expires_at(),
    })
}

/// The production entry: refuses a fixture-minted token, and otherwise answers `Unavailable("W02-PROD")`.
pub fn compose_production(evidence: &EvidenceAccepted, qualification: &QualificationAccepted)
                          -> Result<Production, CompositionRefusal> {
    production_branch(evidence.fixture(), qualification.fixture())
}

#[cfg(test)]
mod tests {
    use crate::composition::{fixture_branch, production_branch, CompositionRefusal, Production};

    #[test]
    fn the_production_branch_refuses_every_fixture_token_and_is_otherwise_unavailable() {
        assert_eq!(production_branch(false, false), Ok(Production::Unavailable("W02-PROD")));
        for (evidence, qualification) in [(true, false), (false, true), (true, true)] {
            assert_eq!(production_branch(evidence, qualification), Err(CompositionRefusal::FixtureTokenInProduction));
        }
    }

    #[test]
    fn the_fixture_branch_takes_two_fixture_tokens_of_one_record() {
        assert_eq!(fixture_branch(true, true, true), Ok(()));
        assert_eq!(fixture_branch(true, true, false), Err(CompositionRefusal::RecordMismatch));
        for (evidence, qualification) in [(false, true), (true, false), (false, false)] {
            for same in [false, true] {
                assert_eq!(fixture_branch(evidence, qualification, same), Err(CompositionRefusal::ProductionTokenInFixture));
            }
        }
    }
}
