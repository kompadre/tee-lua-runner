use std::collections::BTreeSet;
use std::fmt;

/// A host capability a guest module may import.
///
/// Capabilities are declared by *importing* them: the import section of a wasm
/// module is part of the hashed artifact, so the manifest cannot drift from
/// what the code actually does — a call to an ungranted capability is
/// structurally impossible rather than merely absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// `log.log` — emit a log record.
    Log,
    /// `state.*` — namespaced in-memory key/value store.
    State,
    /// `clock.unix_seconds` — coarse wall-clock time (breaks determinism).
    Clock,
    /// `random.bytes` — CSPRNG access (breaks determinism).
    Random,
    /// `crypto.*` — hash/MAC/KDF helpers.
    Crypto,
    /// `attest.attest` — attestation documents.
    Attest,
}

impl Capability {
    /// Every capability the runner knows, in canonical order.
    pub const ALL: [Capability; 6] = [
        Capability::Log,
        Capability::State,
        Capability::Clock,
        Capability::Random,
        Capability::Crypto,
        Capability::Attest,
    ];

    /// The wasm import module name of this capability.
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::Log => "log",
            Capability::State => "state",
            Capability::Clock => "clock",
            Capability::Random => "random",
            Capability::Crypto => "crypto",
            Capability::Attest => "attest",
        }
    }

    /// Parses an import module name, or `None` if unknown.
    pub fn parse(name: &str) -> Option<Capability> {
        Capability::ALL.into_iter().find(|c| c.as_str() == name)
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The capability set granted to a module (derived from its imports).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    caps: BTreeSet<Capability>,
}

impl Manifest {
    /// Builds a manifest from an explicit capability set.
    pub fn new(caps: impl IntoIterator<Item = Capability>) -> Self {
        Self {
            caps: caps.into_iter().collect(),
        }
    }

    /// Whether `cap` was granted.
    pub fn contains(&self, cap: Capability) -> bool {
        self.caps.contains(&cap)
    }

    /// Whether no capability was granted.
    pub fn is_empty(&self) -> bool {
        self.caps.is_empty()
    }

    /// Iterates the granted capabilities in canonical (sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        self.caps.iter().copied()
    }

    /// Canonical, stable rendering used inside the measurement.
    pub fn canonical(&self) -> String {
        self.caps
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}
