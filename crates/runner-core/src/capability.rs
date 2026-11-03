use std::collections::BTreeSet;
use std::fmt;

use crate::error::RunnerError;

/// A capability a script may request in its manifest header.
///
/// Only declared capabilities are installed into the sandbox, and the manifest
/// is part of the script measurement, so clients can verify exactly which host
/// APIs a script can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// `log(level, msg)` — emit a log record.
    Log,
    /// `state.*` — namespaced in-memory key/value store.
    State,
    /// `clock.*` — coarse wall-clock time (breaks determinism).
    Clock,
    /// `random.*` — CSPRNG access (breaks determinism).
    Random,
    /// `crypto.*` — hash/MAC/KDF helpers.
    Crypto,
    /// `tee.*` — attestation documents.
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

    /// The manifest name of this capability.
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

    /// Parses a capability name, or `None` if unknown.
    pub fn parse(name: &str) -> Option<Capability> {
        Capability::ALL.into_iter().find(|c| c.as_str() == name)
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parsed `@capability` manifest of a script.
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

/// Parses the `@capability` manifest from a script source.
///
/// Manifest lines are `-- @capability <name>` comments which must appear in the
/// leading comment block of the file, before any code. Unknown names and
/// late manifest lines are hard errors so typos cannot silently under-grant.
pub fn parse_manifest(source: &str) -> Result<Manifest, RunnerError> {
    let mut caps = BTreeSet::new();
    let mut seen_code = false;
    for (idx, raw) in source.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix("--") {
            if let Some(pos) = comment.find("@capability") {
                let rest = &comment[pos + "@capability".len()..];
                let name = rest.split_whitespace().next().unwrap_or("");
                if name.is_empty() {
                    return Err(RunnerError::InvalidManifest(format!(
                        "line {}: `@capability` without a name",
                        idx + 1
                    )));
                }
                if seen_code {
                    return Err(RunnerError::InvalidManifest(format!(
                        "line {}: capability manifest must appear before any code",
                        idx + 1
                    )));
                }
                let cap = Capability::parse(name).ok_or_else(|| {
                    RunnerError::InvalidManifest(format!(
                        "line {}: unknown capability `{}` (valid: {})",
                        idx + 1,
                        name,
                        Capability::ALL
                            .iter()
                            .map(|c| c.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                })?;
                caps.insert(cap);
            }
            continue;
        }
        seen_code = true;
    }
    Ok(Manifest { caps })
}
