//! The Lua sandbox and request loop.
//!
//! A [`Runner`] loads one service script into a restricted Lua 5.4 state:
//!
//! * only `table`, `string`, `math` and `utf8` stdlibs are opened (plus the
//!   always-present base library, stripped of `load`, `dofile`, `loadfile`,
//!   `print`, `warn` and `collectgarbage`);
//! * host APIs are installed per declared [`Capability`], and the declaration
//!   is part of the script measurement;
//! * every load/request runs under a wall-clock and memory budget enforced by
//!   an instruction hook which cannot be swallowed by `pcall` (see [`tick`]).
//!
//! The script contract is one global function:
//!
//! ```lua
//! function handle(req)   -- req: JSON-shaped table
//!     return resp        -- resp: JSON-shaped table
//! end
//! ```

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use mlua::{
    Debug, Function, HookTriggers, Lua, LuaOptions, LuaSerdeExt, StdLib, Table, Value, VmState,
};
use rand::RngCore;
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use tee_attest::Attestor;

use crate::capability::{parse_manifest, Capability, Manifest};
use crate::error::{Limit, RunnerError};
use crate::limits::Limits;
use crate::measure::{script_measurement, to_hex};

/// Maximum accepted length of a `log()` message.
const MAX_LOG_MESSAGE: usize = 1024;
/// Maximum accepted length of a `state` key.
const MAX_STATE_KEY: usize = 256;
/// Maximum serialized size of a single `state` value.
const MAX_STATE_VALUE: usize = 64 * 1024;
/// Largest accepted `random.bytes(n)`.
const MAX_RANDOM_BYTES: usize = 4096;
/// Cap on `string.rep` output, to keep one C-level allocation inside budget.
const MAX_REP_BYTES: usize = 4 * 1024 * 1024;

/// A log record emitted by the script via the `log` capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub level: String,
    pub message: String,
}

/// Per-request execution budget.
#[derive(Debug)]
struct Budget {
    start: Instant,
    tripped: Option<Limit>,
}

type HookFn = Box<dyn Fn(&Lua, &Debug) -> mlua::Result<VmState>>;

/// A loaded service script running in a sandbox.
pub struct Runner {
    lua: Lua,
    manifest: Manifest,
    measurement: [u8; 32],
    limits: Limits,
    logs: Rc<RefCell<Vec<LogEntry>>>,
    state: Rc<RefCell<HashMap<String, Json>>>,
    budget: Rc<RefCell<Budget>>,
}

impl std::fmt::Debug for Runner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runner")
            .field("manifest", &self.manifest)
            .field("measurement", &self.measurement_hex())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Runner {
    /// Loads `source` into a fresh sandbox without an attestation backend.
    pub fn new(source: &str, limits: Limits) -> Result<Self, RunnerError> {
        Self::build(source, limits, None)
    }

    /// Loads `source` into a fresh sandbox with an attestation backend.
    pub fn build(
        source: &str,
        limits: Limits,
        attestor: Option<Rc<dyn Attestor>>,
    ) -> Result<Self, RunnerError> {
        let manifest = parse_manifest(source)?;
        let measurement = script_measurement(source, &manifest);

        // Only safe, data-only stdlibs. No io/os/package/coroutine/debug: the
        // script gets no filesystem, environment, process or module access.
        let lua = Lua::new_with(
            StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::UTF8,
            LuaOptions::default(),
        )?;

        // The base library is always opened; strip what must not be reachable.
        let globals = lua.globals();
        for name in [
            "load",
            "dofile",
            "loadfile",
            "print",
            "warn",
            "collectgarbage",
        ] {
            globals.set(name, Value::Nil)?;
        }
        if let Ok(string_table) = globals.get::<Table>("string") {
            string_table.set("dump", Value::Nil)?;
        }

        let logs: Rc<RefCell<Vec<LogEntry>>> = Rc::default();
        let state: Rc<RefCell<HashMap<String, Json>>> = Rc::default();
        let budget = Rc::new(RefCell::new(Budget {
            start: Instant::now(),
            tripped: None,
        }));

        install_log(&lua, &manifest, &logs)?;
        install_state(&lua, &manifest, &limits, &state)?;
        install_clock(&lua, &manifest)?;
        install_random(&lua, &manifest)?;
        install_crypto(&lua, &manifest)?;
        install_attest(&lua, &manifest, &measurement, &attestor)?;
        wrap_string_rep(&lua, &limits)?;

        // Arm the budget hook before loading: top-level script code is budgeted
        // too, so a hostile or buggy load cannot hang the runner.
        let hook = make_hook(budget.clone(), limits.clone());
        lua.set_hook(
            HookTriggers::new().every_nth_instruction(limits.hook_stride),
            hook,
        )?;

        lua.load(source)
            .set_name("@service-script")
            .exec()
            .map_err(|err| match budget.borrow().tripped.clone() {
                Some(limit) => RunnerError::LimitExceeded(limit),
                None => RunnerError::ScriptLoad(err.to_string()),
            })?;

        Ok(Self {
            lua,
            manifest,
            measurement,
            limits,
            logs,
            state,
            budget,
        })
    }

    /// The capability manifest the script declared.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The script measurement (SHA-256, see [`crate::measure`]).
    pub fn measurement(&self) -> [u8; 32] {
        self.measurement
    }

    /// The script measurement as lowercase hex.
    pub fn measurement_hex(&self) -> String {
        to_hex(&self.measurement)
    }

    /// Runs `handle(req)` under the resource budget and returns its response.
    pub fn call_handle(&mut self, request: Json) -> Result<Json, RunnerError> {
        let req_size = serde_json::to_string(&request)
            .map(|s| s.len())
            .unwrap_or(0);
        if req_size > self.limits.max_request_bytes {
            return Err(RunnerError::RequestTooLarge {
                size: req_size,
                max: self.limits.max_request_bytes,
            });
        }

        // Reset the per-request budget and re-arm the normal hook stride.
        {
            let mut b = self.budget.borrow_mut();
            b.start = Instant::now();
            b.tripped = None;
        }
        let hook = make_hook(self.budget.clone(), self.limits.clone());
        self.lua.set_hook(
            HookTriggers::new().every_nth_instruction(self.limits.hook_stride),
            hook,
        )?;

        let handler_val: Value = self.lua.globals().get("handle")?;
        let handler: Function = match handler_val {
            Value::Function(f) => f,
            _ => return Err(RunnerError::NoHandler),
        };

        let req_val = self.lua.to_value(&request)?;
        let resp_val: Value = handler
            .call(req_val)
            .map_err(|err| map_lua_error(err, &self.budget))?;
        let resp: Json = self
            .lua
            .from_value(resp_val)
            .map_err(|err| RunnerError::Script(format!("response is not JSON-shaped: {err}")))?;

        let resp_size = serde_json::to_string(&resp).map(|s| s.len()).unwrap_or(0);
        if resp_size > self.limits.max_response_bytes {
            return Err(RunnerError::ResponseTooLarge {
                size: resp_size,
                max: self.limits.max_response_bytes,
            });
        }
        Ok(resp)
    }

    /// Drains the log records emitted so far.
    pub fn take_logs(&mut self) -> Vec<LogEntry> {
        self.logs.borrow_mut().drain(..).collect()
    }

    /// Snapshot of the script-visible `state` store (for tests/persistence).
    pub fn state_snapshot(&self) -> HashMap<String, Json> {
        self.state.borrow().clone()
    }
}

/// Maps a Lua error to a runner error, preferring the tripped limit.
fn map_lua_error(err: mlua::Error, budget: &Rc<RefCell<Budget>>) -> RunnerError {
    if let Some(limit) = budget.borrow().tripped.clone() {
        RunnerError::LimitExceeded(limit)
    } else {
        RunnerError::Script(err.to_string())
    }
}

/// One hook tick: enforces the wall-clock and memory budget.
///
/// Returns the tripped [`Limit`] plus whether this is the first trip. On the
/// first trip the hook re-arms at stride 1 (see [`make_hook`]), so from then on
/// *every* instruction raises: a script cannot `pcall`-swallow the error and
/// keep making progress, the error always propagates to the host.
fn tick(lua: &Lua, budget: &Rc<RefCell<Budget>>, limits: &Limits) -> Result<(), (Limit, bool)> {
    let mut b = budget.borrow_mut();
    if let Some(limit) = b.tripped.clone() {
        return Err((limit, false));
    }
    let limit = if b.start.elapsed() > limits.max_cpu {
        Some(Limit::Cpu(limits.max_cpu.as_millis() as u64))
    } else {
        let used = lua.used_memory();
        if used > limits.max_memory_bytes {
            Some(Limit::Memory {
                used,
                max: limits.max_memory_bytes,
            })
        } else {
            None
        }
    };
    match limit {
        Some(limit) => {
            b.tripped = Some(limit.clone());
            Err((limit, true))
        }
        None => Ok(()),
    }
}

fn make_hook(budget: Rc<RefCell<Budget>>, limits: Limits) -> HookFn {
    Box::new(
        move |lua: &Lua, _dbg: &Debug| match tick(lua, &budget, &limits) {
            Ok(()) => Ok(VmState::Continue),
            Err((limit, first_trip)) => {
                if first_trip {
                    let hook = make_hook(budget.clone(), limits.clone());
                    lua.set_hook(HookTriggers::new().every_nth_instruction(1), hook)?;
                }
                Err(mlua::Error::RuntimeError(format!("[limit] {limit}")))
            }
        },
    )
}

fn install_log(
    lua: &Lua,
    manifest: &Manifest,
    logs: &Rc<RefCell<Vec<LogEntry>>>,
) -> Result<(), RunnerError> {
    if !manifest.contains(Capability::Log) {
        return Ok(());
    }
    let logs = logs.clone();
    let f = lua.create_function(move |_, (level, message): (String, String)| {
        if !matches!(level.as_str(), "debug" | "info" | "warn" | "error") {
            return Err(mlua::Error::RuntimeError(format!(
                "log: unknown level `{level}` (use debug/info/warn/error)"
            )));
        }
        let message = if message.len() > MAX_LOG_MESSAGE {
            let mut cut = MAX_LOG_MESSAGE;
            while !message.is_char_boundary(cut) {
                cut -= 1;
            }
            message[..cut].to_string()
        } else {
            message
        };
        logs.borrow_mut().push(LogEntry { level, message });
        Ok(())
    })?;
    lua.globals().set("log", f)?;
    Ok(())
}

fn install_state(
    lua: &Lua,
    manifest: &Manifest,
    limits: &Limits,
    state: &Rc<RefCell<HashMap<String, Json>>>,
) -> Result<(), RunnerError> {
    if !manifest.contains(Capability::State) {
        return Ok(());
    }
    let table = lua.create_table()?;

    let st = state.clone();
    table.set(
        "get",
        lua.create_function(move |lua, key: String| {
            check_state_key(&key)?;
            match st.borrow().get(&key) {
                Some(json) => lua.to_value(json),
                None => Ok(Value::Nil),
            }
        })?,
    )?;

    let st = state.clone();
    let max_value = limits.max_response_bytes.min(MAX_STATE_VALUE);
    table.set(
        "set",
        lua.create_function(move |lua, (key, value): (String, Value)| {
            check_state_key(&key)?;
            let json: Json = lua.from_value(value).map_err(|err| {
                mlua::Error::RuntimeError(format!("state.set: value is not JSON-shaped: {err}"))
            })?;
            let size = serde_json::to_string(&json).map(|s| s.len()).unwrap_or(0);
            if size > max_value {
                return Err(mlua::Error::RuntimeError(format!(
                    "state.set: value too large ({size} bytes, limit {max_value})"
                )));
            }
            st.borrow_mut().insert(key, json);
            Ok(())
        })?,
    )?;

    let st = state.clone();
    table.set(
        "delete",
        lua.create_function(move |_, key: String| {
            check_state_key(&key)?;
            st.borrow_mut().remove(&key);
            Ok(())
        })?,
    )?;

    let st = state.clone();
    table.set(
        "keys",
        lua.create_function(move |lua, ()| {
            let mut keys: Vec<String> = st.borrow().keys().cloned().collect();
            keys.sort();
            let t = lua.create_table()?;
            for (i, k) in keys.into_iter().enumerate() {
                t.set(i + 1, k)?;
            }
            Ok(t)
        })?,
    )?;

    lua.globals().set("state", table)?;
    Ok(())
}

fn check_state_key(key: &str) -> mlua::Result<()> {
    if key.is_empty() || key.len() > MAX_STATE_KEY {
        return Err(mlua::Error::RuntimeError(format!(
            "state: invalid key length (1..={MAX_STATE_KEY} bytes)"
        )));
    }
    Ok(())
}

fn install_clock(lua: &Lua, manifest: &Manifest) -> Result<(), RunnerError> {
    if !manifest.contains(Capability::Clock) {
        return Ok(());
    }
    let table = lua.create_table()?;
    table.set(
        "unix_seconds",
        lua.create_function(|_, ()| {
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            Ok(secs)
        })?,
    )?;
    lua.globals().set("clock", table)?;
    Ok(())
}

fn install_random(lua: &Lua, manifest: &Manifest) -> Result<(), RunnerError> {
    if !manifest.contains(Capability::Random) {
        return Ok(());
    }
    let table = lua.create_table()?;
    table.set(
        "bytes",
        lua.create_function(|_, n: usize| {
            if n > MAX_RANDOM_BYTES {
                return Err(mlua::Error::RuntimeError(format!(
                    "random.bytes: max {MAX_RANDOM_BYTES} bytes"
                )));
            }
            let mut buf = vec![0u8; n];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            Ok(buf)
        })?,
    )?;
    lua.globals().set("random", table)?;
    Ok(())
}

fn install_crypto(lua: &Lua, manifest: &Manifest) -> Result<(), RunnerError> {
    if !manifest.contains(Capability::Crypto) {
        return Ok(());
    }
    let table = lua.create_table()?;

    table.set(
        "sha256",
        lua.create_function(|_, data: mlua::String| {
            let digest = Sha256::digest(data.as_bytes());
            Ok(to_hex(&digest))
        })?,
    )?;

    table.set(
        "hmac_sha256",
        lua.create_function(|_, (key, data): (mlua::String, mlua::String)| {
            use hmac::{Hmac, Mac};
            let mut mac = Hmac::<Sha256>::new_from_slice(&key.as_bytes())
                .map_err(|err| mlua::Error::RuntimeError(format!("hmac: {err}")))?;
            mac.update(&data.as_bytes());
            Ok(to_hex(&mac.finalize().into_bytes()))
        })?,
    )?;

    table.set(
        "hkdf_sha256",
        lua.create_function(
            |_, (ikm, salt, info, len): (mlua::String, mlua::String, mlua::String, usize)| {
                if len > 255 * 32 {
                    return Err(mlua::Error::RuntimeError(
                        "hkdf_sha256: max output is 8160 bytes".to_string(),
                    ));
                }
                let hk = hkdf::Hkdf::<Sha256>::new(Some(&salt.as_bytes()), &ikm.as_bytes());
                let mut okm = vec![0u8; len];
                hk.expand(&info.as_bytes(), &mut okm)
                    .map_err(|err| mlua::Error::RuntimeError(format!("hkdf: {err}")))?;
                Ok(to_hex(&okm))
            },
        )?,
    )?;

    table.set(
        "to_hex",
        lua.create_function(|_, data: mlua::String| Ok(to_hex(&data.as_bytes())))?,
    )?;

    table.set(
        "from_hex",
        lua.create_function(|_, data: String| {
            hex::decode(data.trim()).map_err(|err| {
                mlua::Error::RuntimeError(format!("from_hex: invalid hex input: {err}"))
            })
        })?,
    )?;

    table.set(
        "ct_eq",
        lua.create_function(|_, (a, b): (mlua::String, mlua::String)| {
            let (a, b) = (a.as_bytes(), b.as_bytes());
            if a.len() != b.len() {
                return Ok(false);
            }
            let mut diff = 0u8;
            for (x, y) in a.iter().zip(b.iter()) {
                diff |= x ^ y;
            }
            Ok(diff == 0)
        })?,
    )?;

    lua.globals().set("crypto", table)?;
    Ok(())
}

fn install_attest(
    lua: &Lua,
    manifest: &Manifest,
    measurement: &[u8; 32],
    attestor: &Option<Rc<dyn Attestor>>,
) -> Result<(), RunnerError> {
    if !manifest.contains(Capability::Attest) {
        return Ok(());
    }
    let table = lua.create_table()?;
    let attestor = attestor.clone();
    let user_data = *measurement;
    table.set(
        "attest",
        lua.create_function(move |_, nonce: mlua::String| {
            let attestor = attestor.as_ref().ok_or_else(|| {
                mlua::Error::RuntimeError(
                    "tee.attest: no attestation backend configured".to_string(),
                )
            })?;
            let doc = attestor
                .attest(&nonce.as_bytes(), &user_data)
                .map_err(|err| mlua::Error::RuntimeError(format!("tee.attest: {err}")))?;
            Ok(to_hex(&doc))
        })?,
    )?;
    lua.globals().set("tee", table)?;
    Ok(())
}

/// Replaces `string.rep` with a version whose output is bounded, so one C-level
/// allocation cannot blow far past the memory budget between hook ticks.
fn wrap_string_rep(lua: &Lua, limits: &Limits) -> Result<(), RunnerError> {
    let string_table: Table = lua.globals().get("string")?;
    let orig: Function = string_table.get("rep")?;
    let max_bytes = limits.max_memory_bytes.min(MAX_REP_BYTES);
    let wrapper = lua.create_function(
        move |_lua, (s, n, sep): (mlua::String, usize, Option<mlua::String>)| {
            let sep_len = sep.as_ref().map(|s| s.as_bytes().len()).unwrap_or(0);
            let piece = s.as_bytes().len().saturating_add(sep_len);
            let total = piece.saturating_mul(n);
            if total > max_bytes {
                return Err(mlua::Error::RuntimeError(format!(
                    "string.rep: output would exceed {max_bytes} bytes"
                )));
            }
            orig.call::<Value>((s, n, sep))
        },
    )?;
    string_table.set("rep", wrapper)?;
    Ok(())
}
