//! Wasmtime-backed engine: module validation, capability linking, budgets.
//!
//! A [`Runner`] loads one service **module** (wasm binary) into a fresh store
//! per request:
//!
//! * capability manifest = the module's import section (part of the hashed
//!   artifact); unknown modules/fields/signatures are load-time errors;
//! * required exports: `memory`, `alloc(i32)->i32`,
//!   `handle(i32,i32)->i64` (JSON request in, JSON *envelope* out);
//! * budgets: deterministic fuel + epoch interruption (wall clock) + hard
//!   linear-memory cap — all engine-enforced and uncatchable by guest code;
//! * host calls use the uniform ABI `(ptr,len)->i64` (packed `ptr|len`,
//!   little-endian: low 32 bits = pointer) returning a JSON envelope
//!   `{"ok":true,"value":...}` or `{"ok":false,"error":"..."}`.
//!
//! Lock discipline: `HostCtx` is never held across a call into guest code
//! (guest `alloc` can re-enter host imports, and `std::sync::Mutex` is not
//! reentrant).

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::RngCore;
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};
use tee_attest::Attestor;
use wasmtime::{
    bail, format_err, Caller, Config, Engine, Error as WasmError, ExternType, FuncType, Instance,
    Linker, Module, Result as WasmResult, Store, StoreLimits, StoreLimitsBuilder, Trap, TypedFunc,
    ValType,
};

use crate::capability::{Capability, Manifest};
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
/// Largest accepted `hkdf_sha256` output (255 * 32).
const MAX_HKDF_OUTPUT: usize = 255 * 32;
/// How often the epoch ticker advances the wall clock.
const EPOCH_INTERVAL: Duration = Duration::from_millis(25);

/// Every host import the runner offers: capability module -> fields.
/// All host functions share the signature `(ptr: i32, len: i32) -> i64`.
const HOST_IMPORTS: &[(&str, &[&str])] = &[
    ("log", &["log"]),
    ("state", &["get", "set", "delete", "keys"]),
    ("clock", &["unix_seconds"]),
    ("random", &["bytes"]),
    (
        "crypto",
        &[
            "sha256",
            "hmac_sha256",
            "hkdf_sha256",
            "ct_eq",
            "ed25519_verify",
        ],
    ),
    ("attest", &["attest"]),
    ("gate", &["unwrap"]),
];

/// A log record emitted by the guest via the `log` capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub level: String,
    pub message: String,
}

/// Host-side state shared across requests (never persisted).
struct HostCtx {
    logs: Vec<LogEntry>,
    state: HashMap<String, Json>,
    attestor: Option<Arc<dyn Attestor>>,
    measurement: [u8; 32],
    /// Provisioned TEE envelope-unwrap secret (X25519 scalar). Host-side
    /// only — never enters guest memory (Stage 4, `gate.unwrap`).
    tee_key: Option<[u8; 32]>,
}

type SharedCtx = Arc<Mutex<HostCtx>>;

/// Store data: the per-request linear-memory cap.
struct StoreData {
    limits: StoreLimits,
}

/// Advances the engine epoch so wall-clock deadlines fire.
struct EpochTicker {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl EpochTicker {
    fn start(engine: &Engine, interval: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let engine = engine.clone();
        let handle = thread::Builder::new()
            .name("epoch-ticker".into())
            .spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    thread::sleep(interval);
                    engine.increment_epoch();
                }
            })
            .ok();
        Self { stop, handle }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A loaded service module ready to handle requests.
pub struct Runner {
    engine: Engine,
    module: Module,
    linker: Linker<StoreData>,
    manifest: Manifest,
    measurement: [u8; 32],
    limits: Limits,
    ctx: SharedCtx,
    _ticker: EpochTicker,
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

fn engine_config() -> Config {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    config
}

/// Compile a module for measurement/inspection only (no host linking).
pub fn measure_module(module_bytes: &[u8]) -> Result<(Manifest, [u8; 32]), RunnerError> {
    let engine = Engine::new(&engine_config())
        .map_err(|err| RunnerError::Internal(format!("engine init: {err}")))?;
    let module = compile(&engine, module_bytes)?;
    let manifest = derive_manifest(&module)?;
    let measurement = script_measurement(module_bytes, &manifest);
    Ok((manifest, measurement))
}

fn compile(engine: &Engine, module_bytes: &[u8]) -> Result<Module, RunnerError> {
    Module::new(engine, module_bytes)
        .map_err(|err| RunnerError::ScriptLoad(format!("invalid wasm module: {err}")))
}

/// Everything a runner needs besides the module bytes.
#[derive(Default)]
pub struct RunnerConfig {
    /// Per-request resource budgets.
    pub limits: Limits,
    /// Attestation backend for `attest.attest`.
    pub attestor: Option<Arc<dyn Attestor>>,
    /// TEE envelope-unwrap secret (X25519 scalar) for `gate.unwrap`.
    /// Host-side only; never enters guest memory.
    pub tee_key: Option<[u8; 32]>,
}

// Redacted: must not expose key material through Debug.
impl std::fmt::Debug for RunnerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerConfig")
            .field("limits", &self.limits)
            .field("attestor", &self.attestor.is_some())
            .field("tee_key", &self.tee_key.map(|_| "<redacted>"))
            .finish()
    }
}

impl RunnerConfig {
    /// Configuration with explicit limits.
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            attestor: None,
            tee_key: None,
        }
    }

    pub fn with_attestor(mut self, attestor: Arc<dyn Attestor>) -> Self {
        self.attestor = Some(attestor);
        self
    }

    pub fn with_tee_key(mut self, tee_key: [u8; 32]) -> Self {
        self.tee_key = Some(tee_key);
        self
    }
}

impl Runner {
    /// Loads a module with default configuration (no attestor, no TEE key).
    pub fn new(module_bytes: &[u8], limits: Limits) -> Result<Self, RunnerError> {
        Self::build(
            module_bytes,
            RunnerConfig {
                limits,
                ..RunnerConfig::default()
            },
        )
    }

    /// Compiles, validates and links a service module.
    pub fn build(module_bytes: &[u8], config: RunnerConfig) -> Result<Self, RunnerError> {
        let RunnerConfig {
            limits,
            attestor,
            tee_key,
        } = config;
        let engine = Engine::new(&engine_config())
            .map_err(|err| RunnerError::Internal(format!("engine init: {err}")))?;
        let module = compile(&engine, module_bytes)?;
        let manifest = derive_manifest(&module)?;
        check_memory_floor(&module, &limits)?;
        let measurement = script_measurement(module_bytes, &manifest);

        let ctx: SharedCtx = Arc::new(Mutex::new(HostCtx {
            logs: Vec::new(),
            state: HashMap::new(),
            attestor,
            measurement,
            tee_key,
        }));
        let linker = build_linker(&engine, &ctx)
            .map_err(|err| RunnerError::Internal(format!("linking host functions: {err}")))?;
        let ticker = EpochTicker::start(&engine, EPOCH_INTERVAL);

        Ok(Self {
            engine,
            module,
            linker,
            manifest,
            measurement,
            limits,
            ctx,
            _ticker: ticker,
        })
    }

    /// The granted capability manifest (derived from the module's imports).
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The module measurement (SHA-256, see [`crate::measure`]).
    pub fn measurement(&self) -> [u8; 32] {
        self.measurement
    }

    /// The module measurement as lowercase hex.
    pub fn measurement_hex(&self) -> String {
        to_hex(&self.measurement)
    }

    /// Runs `handle(request)` in a fresh store under the resource budgets and
    /// returns the guest's response.
    pub fn call_handle(&mut self, request: Json) -> Result<Json, RunnerError> {
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|err| RunnerError::Internal(format!("request serialization: {err}")))?;
        if request_bytes.len() > self.limits.max_request_bytes {
            return Err(RunnerError::RequestTooLarge {
                size: request_bytes.len(),
                max: self.limits.max_request_bytes,
            });
        }

        let mut store = Store::new(
            &self.engine,
            StoreData {
                limits: store_limits(&self.limits),
            },
        );
        store.limiter(|data| &mut data.limits);
        store
            .set_fuel(self.limits.max_fuel)
            .map_err(|err| RunnerError::Internal(format!("set_fuel: {err}")))?;
        store.set_epoch_deadline(self.epoch_deadline_ticks());

        let instance = self
            .linker
            .instantiate(&mut store, &self.module)
            .map_err(|err| map_wasm_error(err, &self.limits))?;
        let ret = invoke_handle(&instance, &mut store, &request_bytes)
            .map_err(|err| map_wasm_error(err, &self.limits))?;

        let (ptr, len) = unpack(ret);
        if len as usize > self.limits.max_response_bytes {
            return Err(RunnerError::ResponseTooLarge {
                size: len as usize,
                max: self.limits.max_response_bytes,
            });
        }
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| RunnerError::MissingExport("memory".into()))?;
        let mut buf = vec![0u8; len as usize];
        memory
            .read(&mut store, ptr as usize, &mut buf)
            .map_err(|err| {
                RunnerError::Script(format!("guest returned out-of-bounds output: {err}"))
            })?;

        let envelope: Json = serde_json::from_slice(&buf)
            .map_err(|err| RunnerError::Script(format!("guest returned invalid output: {err}")))?;
        envelope_into_handle_result(envelope)
    }

    /// Drains the log records emitted so far.
    pub fn take_logs(&mut self) -> Vec<LogEntry> {
        std::mem::take(&mut self.ctx.lock().expect("host ctx lock").logs)
    }

    /// Snapshot of the guest-visible `state` store (for tests/persistence).
    pub fn state_snapshot(&self) -> HashMap<String, Json> {
        self.ctx.lock().expect("host ctx lock").state.clone()
    }

    fn epoch_deadline_ticks(&self) -> u64 {
        let interval_ms = EPOCH_INTERVAL.as_millis() as u64;
        (self.limits.max_cpu.as_millis() as u64)
            .div_ceil(interval_ms)
            .max(1)
    }
}

// ---------------------------------------------------------------- validation

/// Validates the import section (capabilities, fields, signatures) and the
/// required exports against the runner's ABI.
fn derive_manifest(module: &Module) -> Result<Manifest, RunnerError> {
    let mut caps = BTreeSet::new();
    for import in module.imports() {
        let cap = Capability::parse(import.module()).ok_or_else(|| {
            RunnerError::InvalidManifest(format!(
                "unknown import module `{}` (valid: {})",
                import.module(),
                Capability::ALL
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;
        let fields = host_fields(cap);
        if !fields.contains(&import.name()) {
            return Err(RunnerError::InvalidManifest(format!(
                "unknown import `{}.{}` (known: {})",
                import.module(),
                import.name(),
                fields.join(", ")
            )));
        }
        match import.ty() {
            ExternType::Func(ty) => {
                if !is_host_sig(&ty) {
                    return Err(RunnerError::InvalidManifest(format!(
                        "import `{}.{}` has wrong signature: expected (i32, i32) -> i64",
                        import.module(),
                        import.name()
                    )));
                }
            }
            _ => {
                return Err(RunnerError::InvalidManifest(format!(
                    "import `{}.{}` must be a function",
                    import.module(),
                    import.name()
                )))
            }
        }
        caps.insert(cap);
    }

    let mut has_memory = false;
    let mut has_alloc = false;
    let mut has_handle = false;
    for export in module.exports() {
        match export.name() {
            "memory" => match export.ty() {
                ExternType::Memory(_) => has_memory = true,
                _ => {
                    return Err(RunnerError::MissingExport(
                        "`memory` is not a memory export".into(),
                    ))
                }
            },
            "alloc" => {
                if let ExternType::Func(ty) = export.ty() {
                    if is_alloc_sig(&ty) {
                        has_alloc = true;
                    }
                }
            }
            "handle" => {
                if let ExternType::Func(ty) = export.ty() {
                    if is_handle_sig(&ty) {
                        has_handle = true;
                    }
                }
            }
            _ => {}
        }
    }
    if !has_memory {
        return Err(RunnerError::MissingExport("memory".into()));
    }
    if !has_alloc {
        return Err(RunnerError::MissingExport("alloc".into()));
    }
    if !has_handle {
        return Err(RunnerError::MissingExport("handle".into()));
    }
    Ok(Manifest::new(caps))
}

/// Rejects modules whose *declared* initial memory already exceeds the cap
/// (deterministic, before any guest code runs).
fn check_memory_floor(module: &Module, limits: &Limits) -> Result<(), RunnerError> {
    for export in module.exports() {
        if export.name() == "memory" {
            if let ExternType::Memory(ty) = export.ty() {
                let bytes = (ty.minimum() as usize).saturating_mul(64 * 1024);
                if bytes > limits.max_memory_bytes {
                    return Err(RunnerError::LimitExceeded(Limit::Memory {
                        max: limits.max_memory_bytes,
                    }));
                }
            }
        }
    }
    Ok(())
}

/// Known host fields for a capability, from the [`HOST_IMPORTS`] table.
fn host_fields(cap: Capability) -> &'static [&'static str] {
    HOST_IMPORTS
        .iter()
        .find(|(module, _)| *module == cap.as_str())
        .map(|(_, fields)| *fields)
        .expect("every capability has host imports")
}

// Signature checks (wasmtime's ValType does not implement PartialEq).
fn is_host_sig(ty: &FuncType) -> bool {
    let mut params = ty.params();
    let mut results = ty.results();
    matches!(params.next(), Some(ValType::I32))
        && matches!(params.next(), Some(ValType::I32))
        && params.next().is_none()
        && matches!(results.next(), Some(ValType::I64))
        && results.next().is_none()
}

fn is_alloc_sig(ty: &FuncType) -> bool {
    let mut params = ty.params();
    let mut results = ty.results();
    matches!(params.next(), Some(ValType::I32))
        && params.next().is_none()
        && matches!(results.next(), Some(ValType::I32))
        && results.next().is_none()
}

fn is_handle_sig(ty: &FuncType) -> bool {
    let mut params = ty.params();
    let mut results = ty.results();
    matches!(params.next(), Some(ValType::I32))
        && matches!(params.next(), Some(ValType::I32))
        && params.next().is_none()
        && matches!(results.next(), Some(ValType::I64))
        && results.next().is_none()
}

fn store_limits(limits: &Limits) -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size(limits.max_memory_bytes)
        .trap_on_grow_failure(true)
        .build()
}

// ----------------------------------------------------------------- execution

/// Writes the request into guest memory, invokes `handle`, returns the packed
/// envelope pointer/length.
fn invoke_handle(
    instance: &Instance,
    store: &mut Store<StoreData>,
    request_bytes: &[u8],
) -> WasmResult<i64> {
    let alloc: TypedFunc<i32, i32> = instance
        .get_typed_func(&mut *store, "alloc")
        .map_err(|err| format_err!("guest `alloc` export unusable: {err}"))?;
    let dst = alloc.call(&mut *store, request_bytes.len() as i32)?;
    let memory = instance
        .get_memory(&mut *store, "memory")
        .ok_or_else(|| format_err!("guest has no `memory` export"))?;
    memory
        .write(&mut *store, dst as usize, request_bytes)
        .map_err(|err| format_err!("guest rejected request write: {err}"))?;

    let handle: TypedFunc<(i32, i32), i64> = instance
        .get_typed_func(&mut *store, "handle")
        .map_err(|err| format_err!("guest `handle` export unusable: {err}"))?;
    handle.call(&mut *store, (dst, request_bytes.len() as i32))
}

/// Maps a wasmtime/execution error onto the runner's error model.
fn map_wasm_error(err: WasmError, limits: &Limits) -> RunnerError {
    if let Some(trap) = err.downcast_ref::<Trap>() {
        return match trap {
            Trap::OutOfFuel => RunnerError::LimitExceeded(Limit::Fuel(limits.max_fuel)),
            Trap::Interrupt => {
                RunnerError::LimitExceeded(Limit::Cpu(limits.max_cpu.as_millis() as u64))
            }
            // A grow that trips StoreLimits surfaces as a memory trap; the
            // guest could not exceed the cap, so report the limit as hit.
            Trap::MemoryOutOfBounds => RunnerError::LimitExceeded(Limit::Memory {
                max: limits.max_memory_bytes,
            }),
            other => RunnerError::Script(format!("guest trapped: {other}")),
        };
    }
    let msg = err.to_string();
    if msg.contains("memory") && msg.contains("limit") {
        return RunnerError::LimitExceeded(Limit::Memory {
            max: limits.max_memory_bytes,
        });
    }
    RunnerError::Script(msg)
}

fn envelope_into_handle_result(envelope: Json) -> Result<Json, RunnerError> {
    match envelope.get("ok") {
        Some(Json::Bool(true)) => Ok(envelope.get("response").cloned().unwrap_or(Json::Null)),
        _ => {
            let msg = envelope
                .get("error")
                .and_then(Json::as_str)
                .unwrap_or("guest reported an error")
                .to_string();
            Err(RunnerError::Script(msg))
        }
    }
}

// -------------------------------------------------------------- host plumbing

const fn pack(ptr: u32, len: u32) -> i64 {
    (ptr as i64) | ((len as i64) << 32)
}

fn unpack(value: i64) -> (u32, u32) {
    let raw = value as u64;
    (raw as u32, (raw >> 32) as u32)
}

fn host_ok(value: Json) -> Json {
    json!({ "ok": true, "value": value })
}

fn host_err(msg: impl Into<String>) -> Json {
    json!({ "ok": false, "error": msg.into() })
}

/// Error envelope with a stable machine-readable `code` for guest-side
/// mapping (bridge contract: the code strings below are part of the runner↔
/// service interface — both sides are attested together).
fn host_err_code(msg: impl Into<String>, code: &str) -> Json {
    json!({ "ok": false, "error": msg.into(), "code": code })
}

/// Bounds-checked read of the JSON argument from guest memory.
fn read_input(caller: &mut Caller<'_, StoreData>, ptr: i32, len: i32) -> WasmResult<Json> {
    let memory = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or_else(|| format_err!("guest has no `memory` export"))?;
    if ptr < 0 || len < 0 {
        bail!("negative input pointer/length");
    }
    let start = ptr as usize;
    let end = start
        .checked_add(len as usize)
        .ok_or_else(|| format_err!("input length overflow"))?;
    let data = memory.data(caller);
    let bytes = data
        .get(start..end)
        .ok_or_else(|| format_err!("input out of bounds"))?;
    serde_json::from_slice(bytes).map_err(|err| format_err!("input is not valid JSON: {err}"))
}

/// Serializes an envelope and writes it into fresh guest memory via the
/// guest's `alloc` export. The host context lock must NOT be held here (the
/// guest can re-enter host imports from `alloc`).
fn write_envelope(caller: &mut Caller<'_, StoreData>, envelope: &Json) -> WasmResult<i64> {
    let bytes = serde_json::to_vec(envelope)?;
    let alloc = caller
        .get_export("alloc")
        .and_then(|export| export.into_func())
        .ok_or_else(|| format_err!("guest has no `alloc` export"))?;
    let alloc: TypedFunc<i32, i32> = alloc.typed(&*caller)?;
    let dst = alloc.call(&mut *caller, bytes.len() as i32)?;
    if dst < 0 {
        bail!("guest alloc returned a negative pointer");
    }
    let memory = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or_else(|| format_err!("guest has no `memory` export"))?;
    let start = dst as usize;
    let end = start
        .checked_add(bytes.len())
        .ok_or_else(|| format_err!("alloc length overflow"))?;
    let data = memory.data_mut(&mut *caller);
    let slot = data
        .get_mut(start..end)
        .ok_or_else(|| format_err!("guest alloc returned an out-of-bounds pointer"))?;
    slot.copy_from_slice(&bytes);
    Ok(pack(dst as u32, bytes.len() as u32))
}

fn build_linker(engine: &Engine, ctx: &SharedCtx) -> WasmResult<Linker<StoreData>> {
    let mut linker: Linker<StoreData> = Linker::new(engine);

    {
        let ctx = ctx.clone();
        linker.func_wrap(
            "log",
            "log",
            move |mut caller: Caller<'_, StoreData>, ptr: i32, len: i32| -> WasmResult<i64> {
                let arg = read_input(&mut caller, ptr, len)?;
                let envelope = log_envelope(&ctx, &arg);
                write_envelope(&mut caller, &envelope)
            },
        )?;
    }
    {
        let ctx = ctx.clone();
        linker.func_wrap(
            "state",
            "get",
            move |mut caller: Caller<'_, StoreData>, ptr: i32, len: i32| -> WasmResult<i64> {
                let arg = read_input(&mut caller, ptr, len)?;
                let envelope = state_get_envelope(&ctx, &arg);
                write_envelope(&mut caller, &envelope)
            },
        )?;
    }
    {
        let ctx = ctx.clone();
        linker.func_wrap(
            "state",
            "set",
            move |mut caller: Caller<'_, StoreData>, ptr: i32, len: i32| -> WasmResult<i64> {
                let arg = read_input(&mut caller, ptr, len)?;
                let envelope = state_set_envelope(&ctx, &arg);
                write_envelope(&mut caller, &envelope)
            },
        )?;
    }
    {
        let ctx = ctx.clone();
        linker.func_wrap(
            "state",
            "delete",
            move |mut caller: Caller<'_, StoreData>, ptr: i32, len: i32| -> WasmResult<i64> {
                let arg = read_input(&mut caller, ptr, len)?;
                let envelope = state_delete_envelope(&ctx, &arg);
                write_envelope(&mut caller, &envelope)
            },
        )?;
    }
    {
        let ctx = ctx.clone();
        linker.func_wrap(
            "state",
            "keys",
            move |mut caller: Caller<'_, StoreData>, ptr: i32, len: i32| -> WasmResult<i64> {
                let arg = read_input(&mut caller, ptr, len)?;
                let envelope = state_keys_envelope(&ctx, &arg);
                write_envelope(&mut caller, &envelope)
            },
        )?;
    }
    {
        linker.func_wrap(
            "clock",
            "unix_seconds",
            move |mut caller: Caller<'_, StoreData>, ptr: i32, len: i32| -> WasmResult<i64> {
                let arg = read_input(&mut caller, ptr, len)?;
                let envelope = clock_envelope(&arg);
                write_envelope(&mut caller, &envelope)
            },
        )?;
    }
    {
        linker.func_wrap(
            "random",
            "bytes",
            move |mut caller: Caller<'_, StoreData>, ptr: i32, len: i32| -> WasmResult<i64> {
                let arg = read_input(&mut caller, ptr, len)?;
                let envelope = random_envelope(&arg);
                write_envelope(&mut caller, &envelope)
            },
        )?;
    }
    {
        linker.func_wrap(
            "crypto",
            "sha256",
            move |mut caller: Caller<'_, StoreData>, ptr: i32, len: i32| -> WasmResult<i64> {
                let arg = read_input(&mut caller, ptr, len)?;
                let envelope = sha256_envelope(&arg);
                write_envelope(&mut caller, &envelope)
            },
        )?;
    }
    {
        linker.func_wrap(
            "crypto",
            "hmac_sha256",
            move |mut caller: Caller<'_, StoreData>, ptr: i32, len: i32| -> WasmResult<i64> {
                let arg = read_input(&mut caller, ptr, len)?;
                let envelope = hmac_sha256_envelope(&arg);
                write_envelope(&mut caller, &envelope)
            },
        )?;
    }
    {
        linker.func_wrap(
            "crypto",
            "hkdf_sha256",
            move |mut caller: Caller<'_, StoreData>, ptr: i32, len: i32| -> WasmResult<i64> {
                let arg = read_input(&mut caller, ptr, len)?;
                let envelope = hkdf_sha256_envelope(&arg);
                write_envelope(&mut caller, &envelope)
            },
        )?;
    }
    {
        linker.func_wrap(
            "crypto",
            "ct_eq",
            move |mut caller: Caller<'_, StoreData>, ptr: i32, len: i32| -> WasmResult<i64> {
                let arg = read_input(&mut caller, ptr, len)?;
                let envelope = ct_eq_envelope(&arg);
                write_envelope(&mut caller, &envelope)
            },
        )?;
    }
    {
        let ctx = ctx.clone();
        linker.func_wrap(
            "attest",
            "attest",
            move |mut caller: Caller<'_, StoreData>, ptr: i32, len: i32| -> WasmResult<i64> {
                let arg = read_input(&mut caller, ptr, len)?;
                let envelope = attest_envelope(&ctx, &arg);
                write_envelope(&mut caller, &envelope)
            },
        )?;
    }
    {
        let ctx = ctx.clone();
        linker.func_wrap(
            "gate",
            "unwrap",
            move |mut caller: Caller<'_, StoreData>, ptr: i32, len: i32| -> WasmResult<i64> {
                let arg = read_input(&mut caller, ptr, len)?;
                let envelope = gate_unwrap_envelope(&ctx, &arg);
                write_envelope(&mut caller, &envelope)
            },
        )?;
    }
    {
        linker.func_wrap(
            "crypto",
            "ed25519_verify",
            move |mut caller: Caller<'_, StoreData>, ptr: i32, len: i32| -> WasmResult<i64> {
                let arg = read_input(&mut caller, ptr, len)?;
                let envelope = crypto_ed25519_verify_envelope(&arg);
                write_envelope(&mut caller, &envelope)
            },
        )?;
    }
    Ok(linker)
}

// ------------------------------------------------------------ host handlers

fn truncate_chars(message: &str, max_bytes: usize) -> String {
    if message.len() <= max_bytes {
        return message.to_string();
    }
    let mut cut = max_bytes;
    while !message.is_char_boundary(cut) {
        cut -= 1;
    }
    message[..cut].to_string()
}

fn log_envelope(ctx: &SharedCtx, arg: &Json) -> Json {
    let Some(level) = arg.get("level").and_then(Json::as_str) else {
        return host_err("log: missing `level`");
    };
    let Some(message) = arg.get("message").and_then(Json::as_str) else {
        return host_err("log: missing `message`");
    };
    if !matches!(level, "debug" | "info" | "warn" | "error") {
        return host_err(format!(
            "log: unknown level `{level}` (use debug/info/warn/error)"
        ));
    }
    let entry = LogEntry {
        level: level.to_string(),
        message: truncate_chars(message, MAX_LOG_MESSAGE),
    };
    ctx.lock().expect("host ctx lock").logs.push(entry);
    host_ok(Json::Null)
}

fn state_key(arg: &Json) -> Result<&str, Json> {
    let key = arg
        .get("key")
        .and_then(Json::as_str)
        .ok_or_else(|| host_err("state: missing or invalid `key`"))?;
    if key.is_empty() || key.len() > MAX_STATE_KEY {
        return Err(host_err(format!(
            "state: invalid key length (1..={MAX_STATE_KEY} bytes)"
        )));
    }
    Ok(key)
}

fn state_get_envelope(ctx: &SharedCtx, arg: &Json) -> Json {
    let key = match state_key(arg) {
        Ok(key) => key,
        Err(envelope) => return envelope,
    };
    let value = ctx
        .lock()
        .expect("host ctx lock")
        .state
        .get(key)
        .cloned()
        .unwrap_or(Json::Null);
    host_ok(value)
}

fn state_set_envelope(ctx: &SharedCtx, arg: &Json) -> Json {
    let key = match state_key(arg) {
        Ok(key) => key.to_string(),
        Err(envelope) => return envelope,
    };
    let Some(value) = arg.get("value") else {
        return host_err("state.set: missing `value`");
    };
    let size = serde_json::to_string(value).map(|s| s.len()).unwrap_or(0);
    if size > MAX_STATE_VALUE {
        return host_err(format!(
            "state.set: value too large ({size} bytes, limit {MAX_STATE_VALUE})"
        ));
    }
    ctx.lock()
        .expect("host ctx lock")
        .state
        .insert(key, value.clone());
    host_ok(Json::Null)
}

fn state_delete_envelope(ctx: &SharedCtx, arg: &Json) -> Json {
    let key = match state_key(arg) {
        Ok(key) => key.to_string(),
        Err(envelope) => return envelope,
    };
    ctx.lock().expect("host ctx lock").state.remove(&key);
    host_ok(Json::Null)
}

fn state_keys_envelope(ctx: &SharedCtx, _arg: &Json) -> Json {
    let mut keys: Vec<String> = ctx
        .lock()
        .expect("host ctx lock")
        .state
        .keys()
        .cloned()
        .collect();
    keys.sort();
    host_ok(Json::Array(keys.into_iter().map(Json::String).collect()))
}

fn clock_envelope(_arg: &Json) -> Json {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    host_ok(json!(secs))
}

fn random_envelope(arg: &Json) -> Json {
    let Some(n) = arg.get("n").and_then(Json::as_u64) else {
        return host_err("random.bytes: missing `n`");
    };
    if n == 0 || n > MAX_RANDOM_BYTES as u64 {
        return host_err(format!("random.bytes: n must be 1..={MAX_RANDOM_BYTES}"));
    }
    let mut buf = vec![0u8; n as usize];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    host_ok(Json::String(to_hex(&buf)))
}

fn decode_hex_field(arg: &Json, field: &str) -> Result<Vec<u8>, Json> {
    let raw = arg
        .get(field)
        .and_then(Json::as_str)
        .ok_or_else(|| host_err(format!("missing `{field}`")))?;
    hex::decode(raw).map_err(|err| host_err(format!("invalid hex in `{field}`: {err}")))
}

fn sha256_envelope(arg: &Json) -> Json {
    let data = match decode_hex_field(arg, "data_hex") {
        Ok(data) => data,
        Err(envelope) => return host_err(format!("crypto.sha256: {}", envelope["error"])),
    };
    host_ok(Json::String(to_hex(&Sha256::digest(&data))))
}

fn hmac_sha256_envelope(arg: &Json) -> Json {
    use hmac::{Hmac, Mac};
    let key = match decode_hex_field(arg, "key_hex") {
        Ok(key) => key,
        Err(envelope) => return host_err(format!("crypto.hmac_sha256: {}", envelope["error"])),
    };
    let data = match decode_hex_field(arg, "data_hex") {
        Ok(data) => data,
        Err(envelope) => return host_err(format!("crypto.hmac_sha256: {}", envelope["error"])),
    };
    let mut mac = match Hmac::<Sha256>::new_from_slice(&key) {
        Ok(mac) => mac,
        Err(err) => return host_err(format!("crypto.hmac_sha256: {err}")),
    };
    mac.update(&data);
    host_ok(Json::String(to_hex(&mac.finalize().into_bytes())))
}

fn hkdf_sha256_envelope(arg: &Json) -> Json {
    let ikm = match decode_hex_field(arg, "ikm_hex") {
        Ok(ikm) => ikm,
        Err(envelope) => return host_err(format!("crypto.hkdf_sha256: {}", envelope["error"])),
    };
    let salt = match decode_hex_field(arg, "salt_hex") {
        Ok(salt) => salt,
        Err(envelope) => return host_err(format!("crypto.hkdf_sha256: {}", envelope["error"])),
    };
    let info = match decode_hex_field(arg, "info_hex") {
        Ok(info) => info,
        Err(envelope) => return host_err(format!("crypto.hkdf_sha256: {}", envelope["error"])),
    };
    let Some(len) = arg.get("len").and_then(Json::as_u64) else {
        return host_err("crypto.hkdf_sha256: missing `len`");
    };
    if len == 0 || len > MAX_HKDF_OUTPUT as u64 {
        return host_err(format!(
            "crypto.hkdf_sha256: len must be 1..={MAX_HKDF_OUTPUT}"
        ));
    }
    let hk = hkdf::Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = vec![0u8; len as usize];
    if let Err(err) = hk.expand(&info, &mut okm) {
        return host_err(format!("crypto.hkdf_sha256: {err}"));
    }
    host_ok(Json::String(to_hex(&okm)))
}

fn ct_eq_envelope(arg: &Json) -> Json {
    let a = match decode_hex_field(arg, "a_hex") {
        Ok(a) => a,
        Err(envelope) => return host_err(format!("crypto.ct_eq: {}", envelope["error"])),
    };
    let b = match decode_hex_field(arg, "b_hex") {
        Ok(b) => b,
        Err(envelope) => return host_err(format!("crypto.ct_eq: {}", envelope["error"])),
    };
    if a.len() != b.len() {
        return host_ok(Json::Bool(false));
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    host_ok(Json::Bool(diff == 0))
}

fn attest_envelope(ctx: &SharedCtx, arg: &Json) -> Json {
    let nonce = match decode_hex_field(arg, "nonce_hex") {
        Ok(nonce) => nonce,
        Err(envelope) => return host_err(format!("tee.attest: {}", envelope["error"])),
    };
    // Clone the attestor out, then drop the lock before calling into it.
    let (attestor, measurement) = {
        let guard = ctx.lock().expect("host ctx lock");
        (guard.attestor.clone(), guard.measurement)
    };
    let Some(attestor) = attestor else {
        return host_err("tee.attest: no attestation backend configured");
    };
    match attestor.attest(&nonce, &measurement) {
        Ok(doc) => host_ok(Json::String(to_hex(&doc))),
        Err(err) => host_err(format!("tee.attest: {err}")),
    }
}

/// `gate.unwrap` — the blind-gatekeeper operation: open the outer envelope
/// with the provisioned TEE key, verify the inner envelope is addressed to
/// the claimed owner, return the inner blob. Plaintext never exists here
/// (the inner layer stays sealed to the owner's local key).
///
/// Failure codes (`code` field): `bad_request`, `not_provisioned`,
/// `wrong_owner`, `decrypt_failed`, `malformed`.
fn gate_unwrap_envelope(ctx: &SharedCtx, arg: &Json) -> Json {
    let Some(outer_hex) = arg.get("outer_hex").and_then(Json::as_str) else {
        return host_err_code("gate.unwrap: missing `outer_hex`", "bad_request");
    };
    let Some(owner_hex) = arg.get("owner_hex").and_then(Json::as_str) else {
        return host_err_code("gate.unwrap: missing `owner_hex`", "bad_request");
    };
    let Ok(outer) = hex::decode(outer_hex) else {
        return host_err_code("gate.unwrap: invalid hex in `outer_hex`", "bad_request");
    };
    let Ok(owner) = <[u8; 32]>::try_from(hex::decode(owner_hex).unwrap_or_default().as_slice())
    else {
        return host_err_code("gate.unwrap: `owner_hex` must be 32 bytes", "bad_request");
    };

    // Read the key under the lock, then do all crypto lock-free (lock
    // discipline: never hold the ctx across anything re-entrant).
    let tee_key = ctx.lock().expect("host ctx lock").tee_key;
    let Some(tee_key) = tee_key else {
        return host_err_code("gate.unwrap: no TEE key provisioned", "not_provisioned");
    };
    match tee_crypto::tee_unwrap(&tee_key, &outer, &owner) {
        Ok(inner) => host_ok(Json::String(hex::encode(inner))),
        Err(tee_crypto::CryptoError::WrongOwner) => host_err_code(
            "gate.unwrap: envelope addressed to a different owner",
            "wrong_owner",
        ),
        Err(tee_crypto::CryptoError::OpenFailed) => {
            host_err_code("gate.unwrap: envelope did not decrypt", "decrypt_failed")
        }
        Err(tee_crypto::CryptoError::Malformed(_, detail)) => host_err_code(
            format!("gate.unwrap: malformed envelope: {detail}"),
            "malformed",
        ),
        Err(other) => host_err_code(format!("gate.unwrap: {other}"), "decrypt_failed"),
    }
}

/// `crypto.ed25519_verify` — proof-of-possession verification primitive.
/// Structurally invalid keys/messages are caller errors; a *valid* signature
/// simply yields `false`.
fn crypto_ed25519_verify_envelope(arg: &Json) -> Json {
    let Some(pk_hex) = arg.get("pk_hex").and_then(Json::as_str) else {
        return host_err("crypto.ed25519_verify: missing `pk_hex`");
    };
    let Some(msg_hex) = arg.get("msg_hex").and_then(Json::as_str) else {
        return host_err("crypto.ed25519_verify: missing `msg_hex`");
    };
    let Some(sig_hex) = arg.get("sig_hex").and_then(Json::as_str) else {
        return host_err("crypto.ed25519_verify: missing `sig_hex`");
    };
    let Ok(pk) = <[u8; 32]>::try_from(hex::decode(pk_hex).unwrap_or_default().as_slice()) else {
        return host_err("crypto.ed25519_verify: invalid `pk_hex`");
    };
    let Ok(sig) = <[u8; 64]>::try_from(hex::decode(sig_hex).unwrap_or_default().as_slice()) else {
        return host_err("crypto.ed25519_verify: invalid `sig_hex`");
    };
    let Ok(message) = hex::decode(msg_hex) else {
        return host_err("crypto.ed25519_verify: invalid `msg_hex`");
    };
    let Ok(verifying) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else {
        return host_err("crypto.ed25519_verify: invalid public key");
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig);
    host_ok(Json::Bool(
        verifying.verify_strict(&message, &signature).is_ok(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tee_attest::AttestError;

    fn test_ctx(attestor: Option<Arc<dyn Attestor>>) -> SharedCtx {
        test_ctx_full(attestor, None)
    }

    fn test_ctx_full(attestor: Option<Arc<dyn Attestor>>, tee_key: Option<[u8; 32]>) -> SharedCtx {
        Arc::new(Mutex::new(HostCtx {
            logs: Vec::new(),
            state: HashMap::new(),
            attestor,
            measurement: [7u8; 32],
            tee_key,
        }))
    }

    fn assert_error(envelope: &Json, needle: &str) {
        assert_eq!(envelope.get("ok"), Some(&Json::Bool(false)), "{envelope}");
        let msg = envelope
            .get("error")
            .and_then(Json::as_str)
            .unwrap_or_default();
        assert!(msg.contains(needle), "expected `{needle}` in `{msg}`");
    }

    #[test]
    fn log_validates_and_collects() {
        let ctx = test_ctx(None);
        let env = log_envelope(&ctx, &json!({"level": "info", "message": "hi"}));
        assert_eq!(env, json!({"ok": true, "value": null}));
        assert_eq!(
            ctx.lock().expect("lock").logs,
            vec![LogEntry {
                level: "info".into(),
                message: "hi".into()
            }]
        );

        assert_error(
            &log_envelope(&ctx, &json!({"level": "nope", "message": "x"})),
            "unknown level",
        );
        assert_error(
            &log_envelope(&ctx, &json!({"message": "x"})),
            "missing `level`",
        );
        assert_error(
            &log_envelope(&ctx, &json!({"level": "info"})),
            "missing `message`",
        );
        assert!(
            ctx.lock().expect("lock").logs.len() == 1,
            "no entries added"
        );
    }

    #[test]
    fn log_truncates_at_char_boundary() {
        let ctx = test_ctx(None);
        let long = "€".repeat(1000); // 3 bytes each
        let env = log_envelope(&ctx, &json!({"level": "info", "message": long}));
        assert_eq!(env.get("ok"), Some(&Json::Bool(true)));
        let entry = &ctx.lock().expect("lock").logs[0];
        assert!(entry.message.len() <= MAX_LOG_MESSAGE);
        assert!(long.starts_with(&entry.message));
    }

    #[test]
    fn state_roundtrip_and_limits() {
        let ctx = test_ctx(None);
        assert_eq!(
            state_get_envelope(&ctx, &json!({"key": "a"})),
            json!({"ok": true, "value": null})
        );
        state_set_envelope(&ctx, &json!({"key": "a", "value": 42}));
        assert_eq!(
            state_get_envelope(&ctx, &json!({"key": "a"})),
            json!({"ok": true, "value": 42})
        );
        assert_eq!(
            state_keys_envelope(&ctx, &json!({})),
            json!({"ok": true, "value": ["a"]})
        );
        state_delete_envelope(&ctx, &json!({"key": "a"}));
        assert_eq!(
            state_get_envelope(&ctx, &json!({"key": "a"})),
            json!({"ok": true, "value": null})
        );

        assert_error(
            &state_get_envelope(&ctx, &json!({"key": "k".repeat(301)})),
            "invalid key length",
        );
        assert_error(
            &state_get_envelope(&ctx, &json!({"key": 42})),
            "missing or invalid `key`",
        );
        assert_error(
            &state_set_envelope(&ctx, &json!({"key": "b"})),
            "missing `value`",
        );
        let big = "x".repeat(MAX_STATE_VALUE + 1);
        assert_error(
            &state_set_envelope(&ctx, &json!({"key": "b", "value": big})),
            "too large",
        );
        assert!(ctx.lock().expect("lock").state.is_empty());
    }

    #[test]
    fn sha256_matches_known_vectors() {
        let env = sha256_envelope(&json!({"data_hex": ""}));
        assert_eq!(
            env,
            json!({"ok": true,
                   "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"})
        );
        let env = sha256_envelope(&json!({"data_hex": hex::encode("abc")}));
        assert_eq!(
            env["value"],
            json!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_error(&sha256_envelope(&json!({"data_hex": "zz"})), "invalid hex");
        assert_error(&sha256_envelope(&json!({})), "missing `data_hex`");
    }

    #[test]
    fn hmac_matches_rfc4231_case_1() {
        let key = vec![0x0bu8; 20];
        let env = hmac_sha256_envelope(&json!({
            "key_hex": hex::encode(key),
            "data_hex": hex::encode("Hi There"),
        }));
        assert_eq!(
            env["value"],
            json!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
    }

    #[test]
    fn hkdf_is_deterministic_and_bounded() {
        let args = json!({
            "ikm_hex": hex::encode(vec![0x0bu8; 22]),
            "salt_hex": hex::encode((0u8..=12).collect::<Vec<u8>>()),
            "info_hex": hex::encode((0xf0u8..=0xf9).collect::<Vec<u8>>()),
            "len": 42,
        });
        let a = hkdf_sha256_envelope(&args);
        let b = hkdf_sha256_envelope(&args);
        assert_eq!(a, b);
        assert_eq!(a["value"].as_str().unwrap().len(), 84); // 42 bytes hex

        let mut zero = args.clone();
        zero["len"] = json!(0);
        assert_error(&hkdf_sha256_envelope(&zero), "len must be 1..=");
        let mut huge = args;
        huge["len"] = json!(1_000_000);
        assert_error(&hkdf_sha256_envelope(&huge), "len must be 1..=");
    }

    #[test]
    fn ct_eq_semantics() {
        let eq = |a: &str, b: &str| {
            ct_eq_envelope(&json!({"a_hex": hex::encode(a), "b_hex": hex::encode(b)}))
        };
        assert_eq!(eq("same", "same")["value"], json!(true));
        assert_eq!(eq("same", "dame")["value"], json!(false));
        assert_eq!(eq("short", "longer")["value"], json!(false));
    }

    #[test]
    fn random_bounds() {
        assert_error(&random_envelope(&json!({})), "missing `n`");
        assert_error(&random_envelope(&json!({"n": 0})), "n must be 1..=");
        assert_error(&random_envelope(&json!({"n": 4097})), "n must be 1..=");
        let env = random_envelope(&json!({"n": 16}));
        assert_eq!(env["value"].as_str().unwrap().len(), 32);
    }

    #[test]
    fn attest_without_backend_is_reported() {
        let ctx = test_ctx(None);
        let env = attest_envelope(&ctx, &json!({"nonce_hex": "aabb"}));
        assert_error(&env, "no attestation backend configured");
    }

    #[test]
    fn attest_binds_nonce_and_measurement() {
        struct FakeAttestor;
        impl Attestor for FakeAttestor {
            fn attest(&self, nonce: &[u8], user_data: &[u8]) -> Result<Vec<u8>, AttestError> {
                let mut doc = b"FAKE-DOC".to_vec();
                doc.extend_from_slice(nonce);
                doc.extend_from_slice(user_data);
                Ok(doc)
            }
        }
        let ctx = test_ctx(Some(Arc::new(FakeAttestor)));
        let env = attest_envelope(&ctx, &json!({"nonce_hex": "6e6f6e6365"}));
        let mut expected = b"FAKE-DOC".to_vec();
        expected.extend_from_slice(b"nonce");
        expected.extend_from_slice(&[7u8; 32]);
        assert_eq!(env, json!({"ok": true, "value": to_hex(&expected)}));
    }

    #[test]
    fn clock_returns_recent_timestamp() {
        let env = clock_envelope(&json!({}));
        assert!(env["value"].as_i64().unwrap() > 1_600_000_000);
    }

    #[test]
    fn pack_unpack_roundtrip() {
        for (ptr, len) in [(0u32, 0u32), (1, 22), (0xDEAD_BEEF, 0x0102_0304)] {
            assert_eq!(unpack(pack(ptr, len)), (ptr, len));
        }
    }

    // ---------------------------------------------------------- gate.unwrap

    fn assert_code(envelope: &Json, code: &str) {
        assert_eq!(envelope.get("ok"), Some(&Json::Bool(false)), "{envelope}");
        assert_eq!(
            envelope.get("code"),
            Some(&Json::String(code.into())),
            "{envelope}"
        );
    }

    #[test]
    fn gate_unwrap_requires_provisioning() {
        let ctx = test_ctx_full(None, None);
        let env = gate_unwrap_envelope(
            &ctx,
            &json!({ "outer_hex": hex::encode([0u8; 80]), "owner_hex": hex::encode([1u8; 32]) }),
        );
        assert_code(&env, "not_provisioned");
    }

    #[test]
    fn gate_unwrap_validates_fields() {
        let ctx = test_ctx_full(None, Some([42; 32]));
        let env = gate_unwrap_envelope(&ctx, &json!({}));
        assert_code(&env, "bad_request");
        let env = gate_unwrap_envelope(
            &ctx,
            &json!({ "outer_hex": "zz", "owner_hex": hex::encode([1u8; 32]) }),
        );
        assert_code(&env, "bad_request");
        let env = gate_unwrap_envelope(
            &ctx,
            &json!({ "outer_hex": hex::encode([0u8; 80]), "owner_hex": "abcd" }),
        );
        assert_code(&env, "bad_request");
    }

    #[test]
    fn gate_unwrap_roundtrip_wrong_owner_and_garbage() {
        let tee_sk = [42u8; 32];
        let tee_pk = tee_crypto::x25519_public(&tee_sk);
        let owner_pk = tee_crypto::x25519_public(&[7u8; 32]);
        let wrong_pk = tee_crypto::x25519_public(&[8u8; 32]);
        let envelope = tee_crypto::seal_secret(&tee_pk, &owner_pk, b"password-entry").unwrap();

        let ctx = test_ctx_full(None, Some(tee_sk));

        // Happy path: inner blob comes back still sealed to the owner.
        let env = gate_unwrap_envelope(
            &ctx,
            &json!({
                "outer_hex": hex::encode(&envelope),
                "owner_hex": hex::encode(owner_pk),
            }),
        );
        assert_eq!(env.get("ok"), Some(&Json::Bool(true)), "{env}");
        let inner_hex = env["value"].as_str().unwrap();
        assert_eq!(
            tee_crypto::inner_recipient(&hex::decode(inner_hex).unwrap()).unwrap(),
            owner_pk,
            "inner must still be addressed to the owner"
        );

        // Claiming another key fails the owner check (this is the throttle's
        // core authorization boundary).
        let env = gate_unwrap_envelope(
            &ctx,
            &json!({
                "outer_hex": hex::encode(&envelope),
                "owner_hex": hex::encode(wrong_pk),
            }),
        );
        assert_code(&env, "wrong_owner");

        // Structurally broken outer envelope.
        let env = gate_unwrap_envelope(
            &ctx,
            &json!({
                "outer_hex": hex::encode([0u8; 8]),
                "owner_hex": hex::encode(owner_pk),
            }),
        );
        assert_code(&env, "malformed");
    }

    // -------------------------------------------------- crypto.ed25519_verify

    #[test]
    fn ed25519_verify_validates_and_verifies() {
        use ed25519_dalek::{Signer, SigningKey};
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        let pk = signing.verifying_key().to_bytes();
        let message = b"fetch-pop-message";
        let signature = signing.sign(message).to_bytes();

        let env = crypto_ed25519_verify_envelope(&json!({
            "pk_hex": hex::encode(pk),
            "msg_hex": hex::encode(message),
            "sig_hex": hex::encode(signature),
        }));
        assert_eq!(env, json!({"ok": true, "value": true}));

        let env = crypto_ed25519_verify_envelope(&json!({
            "pk_hex": hex::encode(pk),
            "msg_hex": hex::encode(b"other-message"),
            "sig_hex": hex::encode(signature),
        }));
        assert_eq!(env, json!({"ok": true, "value": false}));

        let env = crypto_ed25519_verify_envelope(&json!({
            "pk_hex": "zz",
            "msg_hex": hex::encode(message),
            "sig_hex": hex::encode(signature),
        }));
        assert_error(&env, "invalid `pk_hex`");

        let env = crypto_ed25519_verify_envelope(&json!({}));
        assert_error(&env, "missing `pk_hex`");
    }
}
