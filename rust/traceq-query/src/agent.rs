//! Recorded read entry for Agents. Query semantics remain in the existing CLI.
use serde_json::{Value, json};
use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::unix::process::{CommandExt, ExitStatusExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const TIMEOUT: Duration = Duration::from_secs(90);
const HELP: &str = "traceq agent-query [--manifest tools.json] TRACE_ID COMMAND [options]\n\
Recorded, bounded read entry; query stdout/stderr and trace validation are unchanged.\n\
Default row limit 40, maximum 256; mem-state byte limit 1..4096 per checkpoint.\n\
No --all or -o. Use bounded queries and shell redirection.\n\
Relative executable/trace paths and queries/ logs are relative to the manifest.\n\
--capabilities prints the query policy; --help prints this help.\n\
Help/capabilities are recorded with an explicit --manifest; neither reads a trace.\n\
All supported queries use the linked Rust core and presentation in this process\n\
when the manifest selects this executable. Backend names are compatibility labels.\n\
Other executable selections launch a CLI child.\n\
Every trace query retains its normal full validation; the log records its execution path.\n";

type ContextOutput = unsafe extern "C" fn(*mut c_void, c_int, *const u8, usize) -> c_int;
type ContextHandler =
    unsafe extern "C" fn(c_int, *const *const c_char, ContextOutput, *mut c_void) -> c_int;
// Private callback decision, matching agent_query.h. Never an exit code.
const DELEGATE: c_int = -4096;
enum DirectResult {
    Completed(Outcome),
    Delegate,
}

fn policy() -> Value {
    // This is an immutable build resource, checked against the compatibility
    // adapter and through real accepted/rejected invocations.
    serde_json::from_str(include_str!("agent_policy.json")).expect("compiled agent policy")
}
fn member(policy: &Value, key: &str, value: &str) -> bool {
    policy[key]
        .as_array()
        .is_some_and(|items| items.iter().any(|v| v.as_str() == Some(value)))
}
fn epoch_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}
fn error_document(code: &str, origin: &str, message: &str, policy: Option<&Value>) -> Vec<u8> {
    let mut error = json!({"code":code,"origin":origin,"message":message});
    if let Some(policy) = policy {
        error["query_policy"] = policy.clone();
    }
    let mut bytes = serde_json::to_vec(&json!({"error":error})).expect("JSON error values");
    bytes.push(b'\n');
    bytes
}
fn resolve(base: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

struct Outcome {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    partial_stdout: Vec<u8>,
    status: i32,
    origin: Option<&'static str>,
    launched: bool,
    in_process: bool,
}
impl Outcome {
    fn launch_failure(message: &str) -> Self {
        Self {
            stdout: error_document("QUERY_LAUNCH", "launch", message, None),
            stderr: vec![],
            partial_stdout: vec![],
            status: 127,
            origin: Some("launch"),
            launched: false,
            in_process: false,
        }
    }
    fn rejection(code: &str, message: &str, policy: &Value) -> Self {
        Self {
            stdout: error_document(code, "adapter", message, Some(policy)),
            stderr: vec![],
            partial_stdout: vec![],
            status: 2,
            origin: Some("adapter"),
            launched: false,
            in_process: false,
        }
    }
    fn text(stdout: Vec<u8>) -> Self {
        Self {
            stdout,
            stderr: vec![],
            partial_stdout: vec![],
            status: 0,
            origin: None,
            launched: false,
            in_process: false,
        }
    }
}

unsafe extern "C" {
    fn killpg(group: c_int, signal: c_int) -> c_int;
}
fn execute(argv: &[String], backend: Option<&str>, directory: &Path, timeout: Duration) -> Outcome {
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Some(backend) = backend {
        command.env("TRACEQ_QUERY_BACKEND", backend);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return Outcome::launch_failure(&error.to_string()),
    };
    let (sender, receiver) = mpsc::channel();
    let mut readers = Vec::new();
    for (index, mut pipe) in [
        Box::new(child.stdout.take().expect("stdout pipe")) as Box<dyn Read + Send>,
        Box::new(child.stderr.take().expect("stderr pipe")),
    ]
    .into_iter()
    .enumerate()
    {
        let sender = sender.clone();
        readers.push(thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = pipe.read_to_end(&mut bytes);
            let _ = sender.send((index, bytes, result.map(|_| ())));
        }));
    }
    drop(sender);
    let started = Instant::now();
    let mut streams: [Option<Vec<u8>>; 2] = [None, None];
    let mut status = None;
    let mut failure = None;
    let mut timed_out = false;
    loop {
        while let Ok((index, bytes, result)) = receiver.try_recv() {
            streams[index] = Some(bytes);
            if let Err(error) = result {
                failure = Some(error.to_string());
            }
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(value) => status = value,
                Err(error) => {
                    failure = Some(error.to_string());
                    break;
                }
            }
        }
        if status.is_some() && streams.iter().all(Option::is_some) {
            break;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    if timed_out || failure.is_some() {
        // process_group(0) gives this child its own group. Terminate only that
        // group, including a wrapper's children which might retain pipe fds.
        if let Ok(group) = c_int::try_from(child.id()) {
            // SAFETY: group is the positive pid assigned to our own child;
            // SIGKILL has the POSIX value9 on the supported Unix targets.
            unsafe {
                killpg(group, 9);
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    for reader in readers {
        if reader.join().is_err() {
            failure = Some("query stream reader failed".into());
        }
    }
    for (index, bytes, result) in receiver {
        streams[index] = Some(bytes);
        if let Err(error) = result {
            failure = Some(error.to_string());
        }
    }
    let stdout = streams[0].take().unwrap_or_default();
    let stderr = streams[1].take().unwrap_or_default();
    if timed_out {
        return Outcome {
            stdout: error_document(
                "QUERY_TIMEOUT",
                "timeout",
                "traceq exceeded 90 seconds",
                None,
            ),
            stderr,
            partial_stdout: stdout,
            status: 124,
            origin: Some("timeout"),
            launched: true,
            in_process: false,
        };
    }
    if let Some(error) = failure {
        return Outcome {
            stdout: error_document("QUERY_OUTPUT", "cli", &error, None),
            stderr,
            partial_stdout: stdout,
            status: 1,
            origin: Some("cli"),
            launched: true,
            in_process: false,
        };
    }
    let status = status.expect("completed child status");
    let code = status
        .code()
        .unwrap_or_else(|| -status.signal().unwrap_or(1));
    Outcome {
        stdout,
        stderr,
        partial_stdout: vec![],
        status: code,
        origin: (code != 0).then_some("cli"),
        launched: true,
        in_process: false,
    }
}

#[derive(Default)]
struct DirectStreams {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    failed: bool,
}
// The worker owns an Arc for the entire callback. No caller argv, stack data,
// process stdout/stderr or environment is borrowed or redirected.
unsafe extern "C" fn collect_context_output(
    user: *mut c_void,
    stream: c_int,
    bytes: *const u8,
    length: usize,
) -> c_int {
    if user.is_null() || !(0..=1).contains(&stream) || (bytes.is_null() && length != 0) {
        return 1;
    }
    // SAFETY: the direct worker passes its live Arc<Mutex<DirectStreams>>.
    let streams = unsafe { &*user.cast::<Mutex<DirectStreams>>() };
    let Ok(mut streams) = streams.lock() else {
        return 1;
    };
    let destination = if stream == 0 {
        &mut streams.stdout
    } else {
        &mut streams.stderr
    };
    if destination.try_reserve(length).is_err() {
        streams.failed = true;
        return 1;
    }
    if length != 0 {
        // SAFETY: the C++ sink supplies length live bytes for this call only.
        destination.extend_from_slice(unsafe { std::slice::from_raw_parts(bytes, length) });
    }
    0
}

fn execute_read(
    argv: Vec<String>,
    handler: ContextHandler,
    timeout: Duration,
    allow_delegate: bool,
) -> DirectResult {
    let arguments = match argv
        .into_iter()
        .skip(1)
        .map(CString::new)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(arguments) => arguments,
        Err(_) => {
            return DirectResult::Completed(Outcome::launch_failure(
                "nul byte found in provided data",
            ));
        }
    };
    let streams = Arc::new(Mutex::new(DirectStreams::default()));
    let worker_streams = streams.clone();
    let (sender, receiver) = mpsc::channel();
    let worker = thread::Builder::new().spawn(move || {
        let pointers: Vec<_> = arguments.iter().map(|value| value.as_ptr()).collect();
        // SAFETY: argv and sink storage live on this owned worker until return.
        // The linked callback code lives for the CLI process lifetime. No C++
        // exception may cross the handler; its output callback copies bytes.
        let status = unsafe {
            handler(
                pointers.len() as c_int,
                pointers.as_ptr(),
                collect_context_output,
                Arc::as_ptr(&worker_streams).cast_mut().cast(),
            )
        };
        let _ = sender.send(status);
    });
    if let Err(error) = worker {
        return DirectResult::Completed(Outcome::launch_failure(&error.to_string()));
    }
    let status = receiver.recv_timeout(timeout);
    let mut streams = streams.lock().expect("output callback does not panic");
    let stdout = std::mem::take(&mut streams.stdout);
    let stderr = std::mem::take(&mut streams.stderr);
    if matches!(status, Ok(DELEGATE))
        && allow_delegate
        && !streams.failed
        && stdout.is_empty()
        && stderr.is_empty()
    {
        return DirectResult::Delegate;
    }
    DirectResult::Completed(match status {
        Ok(code) if !streams.failed && (0..=255).contains(&code) && code != 74 => Outcome {
            stdout,
            stderr,
            partial_stdout: vec![],
            status: code,
            origin: (code != 0).then_some("cli"),
            launched: false,
            in_process: true,
        },
        Err(mpsc::RecvTimeoutError::Timeout) => Outcome {
            stdout: error_document(
                "QUERY_TIMEOUT",
                "timeout",
                "traceq exceeded 90 seconds",
                None,
            ),
            stderr,
            partial_stdout: stdout,
            status: 124,
            origin: Some("timeout"),
            launched: false,
            in_process: true,
        },
        _ => Outcome {
            stdout: error_document(
                "QUERY_OUTPUT",
                "cli",
                "in-process query output failed",
                None,
            ),
            stderr,
            partial_stdout: stdout,
            status: 1,
            origin: Some("cli"),
            launched: false,
            in_process: true,
        },
    })
}

fn execute_selected_read(
    argv: &[String],
    backend: Option<&str>,
    directory: &Path,
    handler: ContextHandler,
    timeout: Duration,
    allow_delegate: bool,
) -> Outcome {
    let started = Instant::now();
    match execute_read(argv.to_vec(), handler, timeout, allow_delegate) {
        DirectResult::Completed(outcome) => outcome,
        DirectResult::Delegate => execute(
            argv,
            backend,
            directory,
            timeout.saturating_sub(started.elapsed()),
        ),
    }
}

fn direct_context(executable: &str, backend: Option<&str>) -> bool {
    let backend = backend
        .map(str::to_owned)
        .or_else(|| std::env::var("TRACEQ_QUERY_BACKEND").ok());
    if backend.as_deref().is_some_and(|value| value != "rust") {
        return false;
    }
    match (
        fs::canonicalize(executable),
        std::env::current_exe().and_then(fs::canonicalize),
    ) {
        (Ok(selected), Ok(current)) => selected == current,
        _ => false,
    }
}

fn direct_native(executable: &str) -> bool {
    match (
        fs::canonicalize(executable),
        std::env::current_exe().and_then(fs::canonicalize),
    ) {
        (Ok(selected), Ok(current)) => selected == current,
        _ => false,
    }
}
fn execute_native(args: Vec<String>, backend: Option<String>, timeout: Duration) -> Outcome {
    if args.iter().any(|a| a.contains('\0')) {
        return Outcome::launch_failure("nul byte found in provided data");
    }
    let (sender, receiver) = mpsc::channel();
    if let Err(error) = thread::Builder::new().spawn(move || {
        let result =
            std::panic::catch_unwind(|| crate::cli::run_with_backend(&args, backend.as_deref()));
        let _ = sender.send(result);
    }) {
        return Outcome::launch_failure(&error.to_string());
    }
    match receiver.recv_timeout(timeout) {
        Ok(Ok(response)) => Outcome {
            stdout: response.stdout,
            stderr: response.stderr,
            partial_stdout: vec![],
            status: response.status,
            origin: (response.status != 0).then_some("cli"),
            launched: false,
            in_process: true,
        },
        Err(mpsc::RecvTimeoutError::Timeout) => Outcome {
            stdout: error_document(
                "QUERY_TIMEOUT",
                "timeout",
                "traceq exceeded 90 seconds",
                None,
            ),
            stderr: vec![],
            partial_stdout: vec![],
            status: 124,
            origin: Some("timeout"),
            launched: false,
            in_process: true,
        },
        _ => Outcome {
            stdout: error_document(
                "QUERY_OUTPUT",
                "cli",
                "in-process query output failed",
                None,
            ),
            stderr: vec![],
            partial_stdout: vec![],
            status: 1,
            origin: Some("cli"),
            launched: false,
            in_process: true,
        },
    }
}

struct Entry {
    started: Instant,
    started_ns: u64,
    directory: PathBuf,
    trace: Option<String>,
    command: Option<String>,
    requested: Vec<String>,
    options: Vec<String>,
    backend: Value,
    format: Value,
    argv: Option<Vec<String>>,
    kind: &'static str,
    context: Option<ContextHandler>,
    structured_reads: bool,
    typed_queries: bool,
}
impl Entry {
    fn new(args: &[String], directory: PathBuf, started: Instant, started_ns: u64) -> Self {
        let requested = args.get(2..).unwrap_or_default().to_vec();
        Self {
            started,
            started_ns,
            directory,
            trace: args.first().cloned(),
            command: args.get(1).cloned(),
            options: requested.clone(),
            requested,
            backend: Value::Null,
            format: Value::Null,
            argv: None,
            kind: "query",
            context: None,
            structured_reads: false,
            typed_queries: false,
        }
    }
    fn finish(self, outcome: Outcome) -> i32 {
        let finished = epoch_ns();
        let seconds = self.started.elapsed().as_secs_f64();
        let id = format!("{}-{}", finished, std::process::id());
        let context_format = if self.command.as_deref() == Some("context")
            && (outcome.launched || outcome.in_process)
        {
            Some(if self.options.iter().any(|v| v == "--compact") {
                "columns-v1"
            } else {
                "named"
            })
        } else {
            None
        };
        let record = json!({"log_schema":2,"id":id,"trace":self.trace,"command":self.command,
            "requested_options":self.requested,"options":self.options,"argv":self.argv,
            "query_backend":self.backend,"configured_context_format":self.format,"context_format":context_format,
            "launched_cli":outcome.launched,"failure_origin":outcome.origin,"started_ns":self.started_ns,
            "finished_ns":finished,"seconds":seconds,"returncode":outcome.status,
            "stdout_bytes":outcome.stdout.len(),"stderr_bytes":outcome.stderr.len(),
            "partial_stdout_bytes":outcome.partial_stdout.len(),"entry_kind":"rust","request_kind":self.kind,
            "execution_path":if outcome.in_process {"in_process"} else if outcome.launched {"subprocess"} else {"none"},
            "query_execution":outcome.launched || outcome.in_process,
            "delegated_argv":if outcome.launched {&self.argv} else {&None}});
        let log = || -> io::Result<()> {
            let directory = self.directory.join("queries");
            fs::create_dir_all(&directory)?;
            for (suffix, bytes) in [("stdout", &outcome.stdout), ("stderr", &outcome.stderr)] {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(directory.join(format!("{id}.{suffix}")))?
                    .write_all(bytes)?;
            }
            if !outcome.partial_stdout.is_empty() {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(directory.join(format!("{id}.partial.stdout")))?
                    .write_all(&outcome.partial_stdout)?;
            }
            let mut bytes = serde_json::to_vec(&record)?;
            bytes.push(b'\n');
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(directory.join("calls.jsonl"))?
                .write_all(&bytes)
        };
        if let Err(error) = log() {
            let bytes = error_document("QUERY_LOG", "adapter", &error.to_string(), None);
            let _ = io::stdout().write_all(&bytes);
            return 74;
        }
        if io::stdout().write_all(&outcome.stdout).is_err()
            || io::stderr().write_all(&outcome.stderr).is_err()
        {
            return 74;
        }
        outcome.status
    }
    fn reject(self, message: &str, code: &str, policy: &Value) -> i32 {
        self.finish(Outcome::rejection(code, message, policy))
    }
    fn run(mut self, manifest: &Path, explicit: bool) -> i32 {
        let policy = policy();
        if self.command.is_none()
            && matches!(
                self.trace.as_deref(),
                Some("--help" | "-h" | "--capabilities")
            )
        {
            let capabilities = self.trace.as_deref() == Some("--capabilities");
            let bytes = if capabilities {
                let mut bytes = serde_json::to_vec(&policy).expect("policy JSON");
                bytes.push(b'\n');
                bytes
            } else {
                HELP.as_bytes().to_vec()
            };
            self.trace = None;
            self.kind = if capabilities { "capabilities" } else { "help" };
            if explicit {
                return self.finish(Outcome::text(bytes));
            }
            return if io::stdout().write_all(&bytes).is_ok() {
                0
            } else {
                74
            };
        }
        let config = match fs::read(manifest)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                serde_json::from_slice::<Value>(&bytes).map_err(|error| error.to_string())
            }) {
            Ok(config) => config,
            Err(error) => {
                return self.reject(
                    &format!("Invalid manifest: {error}"),
                    "ADAPTER_CONFIG",
                    &policy,
                );
            }
        };
        if config.get("traces").is_none() || config.get("traceq").is_none() {
            return self.reject(
                "manifest requires a traceq path and traces object",
                "ADAPTER_CONFIG",
                &policy,
            );
        }
        self.backend = config.get("query_backend").cloned().unwrap_or_default();
        self.format = config.get("context_format").cloned().unwrap_or_default();
        let (Some(traces), Some(executable)) =
            (config["traces"].as_object(), config["traceq"].as_str())
        else {
            return self.reject(
                "manifest requires a traceq path and traces object",
                "ADAPTER_CONFIG",
                &policy,
            );
        };
        let (Some(trace_id), Some(command)) = (self.trace.as_deref(), self.command.as_deref())
        else {
            return self.reject(
                "Use traceq agent-query TRACE_ID COMMAND [options]",
                "ARGUMENT",
                &policy,
            );
        };
        let Some(trace) = traces.get(trace_id) else {
            return self.reject(
                &format!(
                    "Unknown trace ID; available trace IDs: {}",
                    traces.keys().cloned().collect::<Vec<_>>().join(", ")
                ),
                "ARGUMENT",
                &policy,
            );
        };
        if !member(&policy, "allowed_commands", command)
            || self
                .options
                .iter()
                .any(|v| member(&policy, "disallowed_options", v))
        {
            return self.reject(
                "Use an allowed read query with bounded --limit and shell redirection for output.",
                "ARGUMENT",
                &policy,
            );
        }
        let Some(path) = trace.get("path").and_then(Value::as_str) else {
            return self.reject("Each trace requires a path", "ADAPTER_CONFIG", &policy);
        };
        if !self.backend.is_null() && !matches!(self.backend.as_str(), Some("cpp" | "rust")) {
            return self.reject(
                "query_backend must be cpp or rust",
                "ADAPTER_CONFIG",
                &policy,
            );
        }
        if !self.format.is_null() && !matches!(self.format.as_str(), Some("named" | "columns-v1")) {
            return self.reject(
                "context_format must be named or columns-v1",
                "ADAPTER_CONFIG",
                &policy,
            );
        }
        let maximum = if command == "mem-state" {
            Some(
                policy["memory_state_limits"]["maximum"]
                    .as_u64()
                    .expect("memory maximum"),
            )
        } else if member(&policy["row_limits"], "commands", command) {
            Some(
                policy["row_limits"]["maximum"]
                    .as_u64()
                    .expect("row maximum"),
            )
        } else {
            None
        };
        if let Some(maximum) = maximum.filter(|_| !self.options.iter().any(|v| v == "--help")) {
            if self.options.iter().filter(|v| *v == "--limit").count() > 1 {
                return self.reject(
                    &format!("Specify --limit once; maximum is {maximum}"),
                    "ARGUMENT",
                    &policy,
                );
            }
            if !self.options.iter().any(|v| v == "--limit") {
                self.options.extend([
                    "--limit".into(),
                    policy["row_limits"]["default"].to_string(),
                ]);
            }
            let limit = self
                .options
                .iter()
                .position(|v| v == "--limit")
                .and_then(|at| self.options.get(at + 1))
                .and_then(|value| parse_limit(value, command == "mem-state"));
            let Some(limit) = limit else {
                return self.reject(
                    &format!("--limit requires an integer from 1 to {maximum}"),
                    "ARGUMENT",
                    &policy,
                );
            };
            if limit == 0 || limit > maximum {
                return self.reject(
                    &format!("Per-query --limit must be 1..{maximum}; page or select evidence."),
                    "ARGUMENT",
                    &policy,
                );
            }
        }
        if command == "context"
            && self.format.as_str() == Some("columns-v1")
            && !self.options.iter().any(|v| v == "--help" || v == "-h")
        {
            for flag in ["--compact", "--json"] {
                if !self.options.iter().any(|v| v == flag) {
                    self.options.push(flag.into());
                }
            }
        }
        let executable = resolve(&self.directory, executable);
        let path = resolve(&self.directory, path);
        let (Some(executable), Some(path)) = (executable.to_str(), path.to_str()) else {
            return self.reject(
                "manifest paths require valid UTF-8",
                "ADAPTER_CONFIG",
                &policy,
            );
        };
        let argv = vec![executable.into(), command.into(), path.into()];
        let argv = argv
            .into_iter()
            .chain(self.options.iter().cloned())
            .collect::<Vec<_>>();
        let supported = command == "context"
            || (self.structured_reads && matches!(command, "instructions" | "mem-state"));
        let outcome = if self.typed_queries && direct_native(executable) {
            execute_native(
                argv[1..].to_vec(),
                self.backend
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| std::env::var("TRACEQ_QUERY_BACKEND").ok()),
                TIMEOUT,
            )
        } else if supported && direct_context(executable, self.backend.as_str()) {
            if let Some(handler) = self.context {
                execute_selected_read(
                    &argv,
                    self.backend.as_str(),
                    &self.directory,
                    handler,
                    TIMEOUT,
                    self.structured_reads,
                )
            } else {
                execute(&argv, self.backend.as_str(), &self.directory, TIMEOUT)
            }
        } else {
            execute(&argv, self.backend.as_str(), &self.directory, TIMEOUT)
        };
        self.argv = Some(argv);
        self.finish(outcome)
    }
}
fn parse_limit(literal: &str, memory: bool) -> Option<u64> {
    let value = literal.trim().replace('_', "");
    let (radix, digits) = if memory && value.to_lowercase().starts_with("0x") {
        (16, &value[2..])
    } else if memory && value.len() > 1 && value.starts_with('0') {
        (
            8,
            value
                .strip_prefix("0o")
                .or_else(|| value.strip_prefix("0O"))
                .unwrap_or(&value),
        )
    } else {
        (10, value.as_str())
    };
    u64::from_str_radix(digits, radix).ok()
}
fn main_entry(args: Vec<String>, context: Option<ContextHandler>, structured_reads: bool) -> i32 {
    main_entry_mode(args, context, structured_reads, false)
}
pub fn native_main(args: Vec<String>) -> i32 {
    main_entry_mode(args, None, true, true)
}
fn main_entry_mode(
    args: Vec<String>,
    context: Option<ContextHandler>,
    structured_reads: bool,
    typed_queries: bool,
) -> i32 {
    let started = Instant::now();
    let started_ns = epoch_ns();
    let directory = match std::env::current_dir() {
        Ok(path) => path,
        Err(_) => return 74,
    };
    let explicit = args.first().is_some_and(|v| v == "--manifest");
    let (manifest, rest) = if explicit {
        let Some(path) = args.get(1) else {
            return Entry::new(&args, directory, started, started_ns).reject(
                "--manifest requires a path",
                "ARGUMENT",
                &policy(),
            );
        };
        (resolve(&directory, path), &args[2..])
    } else {
        (directory.join("tools.json"), args.as_slice())
    };
    let directory = manifest
        .parent()
        .expect("absolute manifest parent")
        .to_path_buf();
    let mut entry = Entry::new(rest, directory, started, started_ns);
    entry.context = context;
    entry.structured_reads = structured_reads;
    entry.typed_queries = typed_queries;
    entry.run(&manifest, explicit)
}

/// # Safety
/// argv holds argc live non-null NUL-terminated UTF-8 arguments for this call.
/// No pointer is retained; all subprocess arguments are owned Rust strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn traceq_agent_query_main(argc: c_int, argv: *const *const c_char) -> c_int {
    // SAFETY: forwards the original argument contract; this entry delegates.
    unsafe { traceq_agent_query_main_with_context(argc, argv, None) }
}

/// # Safety
/// Same argv contract as traceq_agent_query_main. The optional linked handler
/// never unwinds, retains no argument/output pointers, and its code stays valid
/// until process exit. This is a terminal CLI entry: a timed-out owned worker
/// may remain active until the CLI process exits after this function returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn traceq_agent_query_main_with_context(
    argc: c_int,
    argv: *const *const c_char,
    context: Option<ContextHandler>,
) -> c_int {
    // SAFETY: forwards the documented argument and handler lifetime contract.
    unsafe { entry_ffi(argc, argv, context, false) }
}

/// # Safety
/// Same pointers and terminal-process lifetime contract as the context-only
/// entry. The read handler may decline before any output. Supported commands
/// are context, instructions and structured-profile2 mem-state; other formats
/// use the original CLI with the remaining time budget.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn traceq_agent_query_main_with_reads(
    argc: c_int,
    argv: *const *const c_char,
    handler: Option<ContextHandler>,
) -> c_int {
    // SAFETY: forwards the documented argument and handler lifetime contract.
    unsafe { entry_ffi(argc, argv, handler, true) }
}

unsafe fn entry_ffi(
    argc: c_int,
    argv: *const *const c_char,
    context: Option<ContextHandler>,
    structured_reads: bool,
) -> c_int {
    if argc < 0
        || (argc != 0
            && (argv.is_null()
                || !(argv as usize).is_multiple_of(std::mem::align_of::<*const c_char>())))
    {
        return 2;
    }
    let mut args = Vec::new();
    for index in 0..argc as usize {
        // SAFETY: the caller guarantees an array of argc live argument pointers.
        let pointer = unsafe { *argv.add(index) };
        if pointer.is_null() {
            return 2;
        }
        // SAFETY: each pointer is a live NUL-terminated argument.
        let Ok(value) = unsafe { CStr::from_ptr(pointer) }.to_str() else {
            return 2;
        };
        args.push(value.to_owned());
    }
    main_entry(args, context, structured_reads)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn execute_context(argv: Vec<String>, handler: ContextHandler, timeout: Duration) -> Outcome {
        match execute_read(argv, handler, timeout, false) {
            DirectResult::Completed(outcome) => outcome,
            DirectResult::Delegate => panic!("context-only handler cannot delegate"),
        }
    }
    unsafe extern "C" fn decline_probe(
        _argc: c_int,
        _argv: *const *const c_char,
        _output: ContextOutput,
        _user: *mut c_void,
    ) -> c_int {
        DELEGATE
    }
    unsafe extern "C" fn dirty_decline_probe(
        argc: c_int,
        argv: *const *const c_char,
        output: ContextOutput,
        user: *mut c_void,
    ) -> c_int {
        // SAFETY: forwards the owned live callback arguments.
        unsafe { direct_probe(argc, argv, output, user) };
        DELEGATE
    }
    unsafe extern "C" fn slow_decline_probe(
        _argc: c_int,
        _argv: *const *const c_char,
        _output: ContextOutput,
        _user: *mut c_void,
    ) -> c_int {
        thread::sleep(Duration::from_millis(120));
        DELEGATE
    }
    #[test]
    fn delegation_is_a_decision_and_cannot_publish_partial_success() {
        let argv = vec!["traceq".into(), "context".into(), "owned path".into()];
        assert!(matches!(
            execute_read(argv.clone(), decline_probe, Duration::from_secs(1), true),
            DirectResult::Delegate
        ));
        for (handler, allowed) in [
            (decline_probe as ContextHandler, false),
            (dirty_decline_probe, true),
        ] {
            let DirectResult::Completed(outcome) =
                execute_read(argv.clone(), handler, Duration::from_secs(1), allowed)
            else {
                panic!("invalid delegation must fail");
            };
            assert_eq!(outcome.status, 1);
            assert!(!outcome.launched);
            assert_eq!(
                serde_json::from_slice::<Value>(&outcome.stdout).unwrap()["error"]["code"],
                "QUERY_OUTPUT"
            );
            if allowed {
                assert_eq!(outcome.partial_stdout, b"facts");
            }
        }
    }
    #[test]
    fn format_probe_and_fallback_share_one_deadline() {
        let argv = vec![
            "/bin/sh".into(),
            "-c".into(),
            "sleep 0.12; printf late".into(),
        ];
        let outcome = execute_selected_read(
            &argv,
            None,
            Path::new("/"),
            slow_decline_probe,
            Duration::from_millis(200),
            true,
        );
        assert_eq!(outcome.status, 124);
        assert_eq!(outcome.origin, Some("timeout"));
        assert!(outcome.launched && !outcome.in_process);
        assert!(outcome.partial_stdout.is_empty());
    }
    unsafe extern "C" fn direct_probe(
        argc: c_int,
        argv: *const *const c_char,
        output: ContextOutput,
        user: *mut c_void,
    ) -> c_int {
        // SAFETY: execute_context supplies all pointers for this call.
        let first = unsafe { CStr::from_ptr(*argv) }.to_bytes();
        assert_eq!(argc, 2);
        assert_eq!(first, b"context");
        unsafe { output(user, 0, b"facts".as_ptr(), 5) };
        unsafe { output(user, 1, b"diagnostic".as_ptr(), 10) };
        0
    }
    unsafe extern "C" fn delayed_probe(
        argc: c_int,
        argv: *const *const c_char,
        output: ContextOutput,
        user: *mut c_void,
    ) -> c_int {
        // SAFETY: forwards the live worker-owned argument and output contract.
        unsafe { direct_probe(argc, argv, output, user) };
        thread::sleep(Duration::from_millis(120));
        0
    }
    #[test]
    fn direct_context_retains_streams_and_deadline_without_a_child() {
        let argv = vec!["traceq".into(), "context".into(), "owned path".into()];
        let outcome = execute_context(argv.clone(), direct_probe, Duration::from_secs(1));
        assert_eq!(outcome.stdout, b"facts");
        assert_eq!(outcome.stderr, b"diagnostic");
        assert_eq!(outcome.status, 0);
        assert!(outcome.in_process && !outcome.launched);
        let started = Instant::now();
        let outcome = execute_context(argv, delayed_probe, Duration::from_millis(40));
        assert_eq!(outcome.partial_stdout, b"facts");
        assert_eq!(outcome.stderr, b"diagnostic");
        assert_eq!(outcome.status, 124);
        assert_eq!(outcome.origin, Some("timeout"));
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(outcome.in_process && !outcome.launched);
    }
    #[test]
    fn direct_context_nul_manifest_path_preserves_launch_failure_without_a_worker() {
        let argv = vec!["traceq".into(), "context".into(), "path\0tail".into()];
        let outcome = execute_context(argv, direct_probe, Duration::from_secs(1));
        assert_eq!(outcome.status, 127);
        assert_eq!(outcome.origin, Some("launch"));
        assert!(!outcome.in_process && !outcome.launched && outcome.stderr.is_empty());
        assert_eq!(
            serde_json::from_slice::<Value>(&outcome.stdout).unwrap()["error"]["code"],
            "QUERY_LAUNCH"
        );
    }
    #[test]
    fn timeout_retains_partial_streams_and_kills_wrapper_group() {
        let argv = vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf partial; printf diagnostic >&2; sleep 20 & wait".into(),
        ];
        let started = Instant::now();
        let outcome = execute(&argv, None, Path::new("/"), Duration::from_millis(80));
        assert_eq!(outcome.status, 124);
        assert_eq!(outcome.partial_stdout, b"partial");
        assert_eq!(outcome.stderr, b"diagnostic");
        assert!(started.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn policy_and_numeric_compatibility_boundaries() {
        let policy = policy();
        assert_eq!(policy["row_limits"]["default"], 40);
        assert_eq!(policy["row_limits"]["maximum"], 256);
        assert_eq!(policy["memory_state_limits"]["maximum"], 4096);
        for value in ["32", "0x20", "040", "0o40"] {
            assert_eq!(parse_limit(value, true), Some(32));
        }
        assert_eq!(parse_limit("0x20", false), None);
        assert_eq!(parse_limit("09", true), None);
    }
    #[test]
    fn launch_failure_and_child_signal_are_distinct() {
        let missing = execute(
            &["/no/such/traceq-executable".into()],
            None,
            Path::new("/"),
            TIMEOUT,
        );
        assert_eq!(missing.status, 127);
        assert!(!missing.launched);
        let signal = execute(
            &["/bin/sh".into(), "-c".into(), "kill -TERM $$".into()],
            None,
            Path::new("/"),
            TIMEOUT,
        );
        assert_eq!(signal.status, -15);
        assert!(signal.launched);
    }
    #[test]
    fn invalid_ffi_argument_arrays_are_rejected_before_io() {
        // SAFETY: each deliberately invalid array is rejected without a read.
        assert_eq!(unsafe { traceq_agent_query_main(-1, std::ptr::null()) }, 2);
        assert_eq!(unsafe { traceq_agent_query_main(1, std::ptr::null()) }, 2);
        let invalid_utf8 = [255u8, 0];
        let argv = [invalid_utf8.as_ptr().cast::<c_char>()];
        // SAFETY: the single argument is live/NUL-terminated; UTF-8 is checked.
        assert_eq!(unsafe { traceq_agent_query_main(1, argv.as_ptr()) }, 2);
    }
}
