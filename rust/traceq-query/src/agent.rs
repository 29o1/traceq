//! Recorded read entry for Agents. Query semantics remain in the existing CLI.
use serde_json::{Value, json};
use std::{
    ffi::c_int,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::unix::process::{CommandExt, ExitStatusExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const TIMEOUT: Duration = Duration::from_secs(90);
const HELP: &str = "traceq agent-query [--manifest tools.json] TRACE_ID COMMAND [options]\n\
Recorded, bounded read entry; query stdout/stderr and trace validation are unchanged.\n\
Navigation/search row limit defaults to 40 (maximum 256).\n\
last-writers uses the CLI's 20-row default (maximum 4096).\n\
mem-state byte limit defaults to 40 (maximum 4096 per checkpoint/page budget).\n\
No --all or -o. Use bounded queries and shell redirection.\n\
Relative executable/trace paths and queries/ logs are relative to the manifest.\n\
--capabilities prints the query policy; --help prints this help.\n\
Help/capabilities are recorded with an explicit --manifest; neither reads a trace.\n\
All supported queries use the linked Rust core and presentation in this process\n\
when the manifest selects this executable. Backend names are compatibility labels.\n\
Other executable selections launch a CLI child.\n\
Every trace query retains its normal full validation; the log records its execution path.\n";

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
        let execution = if outcome.in_process {
            "in_process"
        } else if outcome.launched {
            "subprocess"
        } else {
            "none"
        };
        let record = json!({
            "log_schema": 2,
            "id": id,
            "trace": self.trace,
            "command": self.command,
            "requested_options": self.requested,
            "options": self.options,
            "argv": self.argv,
            "query_backend": self.backend,
            "configured_context_format": self.format,
            "context_format": context_format,
            "launched_cli": outcome.launched,
            "failure_origin": outcome.origin,
            "started_ns": self.started_ns,
            "finished_ns": finished,
            "seconds": seconds,
            "returncode": outcome.status,
            "stdout_bytes": outcome.stdout.len(),
            "stderr_bytes": outcome.stderr.len(),
            "partial_stdout_bytes": outcome.partial_stdout.len(),
            "entry_kind": "rust",
            "request_kind": self.kind,
            "execution_path": execution,
            "query_execution": outcome.launched || outcome.in_process,
            "delegated_argv": if outcome.launched { &self.argv } else { &None }
        });
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
        let limits = if command == "mem-state" {
            Some(&policy["memory_state_limits"])
        } else if member(&policy["row_limits"], "commands", command) {
            Some(&policy["row_limits"])
        } else {
            None
        };
        if let Some(limits) =
            limits.filter(|_| !self.options.iter().any(|v| v == "--help" || v == "-h"))
        {
            let maximum = limits["maximum"].as_u64().expect("page maximum");
            let last = command == "find-value" && self.options.iter().any(|v| v == "--last");
            let page_flag = if last { "--last" } else { "--limit" };
            if last
                && self
                    .options
                    .iter()
                    .any(|v| v == "--limit" || v == "--offset")
            {
                return self.reject(
                    "--last cannot mix with --limit or --offset",
                    "ARGUMENT",
                    &policy,
                );
            }
            if self.options.iter().filter(|v| *v == page_flag).count() > 1 {
                return self.reject(
                    &format!("Specify {page_flag} once; maximum is {maximum}"),
                    "ARGUMENT",
                    &policy,
                );
            }
            if !self.options.iter().any(|v| v == page_flag) {
                self.options
                    .extend([page_flag.into(), limits["default"].to_string()]);
            }
            let limit = self
                .options
                .iter()
                .position(|v| v == page_flag)
                .and_then(|at| self.options.get(at + 1))
                .and_then(|value| crate::cli::parse_page_number(command, value).ok());
            let Some(limit) = limit else {
                return self.reject(
                    &format!("{page_flag} requires an integer from 1 to {maximum}"),
                    "ARGUMENT",
                    &policy,
                );
            };
            if limit == 0 || limit > maximum {
                return self.reject(
                    &format!(
                        "Per-query {page_flag} must be 1..{maximum}; page or select evidence."
                    ),
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
        let outcome = if direct_native(executable) {
            execute_native(
                argv[1..].to_vec(),
                self.backend
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| std::env::var("TRACEQ_QUERY_BACKEND").ok()),
                TIMEOUT,
            )
        } else {
            execute(&argv, self.backend.as_str(), &self.directory, TIMEOUT)
        };
        self.argv = Some(argv);
        self.finish(outcome)
    }
}
pub fn native_main(args: Vec<String>) -> i32 {
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
    let directory = manifest.parent().map_or(directory, Path::to_path_buf);
    Entry::new(rest, directory, started, started_ns).run(&manifest, explicit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_nul_path_is_a_launch_failure() {
        let outcome = execute_native(
            vec!["context".into(), "path\0tail".into()],
            None,
            Duration::from_secs(1),
        );
        assert_eq!(outcome.status, 127);
        assert_eq!(outcome.origin, Some("launch"));
        assert!(!outcome.in_process && !outcome.launched);
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
}
