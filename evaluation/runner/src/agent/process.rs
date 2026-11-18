//! Bounded output and cleanup for a manifest-selected compatible CLI.
use super::{Outcome, error_document};
use std::{
    ffi::c_int,
    io::{self, Read},
    os::{
        fd::OwnedFd,
        unix::{
            net::UnixStream,
            process::{CommandExt, ExitStatusExt},
        },
    },
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const STREAM_LIMITS: [usize; 2] = [32 * 1024 * 1024, 1024 * 1024];
const REAP_WINDOW: Duration = Duration::from_millis(100);
const IDLE: Duration = Duration::from_millis(1);

unsafe extern "C" {
    fn killpg(group: c_int, signal: c_int) -> c_int;
}

fn channel() -> io::Result<(UnixStream, Stdio)> {
    let (reader, writer) = UnixStream::pair()?;
    reader.set_nonblocking(true)?;
    Ok((reader, Stdio::from(OwnedFd::from(writer))))
}

fn stop(child: &mut Child) {
    if let Ok(group) = c_int::try_from(child.id()) {
        // SAFETY: process_group(0) created a private group. The child has not
        // been reaped, so its PID cannot have been recycled.
        unsafe { killpg(group, 9) };
    }
    let _ = child.kill();
    let started = Instant::now();
    while matches!(child.try_wait(), Ok(None)) && started.elapsed() < REAP_WINDOW {
        thread::sleep(IDLE);
    }
}

enum Failure {
    Timeout,
    Output(String),
}

fn capture(
    child: &mut Child,
    mut streams: [Option<UnixStream>; 2],
    output: &mut [Vec<u8>; 2],
    timeout: Duration,
    limits: [usize; 2],
) -> Result<ExitStatus, Failure> {
    let started = Instant::now();
    let mut scratch = [0; 16 * 1024];
    loop {
        if started.elapsed() >= timeout {
            return Err(Failure::Timeout);
        }
        let mut progressed = false;
        let mut overflow = None;
        for index in 0..streams.len() {
            let Some(stream) = &mut streams[index] else {
                continue;
            };
            match stream.read(&mut scratch) {
                Ok(0) => streams[index] = None,
                Ok(count) => {
                    progressed = true;
                    let kept = count.min(limits[index] - output[index].len());
                    output[index].extend_from_slice(&scratch[..kept]);
                    if kept != count {
                        overflow.get_or_insert(index);
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(Failure::Output(e.to_string())),
            }
        }
        if let Some(index) = overflow {
            let name = ["stdout", "stderr"][index];
            return Err(Failure::Output(format!(
                "query {name} exceeded {} bytes",
                limits[index]
            )));
        }
        // Keep the child PID reserved while a descendant still holds a writer.
        if streams.iter().all(Option::is_none)
            && let Some(status) = child
                .try_wait()
                .map_err(|e| Failure::Output(e.to_string()))?
        {
            return Ok(status);
        }
        if !progressed {
            thread::sleep(IDLE);
        }
    }
}

pub(super) fn execute(
    argv: &[String],
    backend: Option<&str>,
    directory: &Path,
    timeout: Duration,
) -> Outcome {
    execute_bounded(argv, backend, directory, timeout, STREAM_LIMITS)
}

fn execute_bounded(
    argv: &[String],
    backend: Option<&str>,
    directory: &Path,
    timeout: Duration,
    limits: [usize; 2],
) -> Outcome {
    let spawn = || -> io::Result<_> {
        let (stdout, stdout_writer) = channel()?;
        let (stderr, stderr_writer) = channel()?;
        let mut command = Command::new(&argv[0]);
        command
            .args(&argv[1..])
            .current_dir(directory)
            .stdin(Stdio::null())
            .stdout(stdout_writer)
            .stderr(stderr_writer)
            .process_group(0);
        if let Some(backend) = backend {
            command.env("TRACEQ_QUERY_BACKEND", backend);
        }
        Ok((command.spawn()?, [Some(stdout), Some(stderr)]))
    };
    let (mut child, streams) = match spawn() {
        Ok(pair) => pair,
        Err(error) => return Outcome::launch_failure(&error.to_string()),
    };
    let mut output = [Vec::new(), Vec::new()];
    let status = capture(&mut child, streams, &mut output, timeout, limits);
    let [stdout, stderr] = output;
    match status {
        Ok(status) => {
            let code = status
                .code()
                .unwrap_or_else(|| -status.signal().unwrap_or(1));
            Outcome {
                stdout,
                stderr,
                partial_stdout: Vec::new(),
                status: code,
                origin: (code != 0).then_some("cli"),
                launched: true,
                in_process: false,
            }
        }
        Err(failure) => {
            stop(&mut child);
            let (code, origin, message, status) = match failure {
                Failure::Timeout => (
                    "QUERY_TIMEOUT",
                    "timeout",
                    "traceq exceeded 90 seconds".into(),
                    124,
                ),
                Failure::Output(message) => ("QUERY_OUTPUT", "cli", message, 1),
            };
            Outcome {
                stdout: error_document(code, origin, &message, None),
                stderr,
                partial_stdout: stdout,
                status,
                origin: Some(origin),
                launched: true,
                in_process: false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_budget_keeps_only_the_bounded_prefix() {
        for (command, is_stdout) in [
            ("printf note >&2; printf 123456", true),
            ("printf 123456 >&2", false),
        ] {
            let args = ["/bin/sh".into(), "-c".into(), command.into()];
            let outcome =
                execute_bounded(&args, None, Path::new("/"), Duration::from_secs(2), [4, 4]);
            assert_eq!(outcome.status, 1);
            assert!(outcome.stdout.windows(12).any(|s| s == b"QUERY_OUTPUT"));
            if is_stdout {
                assert_eq!(outcome.stderr, b"note");
            }
            let retained = if is_stdout {
                outcome.partial_stdout
            } else {
                outcome.stderr
            };
            assert_eq!(retained, b"1234");
        }
    }

    #[test]
    fn idle_open_stream_has_a_deadline_even_after_child_exits() {
        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        let (reader, _still_open) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let start = Instant::now();
        let mut output = [Vec::new(), Vec::new()];
        let result = capture(
            &mut child,
            [Some(reader), None],
            &mut output,
            Duration::from_millis(50),
            [4, 4],
        );
        child.wait().unwrap();
        assert!(matches!(result, Err(Failure::Timeout)));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
