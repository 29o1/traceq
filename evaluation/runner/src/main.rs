//! Standalone evaluation entry. Packed tasks may name this binary traceq.
#![deny(unsafe_op_in_unsafe_fn)]
mod agent;

use std::io::Write;
use traceq_query::cli::{self, Response};

fn run_compatible_query(args: &[String], backend: Option<&str>) -> Response {
    if let Some(command @ ("context" | "instructions" | "reg-state" | "mem-state")) =
        args.first().map(String::as_str)
        && backend.is_some_and(|value| !matches!(value, "rust" | "cpp"))
        && !args.iter().any(|s| matches!(s.as_str(), "--help" | "-h"))
    {
        let message = "TRACEQ_QUERY_BACKEND must be rust or cpp";
        let (stdout, stderr) = if args.iter().any(|arg| arg == "--json") {
            let error = serde_json::json!({"error":{"code":"ARGUMENT","message":message}});
            (format!("{error}\n").into_bytes(), Vec::new())
        } else {
            (Vec::new(), format!("{command}: {message}\n").into_bytes())
        };
        return Response {
            stdout,
            stderr,
            status: 2,
        };
    }
    cli::run(args)
}

fn main() {
    let raw: Vec<_> = std::env::args_os().skip(1).collect();
    let json = raw.iter().any(|arg| arg == "--json");
    let args = match raw
        .into_iter()
        .map(|arg| arg.into_string())
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(args) => args,
        Err(_) => {
            let result = if json {
                std::io::stdout().write_all(b"{\"error\":{\"code\":\"ARGUMENT\",\"message\":\"arguments require valid UTF-8\"}}\n")
            } else {
                std::io::stderr().write_all(b"traceq: arguments require valid UTF-8\n")
            };
            std::process::exit(if result.is_ok() { 2 } else { 74 });
        }
    };
    if args.first().is_some_and(|s| s == "agent-query") {
        std::process::exit(agent::native_main(args[1..].to_vec()));
    }
    let response =
        run_compatible_query(&args, std::env::var("TRACEQ_QUERY_BACKEND").ok().as_deref());
    let ok = std::io::stdout().write_all(&response.stdout).is_ok()
        && std::io::stderr().write_all(&response.stderr).is_ok();
    std::process::exit(if ok { response.status } else { 74 });
}
