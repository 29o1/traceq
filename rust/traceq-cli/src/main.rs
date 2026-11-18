use std::io::Write;
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
        std::process::exit(traceq_query::agent_main(args[1..].to_vec()));
    }
    let response = traceq_query::cli::run(&args);
    let ok = std::io::stdout().write_all(&response.stdout).is_ok()
        && std::io::stderr().write_all(&response.stderr).is_ok();
    std::process::exit(if ok { response.status } else { 74 });
}
