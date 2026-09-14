use rolediff::{Options, Report, Runner, Suite};
use std::{
    env,
    fs::File,
    io::{self, IsTerminal, Read, Write},
    time::Duration,
};

const BANNER: &str = "\n     [ alice ] --+        R O L E D I F F\n     [  bob  ] --+--> ?   Test who can access what.\n     [ admin ] --+\n     [ guest ] --+        Authorization regression tests / Rust\n\n";
const USAGE: &str = "Usage: rolediff [flags] [suite.json|-]\n\n  -json                  emit JSON\n  -validate              validate without sending requests\n  -timeout-ms N          timeout per request (default 5000)\n  -delay-ms N            delay between requests (default 100)\n  -max-requests N        maximum planned requests (default 256)\n  -max-response-bytes N  response byte limit (default 1048576)\n\nNo file means stdin. Put flags before the file.\nExit: 0 = pass; 1 = assertion failure; 2 = configuration or runtime error.\n";

fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    if (args.is_empty() && io::stdin().is_terminal())
        || args
            .first()
            .is_some_and(|s| ["-h", "--help", "help"].contains(&s.as_str()))
    {
        print!("{BANNER}{USAGE}");
        return;
    }
    let code = match run(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("rolediff: {message}");
            2
        }
    };
    std::process::exit(code);
}

fn run(args: &[String]) -> Result<i32, String> {
    let mut options = Options {
        delay: Duration::from_millis(100),
        ..Options::default()
    };
    let mut as_json = false;
    let mut validate = false;
    let mut file = None;
    let mut i = 0;
    while i < args.len() {
        let argument = &args[i];
        if argument == "-" || !argument.starts_with('-') {
            if i + 1 != args.len() {
                return Err("expected one suite file; flags must precede it".into());
            }
            file = Some(argument.clone());
            break;
        }
        match argument.trim_start_matches('-') {
            "json" => as_json = true,
            "validate" => validate = true,
            "timeout-ms" | "delay-ms" | "max-requests" | "max-response-bytes" => {
                i += 1;
                let value: u64 = args
                    .get(i)
                    .ok_or("missing flag value")?
                    .parse()
                    .map_err(|_| "invalid numeric flag value")?;
                match argument.trim_start_matches('-') {
                    "timeout-ms" => options.timeout = Duration::from_millis(value),
                    "delay-ms" => options.delay = Duration::from_millis(value),
                    "max-requests" => {
                        options.max_requests =
                            usize::try_from(value).map_err(|_| "invalid request limit")?
                    }
                    _ => options.max_response_bytes = value,
                }
            }
            _ => return Err("unknown flag; use -h for help".into()),
        }
        i += 1;
    }
    let reader: Box<dyn Read> = match file.as_deref() {
        None | Some("-") => Box::new(io::stdin()),
        Some(path) => Box::new(File::open(path).map_err(|_| "cannot open suite file")?),
    };
    let runner = Runner::new(Suite::read(reader)?, options)?;
    if validate {
        println!(
            "{{\"valid\":true,\"planned_requests\":{}}}",
            runner.planned_requests()
        );
        return Ok(0);
    }
    let report = runner.run();
    let mut stdout = io::stdout().lock();
    if as_json {
        serde_json::to_writer_pretty(&mut stdout, &report).map_err(|_| "cannot write output")?;
        writeln!(stdout).map_err(|_| "cannot write output")?;
    } else {
        render(&mut stdout, &report).map_err(|_| "cannot write output")?;
    }
    Ok(report.exit_code())
}

fn render(out: &mut impl Write, report: &Report) -> io::Result<()> {
    writeln!(
        out,
        "{:<24} {:<16} {:<10} {:<8} {:<6} DETAIL",
        "CASE", "IDENTITY", "EXPECTED", "RESULT", "HTTP"
    )?;
    for row in &report.results {
        let mut detail = row.error.clone().unwrap_or_default();
        for failure in &row.failures {
            if !detail.is_empty() {
                detail += ", ";
            }
            detail += &failure.code;
            if failure.assertion > 0 {
                detail += &format!(" #{}", failure.assertion);
            }
        }
        writeln!(
            out,
            "{:<24} {:<16} {:<10} {:<8} {:<6} {}",
            row.case,
            row.identity,
            row.expected,
            row.outcome,
            row.http_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into()),
            detail
        )?;
    }
    writeln!(
        out,
        "\n{} passed, {} failed, {} errors, {} skipped",
        report.passed, report.failed, report.errors, report.skipped
    )
}
