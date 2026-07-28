// crates/common/src/log_format.rs
//
// Shared ANSI-colored logging formatter for synapse-agent and synapsed-helper.
// Uses env_logger::Builder with a custom format fn to colorize output on TTYs.

use colored::Colorize;
use log::Level;
use std::io::Write;

/// Initialize the global logger with ANSI color formatting.
/// Call once at startup in each binary (agent, helper).
pub fn init_logging() {
    let mut builder = env_logger::Builder::from_default_env();

    builder.format(|f, record| {
        let now = chrono_time();
        let level = record.level();
        let target = record.target();

        let ts = format!("[{now}]").dimmed();
        let tgt = format!("[{target}]").dimmed();
        let msg = record.args().to_string();

        let (lvl_str, msg_str) = colorize(level, &msg);

        writeln!(f, "{ts} {lvl_str} {tgt} {msg_str}")
    });

    builder.init();
}

/// Map log level + message content to colored output.
fn colorize(level: Level, msg: &str) -> (colored::ColoredString, colored::ColoredString) {
    match level {
        Level::Error => (level.to_string().bold().red(), msg.bold().red()),
        Level::Warn | Level::Debug | Level::Trace => {
            let lvl = level.to_string().bold().yellow();
            let m = msg.bold().yellow();
            (lvl, m)
        }
        Level::Info => {
            let lvl = level.to_string().green();
            if msg.contains("[BLOCK]") || msg.contains("BLOCK flow") {
                (lvl, msg.bold().red())
            } else if msg.contains("[ENFORCE]") || msg.contains("enforcement command sent") {
                (lvl, msg.bold().green())
            } else if msg.contains("[ALERT]") || msg.contains("[SKIP]") {
                (lvl, msg.bold().yellow())
            } else if msg.contains("flow") && msg.contains("created") || msg.contains("enrich:") {
                (lvl, msg.cyan())
            } else {
                (lvl, msg.normal())
            }
        }
    }
}

/// Format current time as HH:MM:SS using std only.
fn chrono_time() -> String {
    let Ok(dur) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return "??:??:??".into();
    };
    let secs = dur.as_secs();
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}
