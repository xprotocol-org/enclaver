use anyhow::{Result, anyhow};
use futures_util::stream::StreamExt;
use log::{LevelFilter, info};
use std::future::Future;
use std::path::PathBuf;
use tokio::io::AsyncRead;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::codec::{FramedRead, LinesCodec};

const LOG_LINE_MAX_LEN: usize = 4 * 1024;

#[cfg(feature = "tracing")]
#[macro_export]
macro_rules! spawn {
    ($name:expr, $body:expr) => {{
        tokio::task::Builder::new()
            .name($name)
            .spawn($body)
            .map_err(anyhow::Error::from)
    }};
}

#[cfg(not(feature = "tracing"))]
#[macro_export]
macro_rules! spawn {
    ($name:expr, $body:expr) => {{ Result::<_, anyhow::Error>::Ok(tokio::task::spawn($body)) }};
}

pub use spawn;

pub fn init_logging(verbosity: u8) {
    fn level_filter(verbosity: u8) -> LevelFilter {
        match verbosity {
            0 => LevelFilter::Info,
            1 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        }
    }

    pretty_env_logger::formatted_builder()
        .filter_module("bollard", level_filter(verbosity.saturating_sub(1)))
        .filter_module("hyper", level_filter(verbosity.saturating_sub(2)))
        .filter_module("tokio", level_filter(verbosity.saturating_sub(3)))
        .filter_module("tracing", level_filter(verbosity.saturating_sub(3)))
        .filter_level(level_filter(verbosity))
        .format_timestamp(None)
        .init();
}

pub trait StringablePathExt {
    fn must_to_str(&self) -> Result<&str>;
    fn must_to_string(&self) -> Result<String>;
}

impl StringablePathExt for PathBuf {
    fn must_to_str(&self) -> Result<&str> {
        self.to_str()
            .ok_or_else(|| anyhow!("filename contains non-UTF-8 characters"))
    }

    fn must_to_string(&self) -> Result<String> {
        self.to_str()
            .ok_or_else(|| anyhow!("filename contains non-UTF-8 characters"))
            .map(|s| s.to_string())
    }
}

pub async fn log_lines_from_stream<S>(target: &str, stream: S) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut framed = FramedRead::new(stream, LinesCodec::new_with_max_length(LOG_LINE_MAX_LEN));

    while let Some(line_res) = framed.next().await {
        match line_res {
            Ok(line) => info!(target: target, "{line}"),
            Err(e) => info!(target: target, "error reading log stream: {e}"),
        }
    }

    Ok(())
}

/// Expand environment variables in a string.
/// Supports ${VAR_NAME} syntax (brace notation) and bash parameter expansion.
/// Variables not found in the environment are left unchanged.
/// Supports default values with ${VAR_NAME:-default} syntax.
/// Returns the expanded string.
pub fn expand_env_vars(input: &str) -> String {
    let mut result = input.to_string();
    let mut pos = 0;

    while let Some(start) = result[pos..].find("${") {
        let absolute_start = pos + start;

        // Look for the closing brace
        if let Some(end) = result[absolute_start + 2..].find('}') {
            let var_start = absolute_start + 2;
            let var_end = absolute_start + 2 + end;
            let var_content = &result[var_start..var_end];

            // Parse variable name and default value
            let (var_name, default_value) = if let Some(colon_dash_pos) = var_content.find(":-") {
                let name = &var_content[..colon_dash_pos];
                let default = &var_content[colon_dash_pos + 2..];
                (name, Some(default))
            } else {
                (var_content, None)
            };

            // Check if variable name is valid (not empty, no special chars except for :- syntax)
            if var_name.is_empty() || var_name.chars().any(|c| !c.is_alphanumeric() && c != '_') {
                // Invalid variable name, skip this occurrence
                pos = var_end + 1;
                continue;
            }

            let replacement_value = match std::env::var(var_name) {
                Ok(var_value) if !var_value.is_empty() => var_value,
                _ => {
                    // Variable not found, empty, or we have a default
                    if let Some(default) = default_value {
                        default.to_string()
                    } else {
                        // No default provided, leave as-is
                        pos = var_end + 1;
                        continue;
                    }
                }
            };

            // Replace this specific occurrence
            let before = &result[..absolute_start];
            let after = &result[var_end + 1..];
            result = format!("{}{}{}", before, replacement_value, after);

            // Adjust position to account for the replacement
            pos = absolute_start + replacement_value.len();
        } else {
            // Malformed ${ syntax, stop processing
            break;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::expand_env_vars;
    use std::env;

    #[test]
    fn test_expand_env_vars_brace_syntax() {
        unsafe {
            env::set_var("TEST_VAR", "expanded_value");
            env::set_var("ANOTHER_VAR", "another_value");
        }

        assert_eq!(expand_env_vars("${TEST_VAR}"), "expanded_value");
        assert_eq!(expand_env_vars("prefix${TEST_VAR}suffix"), "prefixexpanded_valuesuffix");
        assert_eq!(expand_env_vars("${TEST_VAR}${ANOTHER_VAR}"), "expanded_valueanother_value");
        assert_eq!(expand_env_vars("no vars here"), "no vars here");

        // Test undefined variable (should remain unchanged)
        assert_eq!(expand_env_vars("${UNDEFINED_VAR}"), "${UNDEFINED_VAR}");

        unsafe {
            env::remove_var("TEST_VAR");
            env::remove_var("ANOTHER_VAR");
        }
    }

    #[test]
    fn test_expand_env_vars_multiple_and_mixed() {
        unsafe {
            env::set_var("DEFINED_VAR", "defined");
            env::set_var("ANOTHER_DEFINED", "another");
        }

        // Test multiple variables, some defined, some not
        assert_eq!(
            expand_env_vars("${DEFINED_VAR} and ${UNDEFINED_VAR} and ${ANOTHER_DEFINED}"),
            "defined and ${UNDEFINED_VAR} and another"
        );

        // Test same variable multiple times
        assert_eq!(
            expand_env_vars("${DEFINED_VAR} ${DEFINED_VAR}"),
            "defined defined"
        );

        // Test default value syntax
        assert_eq!(
            expand_env_vars("registry: ${REGISTRY:-default}/app:${TAG}"),
            "registry: default/app:${TAG}"
        );

        unsafe {
            env::remove_var("DEFINED_VAR");
            env::remove_var("ANOTHER_DEFINED");
        }
    }

    #[test]
    fn test_expand_env_vars_default_values() {
        unsafe {
            env::set_var("SET_VAR", "set_value");
            env::set_var("EMPTY_VAR", "");
        }

        // Test default value when variable is not set
        assert_eq!(expand_env_vars("${UNSET_VAR:-default}"), "default");

        // Test default value when variable is set
        assert_eq!(expand_env_vars("${SET_VAR:-default}"), "set_value");

        // Test default value when variable is empty
        assert_eq!(expand_env_vars("${EMPTY_VAR:-default}"), "default");

        // Test default value with special characters
        assert_eq!(expand_env_vars("${UNSET_VAR:-964667871994}"), "964667871994");

        // Test default value in complex string
        assert_eq!(
            expand_env_vars("prefix${UNSET_VAR:-middle}suffix"),
            "prefixmiddlesuffix"
        );

        // Test multiple defaults
        assert_eq!(
            expand_env_vars("${VAR1:-val1} ${VAR2:-val2}"),
            "val1 val2"
        );

        unsafe {
            env::remove_var("SET_VAR");
            env::remove_var("EMPTY_VAR");
        }
    }


    #[test]
    fn test_expand_env_vars_edge_cases() {
        unsafe {
            env::set_var("VALID_VAR", "valid");
            env::set_var("VAR_WITH_UNDERSCORE", "underscore");
        }

        // Test empty variable name
        assert_eq!(expand_env_vars("${}"), "${}");

        // Test invalid variable names
        assert_eq!(expand_env_vars("${VAR-NAME}"), "${VAR-NAME}");
        assert_eq!(expand_env_vars("${VAR.NAME}"), "${VAR.NAME}");

        // Test valid underscore
        assert_eq!(expand_env_vars("${VAR_WITH_UNDERSCORE}"), "underscore");

        // Test unclosed braces
        assert_eq!(expand_env_vars("${UNDEFINED"), "${UNDEFINED");

        // Test valid expansion
        assert_eq!(expand_env_vars("${VALID_VAR}"), "valid");

        unsafe {
            env::remove_var("VALID_VAR");
            env::remove_var("VAR_WITH_UNDERSCORE");
        }
    }
}

pub async fn register_shutdown_signal_handler() -> Result<impl Future> {
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    spawn!("signal handler", async move {
        tokio::select! {
            _ = sigint.recv() => (),
            _ = sigterm.recv() => (),
        }
    })
}
