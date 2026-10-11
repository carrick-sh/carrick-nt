//! Windows container oracle capture harness.
//!
//! Orchestrates running clean-room PE executables inside a Windows container on
//! a remote Windows Server 2025 host reached over SSH. Captures stdout, stderr,
//! exit code, and cryptographic hashes, generating an immutable `OracleReceipt`.

use crate::receipt::{compute_sha256, OracleReceipt};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use thiserror::Error;

/// Pinned base image digest for Windows Server 2025 Nano Server:
/// Nano Server is chosen over Server Core because:
/// 1. Footprint & Speed: Nano Server is ~150 MB compressed with sub-second startup,
///    compared to Server Core which is ~3.5-5.0 GB with 10-30s initialization.
/// 2. Minimal Surface: Provides the complete clean-room console Win32/NT runtime
///    (ntdll.dll, kernel32.dll, kernelbase.dll) without legacy COM, GUI, or shell bloat.
/// 3. Zero Persistent State: Ideal for ephemeral, disposable container runs.
pub const DEFAULT_PINNED_NANOSERVER_IMAGE: &str =
    "mcr.microsoft.com/windows/nanoserver:ltsc2025@sha256:15760261db306980fd96acf7e2c73779eaaeefdff289339b9526295c88957e56";

#[derive(Debug, Error)]
pub enum HarnessError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Binary not found: {0}")]
    BinaryNotFound(PathBuf),
    #[error("SCP upload failed: {0}")]
    ScpFailed(String),
    #[error("SSH execution failed: {0}")]
    SshFailed(String),
    #[error("Infrastructure failure (container create/exec error): {0}")]
    InfrastructureError(String),
    #[error("Execution timed out after {0:?}")]
    Timeout(Duration),
    #[error("Failed to parse remote receipt JSON: {0}\nRemote output:\n{1}")]
    InvalidRemoteReceipt(serde_json::Error, String),
    #[error("Binary SHA256 mismatch: local={local}, remote={remote}")]
    BinaryHashMismatch { local: String, remote: String },
}

/// Classifies whether an execution result represents an infrastructure or container engine failure
/// (e.g. HCS create/exec failure, daemon error, access denied bind mount, Docker exit 125)
/// rather than a normal target program exit.
pub fn classify_infrastructure_error(exit_code: i32, stderr: &str) -> Option<String> {
    if exit_code == 125
        || stderr.contains("hcs::")
        || stderr.contains("docker: Error response from daemon")
        || stderr.contains("failure in a Windows system call: Access is denied")
    {
        Some(if stderr.trim().is_empty() {
            format!("Docker container engine error (exit code {exit_code})")
        } else {
            stderr.trim().to_string()
        })
    } else {
        None
    }
}

/// Configuration parameters for a capture run.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub test_name: String,
    pub binary_path: PathBuf,
    pub source_path: Option<PathBuf>,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub ssh_key: Option<PathBuf>,
    pub remote_temp_dir: String,
    pub container_image: String,
    pub timeout_seconds: u64,
    pub output_receipt_path: Option<PathBuf>,
    pub app_args: Option<String>,
    pub env_vars: Vec<String>,
}

impl CaptureConfig {
    pub fn new(
        test_name: impl Into<String>,
        binary_path: impl Into<PathBuf>,
        ssh_host: impl Into<String>,
    ) -> Self {
        Self {
            test_name: test_name.into(),
            binary_path: binary_path.into(),
            source_path: None,
            ssh_host: ssh_host.into(),
            ssh_port: 22,
            ssh_key: None,
            remote_temp_dir: "C:\\carrick-oracle".to_string(),
            container_image: DEFAULT_PINNED_NANOSERVER_IMAGE.to_string(),
            timeout_seconds: 30,
            output_receipt_path: None,
            app_args: None,
            env_vars: Vec::new(),
        }
    }
}

/// Plan describing the exact commands and operations that the capture harness will execute.
#[derive(Debug, Clone)]
pub struct ExecutionPlan {
    pub scp_command: String,
    pub ssh_command: String,
    pub remote_script_invocation: String,
    pub pinned_image: String,
    pub image_rationale: &'static str,
}

fn format_ps_invocation(config: &CaptureConfig, remote_ps1: &str, remote_bin: &str) -> String {
    let app_args_flag = if let Some(args) = &config.app_args {
        format!(" -AppArgs \"{args}\"")
    } else {
        String::new()
    };
    let env_vars_flag = if !config.env_vars.is_empty() {
        let items = config.env_vars.join(",");
        format!(" -EnvVars \"{items}\"")
    } else {
        String::new()
    };

    format!(
        "powershell -NoProfile -ExecutionPolicy Bypass -File \"{remote_ps1}\" -ExePath \"{remote_bin}\" -ImageTag \"{}\" -TimeoutSeconds {}{app_args_flag}{env_vars_flag}",
        config.container_image, config.timeout_seconds
    )
}

/// Generates the dry-run execution plan detailing exact commands without reaching the network.
pub fn generate_execution_plan(config: &CaptureConfig) -> ExecutionPlan {
    let binary_name = config
        .binary_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "hello_console.exe".to_string());

    let remote_dir = &config.remote_temp_dir;
    let remote_bin = format!("{remote_dir}\\{binary_name}");
    let remote_ps1 = format!("{remote_dir}\\oracle_runner.ps1");

    let port_flag = if config.ssh_port != 22 {
        format!("-P {}", config.ssh_port)
    } else {
        String::new()
    };
    let key_flag = if let Some(key) = &config.ssh_key {
        format!("-i {}", key.display())
    } else {
        String::new()
    };

    let scp_cmd = format!(
        "scp {port_flag} {key_flag} {} scripts/oracle_runner.ps1 {}:{remote_dir}\\",
        config.binary_path.display(),
        config.ssh_host
    );

    let ps_invocation = format_ps_invocation(config, &remote_ps1, &remote_bin);

    let ssh_cmd = format!(
        "ssh {port_flag} {key_flag} {} \"{ps_invocation}\"",
        config.ssh_host
    );

    ExecutionPlan {
        scp_command: scp_cmd.trim().to_string(),
        ssh_command: ssh_cmd.trim().to_string(),
        remote_script_invocation: ps_invocation,
        pinned_image: config.container_image.clone(),
        image_rationale: "Nano Server (mcr.microsoft.com/windows/nanoserver:ltsc2025) provides the minimal, fast headless Windows Server 2025 container environment with zero persistent state.",
    }
}

/// Executes the live capture harness over SSH.
pub fn execute_capture(config: &CaptureConfig) -> Result<OracleReceipt, HarnessError> {
    if !config.binary_path.exists() {
        return Err(HarnessError::BinaryNotFound(config.binary_path.clone()));
    }

    let binary_bytes = fs::read(&config.binary_path)?;
    let local_sha256 = compute_sha256(&binary_bytes);

    let source_bytes = if let Some(sp) = &config.source_path {
        if sp.exists() {
            Some(fs::read(sp)?)
        } else {
            None
        }
    } else {
        None
    };

    let binary_name = config
        .binary_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "test.exe".to_string());

    let remote_dir = &config.remote_temp_dir;
    let remote_bin = format!("{remote_dir}\\{binary_name}");
    let remote_ps1 = format!("{remote_dir}\\oracle_runner.ps1");

    // 1. Ensure remote directory exists
    let mut ssh_mkdir = Command::new("ssh");
    if config.ssh_port != 22 {
        ssh_mkdir.args(["-p", &config.ssh_port.to_string()]);
    }
    if let Some(key) = &config.ssh_key {
        ssh_mkdir.args(["-i", key.to_str().unwrap()]);
    }
    ssh_mkdir
        .arg(&config.ssh_host)
        .arg(format!("powershell -Command \"New-Item -ItemType Directory -Path '{remote_dir}' -Force | Out-Null\""));

    let status = ssh_mkdir.status()?;
    if !status.success() {
        return Err(HarnessError::SshFailed(format!(
            "Failed to create remote directory {remote_dir}"
        )));
    }

    // 2. Upload binary and runner script via SCP
    let mut scp = Command::new("scp");
    if config.ssh_port != 22 {
        scp.args(["-P", &config.ssh_port.to_string()]);
    }
    if let Some(key) = &config.ssh_key {
        scp.args(["-i", key.to_str().unwrap()]);
    }
    scp.arg(&config.binary_path);
    scp.arg("scripts/oracle_runner.ps1");
    scp.arg(format!("{}:{remote_dir}\\", config.ssh_host));

    let status = scp.status()?;
    if !status.success() {
        return Err(HarnessError::ScpFailed(format!(
            "Failed to upload files to {}:{remote_dir}\\",
            config.ssh_host
        )));
    }

    // 3. Execute runner over SSH
    let mut ssh_run = Command::new("ssh");
    if config.ssh_port != 22 {
        ssh_run.args(["-p", &config.ssh_port.to_string()]);
    }
    if let Some(key) = &config.ssh_key {
        ssh_run.args(["-i", key.to_str().unwrap()]);
    }
    let ps_cmd = format_ps_invocation(config, &remote_ps1, &remote_bin);
    ssh_run.arg(&config.ssh_host).arg(ps_cmd);

    let output = ssh_run.output()?;
    let stdout_str = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr_str = String::from_utf8_lossy(&output.stderr).into_owned();

    // 4. Clean up remote temp directory
    let mut ssh_clean = Command::new("ssh");
    if config.ssh_port != 22 {
        ssh_clean.args(["-p", &config.ssh_port.to_string()]);
    }
    if let Some(key) = &config.ssh_key {
        ssh_clean.args(["-i", key.to_str().unwrap()]);
    }
    ssh_clean.arg(&config.ssh_host).arg(format!(
        "powershell -Command \"Remove-Item -Path '{remote_dir}' -Recurse -Force -ErrorAction SilentlyContinue\""
    ));
    let _ = ssh_clean.status();

    // Check for infrastructure error indicators first
    let exit_code = output.status.code().unwrap_or(-1);
    if let Some(infra_err) = classify_infrastructure_error(exit_code, &stderr_str) {
        return Err(HarnessError::InfrastructureError(infra_err));
    }

    // Try to extract receipt JSON if present
    let json_slice = if let (Some(start), Some(end)) = (stdout_str.find('{'), stdout_str.rfind('}'))
    {
        if start <= end {
            Some(&stdout_str[start..=end])
        } else {
            None
        }
    } else {
        None
    };

    if let Some(slice) = json_slice {
        let mut receipt: OracleReceipt = serde_json::from_str(slice)
            .map_err(|e| HarnessError::InvalidRemoteReceipt(e, stdout_str.clone()))?;

        // Check if receipt itself reports an infrastructure error
        if receipt.is_infrastructure_failure() {
            let msg = receipt.execution.infra_error.unwrap_or_else(|| {
                format!("Docker exit code 125: {}", receipt.execution.stderr_raw)
            });
            return Err(HarnessError::InfrastructureError(msg));
        }

        if !output.status.success() {
            return Err(HarnessError::SshFailed(format!(
                "Remote runner exited with {}: {stderr_str}\n{stdout_str}",
                output.status
            )));
        }

        // Add source hash if known
        if let Some(sb) = source_bytes {
            receipt.metadata.source_hash_sha256 = Some(compute_sha256(&sb));
        }

        // Check binary hash matches
        if receipt.metadata.binary_hash_sha256 != local_sha256 {
            return Err(HarnessError::BinaryHashMismatch {
                local: local_sha256,
                remote: receipt.metadata.binary_hash_sha256,
            });
        }

        // 6. Write receipt to file if requested
        if let Some(out_path) = &config.output_receipt_path {
            receipt.write_to_file(out_path)?;
        }

        return Ok(receipt);
    }

    if !output.status.success() {
        return Err(HarnessError::SshFailed(format!(
            "Remote runner exited with {}: {stderr_str}\n{stdout_str}",
            output.status
        )));
    }

    Err(HarnessError::InvalidRemoteReceipt(
        serde::de::Error::custom("No valid JSON receipt found in runner output"),
        stdout_str,
    ))
}
