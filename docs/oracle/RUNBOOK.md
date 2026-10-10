# Windows Container Oracle Capture Runbook (Milestone M0)

This runbook specifies the exact commands and operational procedures for the director to capture authoritative oracle execution receipts from real Windows Server 2025 containers.

Workers have no access to the Windows oracle VM; this runbook is executed exclusively by the director from the director's host machine (e.g. macOS).

---

## 1. Governance & Clean-Room Context

Per `AGENTS.md`:
- **The oracle is real Windows.** No Wine, ReactOS, or emulator code may be used.
- Conformance is differential: guest executions under Carrick are asserted byte-for-byte against recorded observations from real Windows containers.
- Committed oracle receipts in `tests/oracle/receipts/*.json` allow regular CI to test compatibility offline without reaching the live Windows VM.

---

## 2. Oracle Host & Container Configuration

- **Oracle Host:** Willow VM 106 running **Windows Server 2025 Datacenter** (`build: 10.0.26100.x`).
- **Access Protocol:** OpenSSH server running on Windows Server 2025, authenticated via SSH key as `administrator`.
  > **Note:** Never store SSH keys, passwords, or credentials in files or git commits. Use standard SSH agent or director-managed keys.
- **Pinned Container Image:**
  ```text
  mcr.microsoft.com/windows/nanoserver:ltsc2025@sha256:15760261db306980fd96acf7e2c73779eaaeefdff289339b9526295c88957e56
  ```

### Why Nano Server over Server Core?
1. **Footprint & Speed:** Nano Server is ~150 MB compressed and starts in under 1 second. Server Core is ~3.5–5.0 GB with a 15–30 second container startup latency.
2. **Surface Purity:** Nano Server includes the exact minimal 64-bit console Win32/NT runtime (`ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, and console subsystem) without legacy desktop, shell, or GUI subsystems.
3. **Zero Persistent State:** Ephemeral container invocation with `--rm` and automatic `finally` cleanup leaves zero leftover containers or host filesystem artifacts.

---

## 3. Preparation: Build & Verify Fixtures (on Linux / Worker)

Before initiating capture, ensure the clean-room test binary is compiled and verified:

```bash
# Compile clean-room x86_64 console PE fixture
cargo xtask build-fixtures

# Verify PE headers (AMD64, CUI subsystem, KERNEL32 imports only)
cargo xtask verify-pe
```

Artifact staged at: `tests/oracle/fixtures/hello_console.exe`.

---

## 4. Execution: Automated Capture (from Director's Machine)

Run the capture CLI tool from `crates/carrick-conformance-nt`:

### 4.1 Dry-Run Inspection
Verify commands and plans without making network connections:
```bash
cargo run -p carrick-conformance-nt --bin carrick-oracle-capture -- --dry-run
```

### 4.2 Live Capture Run
Execute against the Windows oracle VM:
```bash
cargo run -p carrick-conformance-nt --bin carrick-oracle-capture -- \
  --host administrator@<oracle-vm-host-or-ip> \
  --binary tests/oracle/fixtures/hello_console.exe \
  --source tests/oracle/fixtures/hello_console.rs \
  --output tests/oracle/receipts/hello_console.json \
  --timeout 30
```

The harness will:
1. Compute the local SHA-256 hash of `hello_console.exe`.
2. Stage the executable and `scripts/oracle_runner.ps1` to `C:\carrick-oracle\` on the Windows host via SCP.
3. Invoke `oracle_runner.ps1` over SSH:
   - Staging is isolated under `C:\carrick-oracle\runs\<run-id>` and granted `BUILTIN\Users` (`*S-1-5-32-545:(OI)(CI)RX`) permissions via `icacls`, ensuring the container's `ContainerUser` account can read and execute the binary through the bind mount.
   - Executes `docker run --name carrick-oracle-<id> --rm -v "C:\carrick-oracle\runs\<id>:C:\app:ro" <pinned-image> C:\app\hello_console.exe`.
   - Distinguishes infrastructure failures (exit 125, HCS create/exec errors) from guest program exits: emits an `infra_error` field on container runtime failures and prevents bogus receipt recording.
   - Captures stdout raw/base64, stderr raw/base64, and exit code.
   - Guarantees zero persistent state by removing containers and the temporary run directory in a PowerShell `finally` block.
4. Verify the remote binary SHA-256 matches the local binary.
5. Save the formatted JSON receipt to `tests/oracle/receipts/hello_console.json`.

---

## 5. Fallback: Manual SSH & PowerShell Execution

If running without the Rust CLI harness, the director can run the underlying steps manually:

```bash
# 1. Create remote directory
ssh administrator@<oracle-vm> "powershell -Command New-Item -ItemType Directory -Path C:\carrick-oracle -Force"

# 2. Copy binary and runner script
scp tests/oracle/fixtures/hello_console.exe scripts/oracle_runner.ps1 administrator@<oracle-vm>:C:\carrick-oracle\

# 3. Run capture script over SSH
ssh administrator@<oracle-vm> "powershell -NoProfile -ExecutionPolicy Bypass -File C:\carrick-oracle\oracle_runner.ps1 -ExePath C:\carrick-oracle\hello_console.exe -TimeoutSeconds 30" > tests/oracle/receipts/hello_console.json

# 4. Clean up remote directory
ssh administrator@<oracle-vm> "powershell -Command Remove-Item -Path C:\carrick-oracle\runs -Recurse -Force -ErrorAction SilentlyContinue"
```

---

## 6. Verification & Commit

Once `tests/oracle/receipts/hello_console.json` is generated:

```bash
# Verify receipt matches schema and comparator passes
cargo test -p carrick-conformance-nt

# Commit receipt (NT-003)
git add tests/oracle/receipts/hello_console.json
git commit -m "test(oracle): commit baseline observation for hello_console"
```
