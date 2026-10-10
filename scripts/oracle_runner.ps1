<#
.SYNOPSIS
    Differential black-box oracle capture script for Windows Server 2025 Docker containers.

.DESCRIPTION
    Executes a Windows console PE inside a clean-room Windows container from a pinned base image,
    captures stdout, stderr, exit code, and cryptographic hashes, and outputs an immutable
    JSON receipt adhering to oracle-receipt-v1.json.
    Guarantees zero persistent state or lingering containers via finally cleanup.
    Stages binaries under C:\carrick-oracle\runs\<run-id> with BUILTIN\Users permissions so
    ContainerUser can read and execute the binary through the bind mount.
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$ExePath,

    [Parameter(Mandatory=$false)]
    [string]$ImageTag = "mcr.microsoft.com/windows/nanoserver:ltsc2025@sha256:15760261db306980fd96acf7e2c73779eaaeefdff289339b9526295c88957e56",

    [Parameter(Mandatory=$false)]
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ExePath)) {
    Write-Error "Target executable not found: $ExePath"
    exit 1
}

$ExeFileName = Split-Path -Leaf $ExePath
$TestName = [System.IO.Path]::GetFileNameWithoutExtension($ExeFileName)
$RunId = [Guid]::NewGuid().ToString()
$ContainerName = "carrick-oracle-$RunId"

# Stage under dedicated directory C:\carrick-oracle\runs\<run-id> instead of $env:TEMP,
# which is inside the Administrator profile and inaccessible to ContainerUser.
$BaseDir = "C:\carrick-oracle"
$RunsDir = Join-Path $BaseDir "runs"
$TempHostDir = Join-Path $RunsDir $RunId

# 1. Query Host Environment
$OSCaption = (Get-CimInstance Win32_OperatingSystem).Caption
$CurrentVersionKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$CurrentBuild = (Get-ItemProperty $CurrentVersionKey).CurrentBuildNumber
$UBR = (Get-ItemProperty $CurrentVersionKey).UBR
if ($UBR) {
    $FullBuild = "$CurrentBuild.$UBR"
} else {
    $FullBuild = "$CurrentBuild"
}

# 2. Binary Hash
$BinaryHash = (Get-FileHash -Path $ExePath -Algorithm SHA256).Hash.ToLowerInvariant()

# Stage binary to isolated temporary directory and grant BUILTIN\Users permissions
New-Item -ItemType Directory -Path $TempHostDir -Force | Out-Null
Copy-Item -Path $ExePath -Destination (Join-Path $TempHostDir $ExeFileName) -Force

# Grant BUILTIN\Users (*S-1-5-32-545) Read & Execute inheritance for ContainerUser
icacls "$TempHostDir" /grant "*S-1-5-32-545:(OI)(CI)RX" /T | Out-Null

try {
    # 3. Pull image if needed
    docker pull $ImageTag 2>&1 | Out-Null

    # 4. Execute container with timeout and stream redirection
    $StdoutStream = [System.IO.MemoryStream]::new()
    $StderrStream = [System.IO.MemoryStream]::new()

    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = "docker"
    $ProcessInfo.Arguments = "run --name $ContainerName --rm -v `"${TempHostDir}:C:\app:ro`" $ImageTag C:\app\$ExeFileName"
    $ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.CreateNoWindow = $true

    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo

    $Process.Start() | Out-Null

    $StdoutTask = $Process.StandardOutput.BaseStream.CopyToAsync($StdoutStream)
    $StderrTask = $Process.StandardError.BaseStream.CopyToAsync($StderrStream)

    $Completed = $Process.WaitForExit($TimeoutSeconds * 1000)
    if (-not $Completed) {
        $Process.Kill()
        docker rm -f $ContainerName 2>$null | Out-Null
        Write-Error "Container execution timed out after $TimeoutSeconds seconds"
        exit 124
    }

    [System.Threading.Tasks.Task]::WaitAll($StdoutTask, $StderrTask)

    $ExitCode = $Process.ExitCode
    $StdoutBytes = $StdoutStream.ToArray()
    $StderrBytes = $StderrStream.ToArray()

    $StdoutBase64 = [Convert]::ToBase64String($StdoutBytes)
    $StderrBase64 = [Convert]::ToBase64String($StderrBytes)
    $StdoutRaw = [System.Text.Encoding]::UTF8.GetString($StdoutBytes)
    $StderrRaw = [System.Text.Encoding]::UTF8.GetString($StderrBytes)

    $CapturedAtUtc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")

    # Detect infrastructure failure (Docker daemon failure, container create/exec failure)
    $IsInfraFailure = $false
    $InfraErrorMessage = $null

    if ($ExitCode -eq 125 -or $StderrRaw -match "docker:" -or $StderrRaw -match "hcs::" -or $StderrRaw -match "Error response from daemon") {
        $IsInfraFailure = $true
        $InfraErrorMessage = $StderrRaw.Trim()
        if (-not $InfraErrorMessage) {
            $InfraErrorMessage = "Docker container runtime error (exit 125)"
        }
    }

    $ExecutionDict = [ordered]@{
        "command" = @($ExeFileName)
        "exit_code" = $ExitCode
        "stdout_raw" = $StdoutRaw
        "stdout_base64" = $StdoutBase64
        "stderr_raw" = $StderrRaw
        "stderr_base64" = $StderrBase64
    }

    if ($IsInfraFailure) {
        $ExecutionDict["infra_error"] = $InfraErrorMessage
    }

    $Receipt = [ordered]@{
        "`$schema" = "https://carrick.dev/schemas/oracle-receipt-v1.json"
        "metadata" = [ordered]@{
            "test_name" = $TestName
            "lane" = "nt"
            "target_arch" = "x86_64"
            "oracle_host" = [ordered]@{
                "os" = $OSCaption
                "build" = $FullBuild
                "container_image" = $ImageTag
            }
            "binary_hash_sha256" = $BinaryHash
            "captured_at_utc" = $CapturedAtUtc
        }
        "execution" = $ExecutionDict
    }

    $JsonReceipt = $Receipt | ConvertTo-Json -Depth 10
    Write-Output $JsonReceipt

    if ($IsInfraFailure) {
        exit 125
    }
}
finally {
    # Enforce zero persistent state: remove container if still running and delete temp directory
    docker rm -f $ContainerName 2>$null | Out-Null
    if (Test-Path $TempHostDir) {
        Remove-Item -Path $TempHostDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
