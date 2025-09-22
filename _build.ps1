# build-uweb.ps1
# PowerShell version of your batch build

param(
  [string] $Thumb,            # cert SHA1 thumbprint for signtool (overrides env)
  [string] $ApiKey,           # VirusTotal API key (overrides env)
  [switch] $NoCompile,        # skip compilation if set)
  [switch] $NoSubmit          # skip virustotal submission if set)
)

# ---------- Config ----------
$VSVCVARS  = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat'

$OUTDIR   = 'WindowsBinaries'
$RCFILE   = 'uweb.rc'
$SOURCES  = 'uweb.c log.c cmd_line.c'  

# Signing (optional)
$SignTool = 'C:\Program Files (x86)\Windows Kits\10\App Certification Kit\signtool.exe'

# Params/env fallbacks
if (-not $Thumb)  { $Thumb  = $env:SIGN_CERT_THUMBPRINT }
if (-not $ApiKey) { $ApiKey = $env:VT_API_KEY }
# ----------------------------

if (!(Test-Path $OUTDIR)) { New-Item -ItemType Directory -Path $OUTDIR | Out-Null }
if (!(Test-Path $RCFILE)) { throw "RC file not found: $RCFILE" }

function Invoke-Build {
    param(
        [Parameter(Mandatory)] [ValidateSet('x64','x86')] $Arch,
        [Parameter(Mandatory)] [ValidateSet('/MD','/MT')] $CRT,
        [Parameter(Mandatory)] [string] $CFlags,
        [Parameter(Mandatory)] [string] $OutExe
    )

    Write-Host "`n--- Building $Arch $Flavor ($CRT) ---"

    # Common flags
    $cdefs   = '/DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS'
    $libs    = 'ws2_32.lib user32.lib'
    $ldflags = '/link /DYNAMICBASE /NXCOMPAT /guard:cf /INCREMENTAL:NO /OPT:REF /OPT:ICF /STACK:65536'

    # Build one pass inside a fresh cmd.exe so vcvarsall doesn't pollute the PS session
    $cmd = @(
        "call `"$VSVCVARS`" $Arch"
        "rc /nologo /fo uweb.res `"$RCFILE`""
        $cmdLine = "cl $CFlags $cdefs $CRT $includes /Fe:`"$OutExe`" $SOURCES uweb.res $ldflags $libpath $libs"
        Write-Host $cmdLine -ForegroundColor Cyan
        "cl $CFlags $cdefs $CRT $includes /Fe:`"$OutExe`" $SOURCES uweb.res $ldflags $libpath $libs"
        # Clean intermediates (quiet)
        "del /q *.obj *.exp *.lib *.res 2>nul"
    ) -join " && "

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'cmd.exe'
    $psi.Arguments = "/c $cmd"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $stdOut = $p.StandardOutput.ReadToEnd()
    $stdErr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    if ($stdOut) { Write-Host $stdOut }
    if ($stdErr) { Write-Host $stdErr -ForegroundColor Yellow }

    if ($p.ExitCode -ne 0) {
        throw "[ERROR] Build failed for $Arch $Flavor (exit $($p.ExitCode))"
    }

    # Sign (optional)
    if ($Thumb -and (Test-Path $SignTool)) {
        Write-Host "Signing $OutExe"
        & "$SignTool" sign /sha1 $Thumb /tr http://time.certum.pl /td sha256 /fd sha256 /v "$OutExe"
        if ($LASTEXITCODE -ne 0) { throw "[ERROR] Signing failed: $OutExe" }
    } else {
        if (-not (Test-Path $SignTool)) { Write-Host "[WARN] signtool not found at $SignTool; skipping signing." -ForegroundColor Yellow }
        if (-not $Thumb) { Write-Host "[WARN] SIGN_CERT_THUMBPRINT not set; skipping signing." -ForegroundColor Yellow }
    }

    if ($Flavor -eq 'DYNAMIC') {
        Write-Host "To run: set uweb_OPENSSL_DIR=$OPENSSL_BIN`n"
    } else {
        Write-Host "Static build: no OpenSSL DLLs required.`n"
    }
}


function Write-Checksums {
    $md5File    = Join-Path $OUTDIR 'MD5SUMS'
    $sha256File = Join-Path $OUTDIR 'SHA256SUMS'
    Remove-Item -LiteralPath $md5File,$sha256File -ErrorAction SilentlyContinue

    $exeFiles = Get-ChildItem -Path $OUTDIR -Filter '*.exe' -File | Sort-Object Name
    foreach ($file in $exeFiles) {
        $md5     = (Get-FileHash -Path $file.FullName -Algorithm MD5).Hash.ToLower()
        $sha256  = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash.ToLower()
        Add-Content -Path $md5File    -Value ("{0}`t{1}" -f $file.Name, $md5)
        Add-Content -Path $sha256File -Value ("{0}`t{1}" -f $file.Name, $sha256)
        Write-Host ("{0}: MD5={1}  SHA256={2}" -f $file.Name, $md5, $sha256)
    }
}

function Submit-VTFile {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $ApiKey
    )
    if (-not (Test-Path $Path)) { throw "File not found: $Path" }
    Write-Host "Uploading to VirusTotal: $Path"

    $vtUrl = 'https://www.virustotal.com/api/v3/files'
    $file  = Get-Item -LiteralPath $Path

    try {
        $resp = Invoke-RestMethod -Uri $vtUrl -Method Post `
                -Headers @{ 'x-apikey' = $ApiKey } `
                -Form @{ file = $file }
        $analysisId = $resp.data.id
        Write-Host "  VT upload ok. Analysis id: $analysisId"
        # return a tagged object so caller knows how to query later
        [pscustomobject]@{ Kind = 'analysis'; Value = $analysisId; Path = $Path }
    } catch {
        # If it's a 409 Conflict (duplicate), fall back to SHA256 look-up
        $status = $_.Exception.Response.StatusCode.Value__
        if ($status -eq 409) {
            Write-Host "  [INFO] Duplicate on VT (409). Will query by SHA256."
            $sha256 = (Get-FileHash -Path $Path -Algorithm SHA256).Hash
            [pscustomobject]@{ Kind = 'sha256'; Value = $sha256; Path = $Path }
        } else {
            Write-Host "[ERROR] VT upload failed: $($_.Exception.Message)" -ForegroundColor Yellow
            $null
        }
    }
}


function Get-VTFileSummary {
    param(
        [Parameter(Mandatory)] [string] $Sha256,
        [Parameter(Mandatory)] [string] $ApiKey
    )
    $curl = 'C:\Windows\System32\curl.exe'
    $raw = & $curl -s "https://www.virustotal.com/api/v3/files/$Sha256" -H "x-apikey: $ApiKey"
    if (-not $raw) { Write-Host "  [$Sha256] No response"; return }
    try {
        $j = $raw | ConvertFrom-Json
        $stats = $j.data.attributes.last_analysis_stats
        Write-Host ("  [$Sha256] harmless={0}, malicious={1}, suspicious={2}, undetected={3}, timeout={4}" -f `
            $stats.harmless, $stats.malicious, $stats.suspicious, $stats.undetected, $stats.timeout)
    } catch {
        Write-Host "  [$Sha256] Parse error: $raw"
    }
}


function Get-VTAnalysisSummary {
    param(
        [Parameter(Mandatory)] [string] $AnalysisId,
        [Parameter(Mandatory)] [string] $ApiKey,
        [int] $MaxAttempts = 12,      # ~1 minute total by default
        [int] $SleepSeconds = 5
    )
    $curl = 'C:\Windows\System32\curl.exe'
    if (-not (Test-Path $curl)) {
        Write-Host "[WARN] curl.exe not found at $curl" -ForegroundColor Yellow
        return
    }

    for ($i=1; $i -le $MaxAttempts; $i++) {
        $raw = & $curl -s "https://www.virustotal.com/api/v3/analyses/$AnalysisId" -H "x-apikey: $ApiKey"
        if (-not $raw) {
            Write-Host "  [$AnalysisId] Empty response (attempt $i/$MaxAttempts)"
            Start-Sleep -Seconds $SleepSeconds
            continue
        }
        try {
            $json = $raw | ConvertFrom-Json
            $status = $json.data.attributes.status
            if ($status -ne 'completed') {
                Write-Host "  [$AnalysisId] status=$status (attempt $i/$MaxAttempts)..."
                Start-Sleep -Seconds $SleepSeconds
                continue
            }
            $stats = $json.data.attributes.stats
            Write-Host ("  [$AnalysisId] harmless={0}, malicious={1}, suspicious={2}, undetected={3}, timeout={4}" -f `
                $stats.harmless, $stats.malicious, $stats.suspicious, $stats.undetected, $stats.timeout)
            return
        } catch {
            Write-Host "  [$AnalysisId] Parse error on response (attempt $i/$MaxAttempts)."
            Start-Sleep -Seconds $SleepSeconds
        }
    }
    Write-Host "  [$AnalysisId] Gave up waiting for completion." -ForegroundColor Yellow
}


# ---- Build matrix ----

if (-not $NoCompile) 
{
    # no optimization for x86/MD since it triggers antivirus detection
    $Cx64Flags = "/nologo /W4 /O2 /Gy /Zc:inline"
    $Cx86Flags = "/nologo /W4 /Gy /Zc:inline"

    # debug flags
    # $Cx64Flags = "/nologo /W4 /Zi /Gy /Zc:inline"
    # $Cx86Flags = "/nologo /W4 /Zi /Zc:inline"

    Invoke-Build -Arch x64 -CRT /MT -CFlags $Cx64Flags -OutExe (Join-Path $OUTDIR 'uweb64.exe')
    Invoke-Build -Arch x86 -CRT /MT -CFlags $Cx86Flags -OutExe (Join-Path $OUTDIR 'uweb32.exe')


    Write-Checksums
} else {
    Write-Host "`n[INFO] --NoCompile set; skipping compilation."
}

Write-Host "`n==== Build complete ===="

# Optional: upload all EXEs to VirusTotal if ApiKey is provided

if (-not $NoSubmit -And $ApiKey) {
    $results = [System.Collections.Generic.List[object]]::new()
    Write-Host "`nSubmitting EXEs to VirusTotal..."
    Get-ChildItem -Path $OUTDIR -Filter '*.exe' -File | Sort-Object Name | ForEach-Object {
        $r = Submit-VTFile -Path $_.FullName -ApiKey $ApiKey 
        if ($r) { [void]$results.Add($r) }
    }
    Sleep -Seconds 10  # brief pause before polling
    Write-Host "`nPolling VirusTotal analyses..."
    foreach ($r in $results) {
        if ($r.Kind -eq 'analysis') {
            Get-VTAnalysisSummary -AnalysisId $r.Value -ApiKey $ApiKey  # your polling-by-id function
        } elseif ($r.Kind -eq 'sha256') {
            Get-VTFileSummary -Sha256 $r.Value -ApiKey $ApiKey          # direct summary by hash
        }
    }
} else {
    Write-Host "`n[INFO] NoSubmit flag or VT_API_KEY / --ApiKey not provided; skipping VirusTotal upload."
}

Write-Host "`n==== VirusTotal checking complete ===="


