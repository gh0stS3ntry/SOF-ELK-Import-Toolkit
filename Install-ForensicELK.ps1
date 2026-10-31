#Requires -Version 5.1
<#
.SYNOPSIS
    Downloads and configures a single-node Elasticsearch 9.4.3 + Kibana 9.4.3
    instance on Windows for local forensic bulk ingestion and analysis.

.DESCRIPTION
    The script:
      1. Creates a "forensic-elk" directory in the current working directory
         (or under -InstallRoot) and downloads the Elasticsearch and Kibana
         Windows zip files into it, verifying each against the SHA-512
         checksum Elastic publishes beside the download.
      2. Extracts both archives and connects Kibana to Elasticsearch by
         writing elasticsearch.hosts in kibana.yml. Security is disabled, so
         no enrolment token is needed (enrolment tokens only exist when
         Elasticsearch security is on).
      3. Binds Elasticsearch (TCP/9200) and Kibana (TCP/5601) to 0.0.0.0 so
         the host and VMs on the workstation's virtual networks can reach
         them, uses single-node discovery, and (when run as Administrator)
         adds Windows Defender Firewall rules for both ports.
      4. Disables Elasticsearch security (xpack.security.enabled: false), so
         neither the Kibana UI nor the REST APIs ask for a username or
         password.
      5. Writes forensic-elk\start.bat, which starts Elasticsearch, waits for
         it to answer, loads the index templates, then starts Kibana and
         waits for it.
      6. Runs start.bat, then deletes the downloaded zip files (and their
         .sha512 files) once everything has succeeded.

    Steps: the work is split into named steps, run in this order:
      Install      create forensic-elk, download and extract (skipped for a
                   product that is already extracted there)
      Configure    write elasticsearch.yml, kibana.yml and the heap override
      Firewall     (re)create the Windows Defender Firewall rules
      Templates    stage the index templates and write load-templates.ps1
      StartScript  write start.bat
      Start        run start.bat and check Elasticsearch answers
      Cleanup      delete the downloaded zip files
    By default every step runs. -Only runs just the named steps, for example
    -Only Firewall on a computer that received a copy of forensic-elk (such
    as from a USB drive): the copy runs as-is, because start.bat and the
    configuration use no absolute paths, but the firewall rules belong to
    the computer and name the absolute path of java.exe and node.exe.

    Index templates: the script copies SOF-ELK's native templates
    (sof-elk-templates\, used by evtxlogs-*, filesystem-*, lnkfiles-* and
    the other SOF-ELK indexes) and the toolkit's own templates
    (Windows\index_templates\, AWS\index_templates\,
    Generic-CSV\index_templates\, Linux\index_templates\) from the toolkit checkout it is run from
    into forensic-elk\templates\, and writes forensic-elk\load-templates.ps1.
    start.bat runs that loader on every start, before any data is ingested,
    so new indexes get the same settings and mappings as on a SOF-ELK VM
    with the toolkit. Keep this script in the root of the toolkit checkout.

    The settings are written before Elasticsearch first starts, which stops
    Elasticsearch from auto-configuring TLS and the elastic password.

    Anyone who can reach TCP/9200 or TCP/5601 can read, change and delete
    every index without credentials. Keep the firewall scope narrow (see
    -FirewallRemoteAddress) and do not run this on an untrusted network.

.PARAMETER InstallRoot
    Directory in which "forensic-elk" is created. Defaults to the current
    working directory. Keep the path short (for example C:\Tools): the Kibana
    archive contains deeply nested files that can exceed the 260-character
    Windows path limit.

.PARAMETER FirewallRemoteAddress
    Remote addresses allowed through the Windows Defender Firewall rules.
    Accepts anything New-NetFirewallRule -RemoteAddress accepts, such as
    "LocalSubnet" (default), "192.168.56.0/24" or "Any". VMware, VirtualBox
    host-only and Hyper-V Default Switch networks give the host an address on
    the VM subnet, so "LocalSubnet" covers VMs on those networks. Note that it
    also covers the subnet of the host's physical network adapter.

.PARAMETER Only
    Run only these steps (see Steps above): Install, Configure, Firewall,
    Templates, StartScript, Start, Cleanup. The others are skipped. Steps
    other than Install need an existing forensic-elk under -InstallRoot.

.PARAMETER SkipFirewall
    Do not create or change Windows Defender Firewall rules.

.PARAMETER HeapSize
    Elasticsearch JVM heap size, such as "4g" or "2048m". By default
    Elasticsearch sizes the heap automatically from the machine's memory,
    which on a workstation running VMs may be more than you want to give it.

.PARAMETER SkipTemplates
    Do not stage or load any index templates.

.PARAMETER NoStart
    Configure everything but do not start Elasticsearch and Kibana.

.PARAMETER KeepDownloads
    Keep the downloaded zip files instead of deleting them at the end.

.PARAMETER StartupTimeoutSeconds
    How long start.bat waits for each service to answer. Default 300.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Install-ForensicELK.ps1

.EXAMPLE
    .\Install-ForensicELK.ps1 -InstallRoot C:\Tools -HeapSize 4g -FirewallRemoteAddress 192.168.56.0/24

.EXAMPLE
    # On a computer that received a copy of C:\Tools\forensic-elk, from an
    # elevated PowerShell: add the firewall rules only.
    .\Install-ForensicELK.ps1 -InstallRoot C:\Tools -Only Firewall

.EXAMPLE
    # Rewrite the configuration and start.bat with a new heap size only.
    .\Install-ForensicELK.ps1 -InstallRoot C:\Tools -Only Configure, StartScript -HeapSize 8g
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = (Get-Location).Path,
    [string[]]$FirewallRemoteAddress = @('LocalSubnet'),
    [switch]$SkipFirewall,
    [ValidatePattern('^[1-9][0-9]*[mMgG]$')]
    [string]$HeapSize,
    [switch]$SkipTemplates,
    [switch]$NoStart,
    [switch]$KeepDownloads,
    [ValidateSet('Install', 'Configure', 'Firewall', 'Templates', 'StartScript', 'Start', 'Cleanup')]
    [string[]]$Only,
    [ValidateRange(30, 3600)]
    [int]$StartupTimeoutSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Invoke-WebRequest is many times slower on Windows PowerShell 5.1 when it
# draws a progress bar for large downloads.
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
$ElasticVersion = '9.4.3'
$ElasticsearchUrl = "https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-$ElasticVersion-windows-x86_64.zip"
$KibanaUrl = "https://artifacts.elastic.co/downloads/kibana/kibana-$ElasticVersion-windows-x86_64.zip"
$ElasticsearchPort = 9200
$KibanaPort = 5601
$FirewallGroup = 'Forensic ELK'
$ManagedMarker = '# Managed by Install-ForensicELK.ps1'

# Steps in the order they run; -Only picks a subset, and the -Skip*/-NoStart/
# -KeepDownloads switches remove one.
$AllSteps = @('Install', 'Configure', 'Firewall', 'Templates', 'StartScript', 'Start', 'Cleanup')
$requested = $AllSteps
if ($Only) { $requested = @($AllSteps | Where-Object { $Only -contains $_ }) }
$Steps = @($requested | Where-Object {
        -not (($_ -eq 'Firewall' -and $SkipFirewall) -or
            ($_ -eq 'Templates' -and $SkipTemplates) -or
            ($_ -eq 'Start' -and $NoStart) -or
            ($_ -eq 'Cleanup' -and $KeepDownloads))
    })
if ($Steps.Count -eq 0) {
    throw 'No steps left to run: -Only and the -Skip*/-NoStart/-KeepDownloads switches exclude every step.'
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Info([string]$Message) { Write-Host "[INFO] $Message" }
function Write-Warn([string]$Message) { Write-Warning $Message }

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-TextFile([string]$Path, [string]$Content, [switch]$Ascii) {
    # Elasticsearch and Kibana read YAML as UTF-8; a BOM (which
    # Set-Content -Encoding UTF8 adds on Windows PowerShell 5.1) is avoided.
    # Batch files are written as ASCII with CRLF line endings for cmd.exe.
    $normalised = ($Content -replace "`r?`n", "`r`n")
    if ($Ascii) {
        $encoding = New-Object System.Text.ASCIIEncoding
    } else {
        $encoding = New-Object System.Text.UTF8Encoding($false)
    }
    [System.IO.File]::WriteAllText($Path, $normalised, $encoding)
}

function Backup-OriginalFile([string]$Path) {
    # Keep the file as shipped in the archive once; later runs leave it alone.
    $backup = "$Path.orig"
    if ((Test-Path -LiteralPath $Path) -and -not (Test-Path -LiteralPath $backup)) {
        Copy-Item -LiteralPath $Path -Destination $backup
        Write-Info "Backed up $Path to $backup"
    }
}

function Get-ExpectedSha512([string]$ChecksumPath) {
    # Elastic's .sha512 files look like "<hex digest>  <file name>".
    $text = (Get-Content -LiteralPath $ChecksumPath -Raw).Trim()
    $digest = ($text -split '\s+')[0]
    if ($digest -notmatch '^[0-9a-fA-F]{128}$') {
        throw "Unexpected checksum file format in $ChecksumPath"
    }
    return $digest.ToUpperInvariant()
}

function Test-FileSha512([string]$Path, [string]$Expected) {
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA512).Hash.ToUpperInvariant()
    return ($actual -eq $Expected)
}

function Save-VerifiedArtifact([string]$Url, [string]$Directory) {
    $fileName = Split-Path -Path $Url -Leaf
    $zipPath = Join-Path $Directory $fileName
    $checksumPath = "$zipPath.sha512"

    Write-Info "Fetching checksum $Url.sha512"
    Invoke-WebRequest -Uri "$Url.sha512" -OutFile $checksumPath -UseBasicParsing
    $expected = Get-ExpectedSha512 $checksumPath

    if ((Test-Path -LiteralPath $zipPath) -and (Test-FileSha512 $zipPath $expected)) {
        Write-Info "$fileName already downloaded and verified; skipping download"
        return $zipPath
    }

    $partial = "$zipPath.part"
    Write-Info "Downloading $Url"
    try {
        Invoke-WebRequest -Uri $Url -OutFile $partial -UseBasicParsing
    } catch {
        Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
        throw "Download of $Url failed: $($_.Exception.Message)"
    }
    if (-not (Test-FileSha512 $partial $expected)) {
        Remove-Item -LiteralPath $partial -Force
        throw "SHA-512 checksum mismatch for $fileName; the download was deleted"
    }
    Move-Item -LiteralPath $partial -Destination $zipPath -Force
    Write-Info "Downloaded and verified $fileName"
    return $zipPath
}

function Get-ZipTopLevelDirectory([string]$ZipPath) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $roots = @($zip.Entries |
            ForEach-Object { ($_.FullName -replace '\\', '/').Split('/')[0] } |
            Where-Object { $_ } |
            Sort-Object -Unique)
    } finally {
        $zip.Dispose()
    }
    if ($roots.Count -ne 1) {
        throw "Expected one top-level directory in $ZipPath, found: $($roots -join ', ')"
    }
    return $roots[0]
}

function Find-ProductHome([string]$Directory, [string]$Product, [string]$MarkerRelativePath) {
    # Returns the extracted <product>-<version>* folder that contains the
    # marker file, or $null when there is none.
    if (-not (Test-Path -LiteralPath $Directory)) { return $null }
    $match = Get-ChildItem -LiteralPath $Directory -Directory -Filter "$Product-$ElasticVersion*" |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName $MarkerRelativePath) } |
        Select-Object -First 1
    if ($match) { return $match.FullName }
    return $null
}

function Expand-ElasticArchive([string]$ZipPath, [string]$Directory, [string]$MarkerRelativePath) {
    # Returns the extracted product directory. An existing, complete
    # extraction is reused so the script can be re-run safely.
    $topLevel = Get-ZipTopLevelDirectory $ZipPath
    $target = Join-Path $Directory $topLevel
    $marker = Join-Path $target $MarkerRelativePath

    if (Test-Path -LiteralPath $marker) {
        Write-Info "$topLevel already extracted; skipping extraction"
        return $target
    }
    if (Test-Path -LiteralPath $target) {
        throw "$target exists but looks incomplete ($MarkerRelativePath missing). Delete it and re-run the script."
    }

    Write-Info "Extracting $(Split-Path $ZipPath -Leaf) (this can take several minutes for Kibana)"
    # tar.exe (bsdtar, shipped with Windows 10 1803+ and Windows 11) is much
    # faster than Expand-Archive on archives with tens of thousands of files.
    $tar = Join-Path $env:SystemRoot 'System32\tar.exe'
    $extracted = $false
    if (Test-Path -LiteralPath $tar) {
        & $tar -xf $ZipPath -C $Directory
        if ($LASTEXITCODE -eq 0) {
            $extracted = $true
        } else {
            Write-Warn "tar.exe exited with code $LASTEXITCODE; retrying with .NET ZipFile"
            Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    if (-not $extracted) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $Directory)
    }
    if (-not (Test-Path -LiteralPath $marker)) {
        throw "Extraction of $ZipPath did not produce $marker. If the error mentions path length, re-run with a shorter -InstallRoot such as C:\Tools."
    }
    return $target
}

function New-RandomKey([int]$Length = 48) {
    # Alphanumeric key for Kibana's encryption settings (32+ characters).
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
}

function Get-ExistingYamlValue([string]$Path, [string]$Key) {
    # Reads a simple "key: value" line written by an earlier run, so the
    # Kibana encryption keys stay stable (changing them makes existing
    # encrypted saved objects unreadable).
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*:\s*"?([^"\s#]+)"?'
    foreach ($line in Get-Content -LiteralPath $Path) {
        $m = [regex]::Match($line, $pattern)
        if ($m.Success) { return $m.Groups[1].Value }
    }
    return $null
}

function Find-FirstFile([string]$Directory, [string]$Filter) {
    if (-not (Test-Path -LiteralPath $Directory)) { return $null }
    $file = Get-ChildItem -LiteralPath $Directory -Filter $Filter -Recurse -File -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($file) { return $file.FullName }
    return $null
}

function Set-FirewallRules([string]$ElasticsearchHome, [string]$KibanaHome) {
    # Rules are tied to the bundled java.exe / node.exe where found, which
    # also stops Windows from showing its "allow this app" prompt (a "Block"
    # click there would create a block rule that overrides these rules).
    Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule

    $services = @(
        @{ Name = 'Elasticsearch'; Port = $ElasticsearchPort; Program = (Find-FirstFile (Join-Path $ElasticsearchHome 'jdk\bin') 'java.exe') },
        @{ Name = 'Kibana'; Port = $KibanaPort; Program = (Find-FirstFile (Join-Path $KibanaHome 'node') 'node.exe') }
    )
    foreach ($svc in $services) {
        $ruleArgs = @{
            DisplayName   = "Forensic ELK - $($svc.Name) (TCP $($svc.Port))"
            Group         = $FirewallGroup
            Direction     = 'Inbound'
            Action        = 'Allow'
            Protocol      = 'TCP'
            LocalPort     = $svc.Port
            RemoteAddress = $FirewallRemoteAddress
            Profile       = 'Any'
        }
        if ($svc.Program) {
            $ruleArgs['Program'] = $svc.Program
        } else {
            Write-Warn "Bundled executable for $($svc.Name) not found; creating a port-only rule"
        }
        New-NetFirewallRule @ruleArgs | Out-Null
        Write-Info "Firewall: allowed inbound TCP $($svc.Port) for $($svc.Name) from $($FirewallRemoteAddress -join ', ')"
    }
}

function Copy-IndexTemplates([string]$SourceRoot, [string]$Destination) {
    # Stages every template under <Destination>\component and
    # <Destination>\index, with the file named after the template it
    # installs, so the loader is a plain loop over the files.
    #   SOF-ELK:  component-<x>.json -> <x>,  index-<x>.json -> <x>
    #             (as SOF-ELK's load_all_dashboards.sh names them)
    #   Toolkit:  component-<x>.json -> sofelk-<x>,  index-<x>.json -> sofelk-toolkit-<x>
    #             (as the importers name them when they install them)
    # Exclude lists files the importers deliberately never install as index
    # templates: AWS index-httpdlog.json would override SOF-ELK's httpdlog-*
    # template, so alb2sofelk.py only uses it to create its own index. Linux
    # index-logstash.json is the same for SOF-ELK's logstash-* (the Linux
    # importers create logstash-<hostname> with it).
    $sources = @(
        @{ Dir = 'sof-elk-templates\component_templates'; ComponentPrefix = ''; IndexPrefix = '' },
        @{ Dir = 'sof-elk-templates\index_templates'; ComponentPrefix = ''; IndexPrefix = '' },
        @{ Dir = 'Windows\index_templates'; ComponentPrefix = 'sofelk-'; IndexPrefix = 'sofelk-toolkit-' },
        @{ Dir = 'AWS\index_templates'; ComponentPrefix = 'sofelk-'; IndexPrefix = 'sofelk-toolkit-'; Exclude = @('index-httpdlog.json') },
        @{ Dir = 'Generic-CSV\index_templates'; ComponentPrefix = 'sofelk-'; IndexPrefix = 'sofelk-toolkit-' },
        @{ Dir = 'Linux\index_templates'; ComponentPrefix = 'sofelk-'; IndexPrefix = 'sofelk-toolkit-'; Exclude = @('index-logstash.json') }
    )
    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Recurse -Force }
    $componentDir = Join-Path $Destination 'component'
    $indexDir = Join-Path $Destination 'index'
    New-Item -ItemType Directory -Path $componentDir, $indexDir | Out-Null

    $seen = @{}
    $counts = @{ component = 0; index = 0 }
    foreach ($src in $sources) {
        $dir = Join-Path $SourceRoot $src.Dir
        if (-not (Test-Path -LiteralPath $dir)) {
            throw "Template directory $dir not found. Run this script from the root of the SOF-ELK Import Toolkit checkout, or use -SkipTemplates."
        }
        $exclude = @()
        if ($src.ContainsKey('Exclude')) { $exclude = $src.Exclude }
        foreach ($file in Get-ChildItem -LiteralPath $dir -Filter '*.json' -File | Sort-Object Name) {
            if ($exclude -contains $file.Name) { continue }
            if ($file.BaseName -like 'component-*') {
                $kind = 'component'
                $name = $src.ComponentPrefix + $file.BaseName.Substring('component-'.Length)
                $target = Join-Path $componentDir "$name.json"
            } elseif ($file.BaseName -like 'index-*') {
                $kind = 'index'
                $name = $src.IndexPrefix + $file.BaseName.Substring('index-'.Length)
                $target = Join-Path $indexDir "$name.json"
            } else {
                continue
            }
            $key = "$kind/$name"
            if ($seen.ContainsKey($key)) {
                throw "Template name clash: $($file.FullName) and $($seen[$key]) both install $kind template '$name'"
            }
            $seen[$key] = $file.FullName
            Copy-Item -LiteralPath $file.FullName -Destination $target
            $counts[$kind]++
        }
    }
    Write-Info "Staged $($counts['component']) component and $($counts['index']) index templates in $Destination"
}

function Get-HostIPv4Addresses {
    try {
        return @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
            Sort-Object InterfaceAlias)
    } catch {
        return @()
    }
}

# ---------------------------------------------------------------------------
# Install: create forensic-elk, download and extract (skipped when already extracted)
# ---------------------------------------------------------------------------
$InstallRoot = (Resolve-Path -LiteralPath $InstallRoot).Path
$ElkRoot = Join-Path $InstallRoot 'forensic-elk'
Write-Info "Steps: $($Steps -join ', ')"
if ($Steps -contains 'Install') {
    if (-not [Environment]::Is64BitOperatingSystem) {
        throw 'Elasticsearch and Kibana for Windows require 64-bit Windows.'
    }
    # Windows PowerShell 5.1 may default to TLS 1.0/1.1, which artifacts.elastic.co refuses.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if (Test-Path -LiteralPath $ElkRoot) {
        Write-Info "Using existing directory $ElkRoot"
    } else {
        New-Item -ItemType Directory -Path $ElkRoot | Out-Null
        Write-Info "Created $ElkRoot"
    }
} elseif (-not (Test-Path -LiteralPath $ElkRoot)) {
    throw "$ElkRoot not found. Set -InstallRoot to the folder that contains forensic-elk, or run the Install step first."
}

# An extracted (or copied) instance is found by its folder, so later runs
# need neither the zip files nor a download.
$EsHome = Find-ProductHome $ElkRoot 'elasticsearch' 'bin\elasticsearch.bat'
$KibanaHome = Find-ProductHome $ElkRoot 'kibana' 'bin\kibana.bat'
if ($Steps -contains 'Install') {
    if ($EsHome) {
        Write-Info "Elasticsearch is already extracted in $EsHome; skipping download and extraction"
    } else {
        $esZip = Save-VerifiedArtifact $ElasticsearchUrl $ElkRoot
        $EsHome = Expand-ElasticArchive $esZip $ElkRoot 'bin\elasticsearch.bat'
    }
    if ($KibanaHome) {
        Write-Info "Kibana is already extracted in $KibanaHome; skipping download and extraction"
    } else {
        $kibanaZip = Save-VerifiedArtifact $KibanaUrl $ElkRoot
        $KibanaHome = Expand-ElasticArchive $kibanaZip $ElkRoot 'bin\kibana.bat'
    }
}
$needsHomes = @($Steps | Where-Object { $_ -in @('Configure', 'Firewall', 'StartScript', 'Cleanup') })
if ($needsHomes.Count -gt 0 -and -not ($EsHome -and $KibanaHome)) {
    throw "No complete Elasticsearch $ElasticVersion and Kibana $ElasticVersion installation found in $ElkRoot (needed by: $($needsHomes -join ', ')). Run the Install step first."
}

# ---------------------------------------------------------------------------
# Configure: Elasticsearch and Kibana listen on all interfaces, no security,
# Kibana connected to Elasticsearch
# ---------------------------------------------------------------------------
if ($Steps -contains 'Configure') {
    $esConfig = Join-Path $EsHome 'config\elasticsearch.yml'

    # If Elasticsearch was started before this script configured it, it has
    # already auto-configured TLS and stored keystore secrets for it; disabling
    # security on top of that is not reliable, so ask for a clean extraction.
    $esCerts = Join-Path $EsHome 'config\certs'
    $esConfigText = ''
    if (Test-Path -LiteralPath $esConfig) { $esConfigText = Get-Content -LiteralPath $esConfig -Raw }
    if ($null -eq $esConfigText) { $esConfigText = '' }
    $alreadyManaged = $esConfigText.Contains($ManagedMarker)
    if ((Test-Path -LiteralPath $esCerts) -and -not $alreadyManaged) {
        throw "Elasticsearch in $EsHome was already started with security auto-configuration ($esCerts exists). Stop it, delete $EsHome and re-run this script."
    }

    Backup-OriginalFile $esConfig
    $esYaml = @"
$ManagedMarker
# The archive's original file is kept as elasticsearch.yml.orig.
cluster.name: forensic-elk
node.name: forensic-elk-node-1

# Listen on every IPv4 interface so the host (127.0.0.1) and VMs on the
# workstation's virtual networks can reach the REST API.
network.host: 0.0.0.0
http.port: $ElasticsearchPort

# Standalone node: no cluster formation, and production bootstrap checks
# that would otherwise apply to a non-loopback bind are not enforced.
discovery.type: single-node

# No authentication or TLS: the Kibana UI and the REST API need no username
# or password. Anyone who can reach this port has full access to all data.
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false
"@
    Write-TextFile $esConfig $esYaml
    Write-Info "Wrote $esConfig"

    $heapFile = Join-Path $EsHome 'config\jvm.options.d\forensic-elk-heap.options'
    if ($HeapSize) {
        $heap = $HeapSize.ToLowerInvariant()
        Write-TextFile $heapFile "-Xms$heap`n-Xmx$heap`n"
        Write-Info "Set Elasticsearch heap to $heap ($heapFile)"
    } elseif (Test-Path -LiteralPath $heapFile) {
        Remove-Item -LiteralPath $heapFile -Force
        Write-Info 'Removed heap override; Elasticsearch will size its heap automatically'
    }

    # ---------------------------------------------------------------------------
    # 2 + 3. Kibana: listen on all interfaces and connect to Elasticsearch
    # ---------------------------------------------------------------------------
    $kibanaConfig = Join-Path $KibanaHome 'config\kibana.yml'
    $keyNames = @(
        'xpack.encryptedSavedObjects.encryptionKey',
        'xpack.reporting.encryptionKey',
        'xpack.security.encryptionKey'
    )
    $keys = @{}
    foreach ($name in $keyNames) {
        $existing = Get-ExistingYamlValue $kibanaConfig $name
        if ($existing -and $existing.Length -ge 32) { $keys[$name] = $existing } else { $keys[$name] = New-RandomKey }
    }

    Backup-OriginalFile $kibanaConfig
    $kibanaYaml = @"
$ManagedMarker
# The archive's original file is kept as kibana.yml.orig.

# Listen on every IPv4 interface so the host and VMs can open the UI and
# call the Kibana APIs (for example to create Data Views).
server.host: "0.0.0.0"
server.port: $KibanaPort

# Connect to the local Elasticsearch node. Security is disabled there, so no
# enrolment token, service account token or password is used. 127.0.0.1 is
# used instead of localhost because Node.js may resolve localhost to ::1,
# and Elasticsearch listens on IPv4 only.
elasticsearch.hosts: ["http://127.0.0.1:$ElasticsearchPort"]

# Stable keys for encrypted saved objects (alerting rules, connectors,
# reporting). Generated once; later runs reuse them.
xpack.encryptedSavedObjects.encryptionKey: "$($keys['xpack.encryptedSavedObjects.encryptionKey'])"
xpack.reporting.encryptionKey: "$($keys['xpack.reporting.encryptionKey'])"
xpack.security.encryptionKey: "$($keys['xpack.security.encryptionKey'])"

telemetry.optIn: false
"@
    Write-TextFile $kibanaConfig $kibanaYaml
    Write-Info "Wrote $kibanaConfig"
}

# ---------------------------------------------------------------------------
# Firewall: Windows Defender Firewall rules for TCP 9200 and 5601
# ---------------------------------------------------------------------------
if ($Steps -contains 'Firewall') {
    if (Test-IsAdministrator) {
        Set-FirewallRules $EsHome $KibanaHome
    } elseif ($Only) {
        throw 'The Firewall step needs an elevated PowerShell (Run as Administrator).'
    } else {
        Write-Warn ("Not running as Administrator, so no firewall rules were added. VMs may not reach " +
            "TCP $ElasticsearchPort/$KibanaPort until you run '.\Install-ForensicELK.ps1 -Only Firewall' " +
            "from an elevated PowerShell, or allow java.exe and node.exe when Windows prompts.")
    }
}

# ---------------------------------------------------------------------------
# Templates: index templates (SOF-ELK native + toolkit) and their loader
# ---------------------------------------------------------------------------
$templatesDir = Join-Path $ElkRoot 'templates'
$loaderPath = Join-Path $ElkRoot 'load-templates.ps1'
if ($Steps -contains 'Templates') {
    Copy-IndexTemplates $PSScriptRoot $templatesDir
    $loader = @'
# Loads the forensic-elk index templates into Elasticsearch.
# Generated by Install-ForensicELK.ps1 and run by start.bat on every start.
# PUT replaces a template of the same name, so re-running is safe. Templates
# apply to indexes created afterwards; existing indexes keep their mappings.
param([string]$ElasticsearchUrl = 'http://127.0.0.1:9200')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = Join-Path $PSScriptRoot 'templates'
$loaded = 0
$failed = 0
# Component templates first: index templates name them in composed_of.
$kinds = @(
    @{ Dir = 'component'; Api = '_component_template' },
    @{ Dir = 'index'; Api = '_index_template' }
)
foreach ($kind in $kinds) {
    $dir = Join-Path $root $kind.Dir
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    foreach ($file in Get-ChildItem -LiteralPath $dir -Filter '*.json' -File | Sort-Object Name) {
        $uri = "$ElasticsearchUrl/$($kind.Api)/$($file.BaseName)"
        try {
            $body = [System.IO.File]::ReadAllBytes($file.FullName)
            Invoke-RestMethod -Method Put -Uri $uri -Body $body -ContentType 'application/json' -UseBasicParsing | Out-Null
            $loaded++
        } catch {
            $failed++
            $detail = $_.Exception.Message
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $detail = $_.ErrorDetails.Message }
            Write-Host "ERROR loading $($kind.Api)/$($file.BaseName): $detail"
        }
    }
}
Write-Host "Loaded $loaded index and component templates ($failed failed)"
if ($failed -gt 0) { exit 1 }
exit 0
'@
    Write-TextFile $loaderPath $loader
    Write-Info "Wrote $loaderPath"
} elseif ($SkipTemplates) {
    Write-Info 'Skipping index templates (-SkipTemplates)'
    # start.bat only loads templates when the loader exists.
    Remove-Item -LiteralPath $loaderPath -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# StartScript: write start.bat
# ---------------------------------------------------------------------------
$startBatPath = Join-Path $ElkRoot 'start.bat'
if ($Steps -contains 'StartScript') {
    $esDirName = Split-Path $EsHome -Leaf
    $kibanaDirName = Split-Path $KibanaHome -Leaf
    # The wait loop runs in PowerShell; the URL comes from an environment
    # variable so the command line contains no cmd.exe-sensitive characters.
    $waitCommand = "`$u = `$env:FELK_WAIT_URL; `$d = (Get-Date).AddSeconds([int]`$env:FELK_WAIT_SECONDS); " +
        "while ((Get-Date) -lt `$d) { try { `$r = Invoke-WebRequest -Uri `$u -UseBasicParsing -TimeoutSec 5; " +
        "if (`$r.StatusCode -eq 200) { exit 0 } } catch { }; Start-Sleep -Seconds 3 }; exit 1"
    $probeCommand = "try { `$r = Invoke-WebRequest -Uri `$env:FELK_WAIT_URL -UseBasicParsing -TimeoutSec 3; " +
        "if (`$r.StatusCode -eq 200) { exit 0 } } catch { }; exit 1"

    $startBat = @"
@echo off
rem Starts the forensic-elk Elasticsearch and Kibana instance.
rem Generated by Install-ForensicELK.ps1. Each service runs in its own
rem window; press Ctrl+C in that window (or close it) to stop the service.
setlocal
set "ROOT=%~dp0"
set "ES_HOME=%ROOT%$esDirName"
set "KIBANA_HOME=%ROOT%$kibanaDirName"
set "ES_URL=http://127.0.0.1:$ElasticsearchPort"
set "KIBANA_URL=http://127.0.0.1:$KibanaPort"
set "FELK_WAIT_SECONDS=$StartupTimeoutSeconds"
set "PS=powershell.exe -NoProfile -ExecutionPolicy Bypass -Command"

set "FELK_WAIT_URL=%ES_URL%/_cluster/health"
%PS% "$probeCommand"
if not errorlevel 1 goto es_running
echo Starting Elasticsearch...
start "Forensic ELK - Elasticsearch" /D "%ES_HOME%" cmd /k bin\elasticsearch.bat
goto es_wait
:es_running
echo Elasticsearch is already running at %ES_URL%
:es_wait
echo Waiting up to %FELK_WAIT_SECONDS% seconds for Elasticsearch...
%PS% "$waitCommand"
if errorlevel 1 goto es_failed
echo Elasticsearch is up at %ES_URL%

rem Load the index templates before anything is ingested.
if not exist "%ROOT%load-templates.ps1" goto kibana_start
echo Loading index templates...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ROOT%load-templates.ps1" -ElasticsearchUrl "%ES_URL%"
if errorlevel 1 set "FELK_TEMPLATES_FAILED=1"

:kibana_start
set "FELK_WAIT_URL=%KIBANA_URL%/api/status"
%PS% "$probeCommand"
if not errorlevel 1 goto kibana_running
echo Starting Kibana...
start "Forensic ELK - Kibana" /D "%KIBANA_HOME%" cmd /k bin\kibana.bat
goto kibana_wait
:kibana_running
echo Kibana is already running at %KIBANA_URL%
:kibana_wait
echo Waiting up to %FELK_WAIT_SECONDS% seconds for Kibana...
%PS% "$waitCommand"
if errorlevel 1 goto kibana_failed
echo Kibana is up at %KIBANA_URL%
echo.
if defined FELK_TEMPLATES_FAILED goto templates_failed
echo Forensic ELK is ready. From VMs, use this workstation's IP address with ports $ElasticsearchPort and $KibanaPort.
exit /b 0

:templates_failed
echo WARNING: Elasticsearch and Kibana are running, but some index templates failed to load (see the errors above).
echo Indexes created before they load will not get the SOF-ELK and toolkit mappings.
exit /b 2

:es_failed
echo ERROR: Elasticsearch did not answer at %ES_URL% within %FELK_WAIT_SECONDS% seconds.
echo Check the "Forensic ELK - Elasticsearch" window and %ES_HOME%\logs\forensic-elk.log
exit /b 1

:kibana_failed
echo ERROR: Kibana did not answer at %KIBANA_URL% within %FELK_WAIT_SECONDS% seconds.
echo Check the "Forensic ELK - Kibana" window.
exit /b 1
"@
    Write-TextFile $startBatPath $startBat -Ascii
    Write-Info "Wrote $startBatPath"
}

# ---------------------------------------------------------------------------
# Start: run start.bat and verify
# ---------------------------------------------------------------------------
if ($Steps -contains 'Start') {
    if (-not (Test-Path -LiteralPath $startBatPath)) {
        throw "$startBatPath not found. Run the StartScript step first."
    }
    Write-Info 'Starting Elasticsearch and Kibana via start.bat'
    & $startBatPath
    if ($LASTEXITCODE -eq 2) {
        throw 'start.bat started both services but some index templates failed to load; see the errors above.'
    } elseif ($LASTEXITCODE -ne 0) {
        throw "start.bat reported a startup failure (exit code $LASTEXITCODE)."
    }

    # Confirm the API answers without credentials and reports the expected version.
    $info = Invoke-RestMethod -Uri "http://127.0.0.1:$ElasticsearchPort/" -UseBasicParsing
    Write-Info "Elasticsearch $($info.version.number) answered without credentials (cluster '$($info.cluster_name)')"
    if ($info.version.number -ne $ElasticVersion) {
        Write-Warn "Expected Elasticsearch $ElasticVersion but the node reports $($info.version.number)"
    }
} elseif (Test-Path -LiteralPath $startBatPath) {
    Write-Info "Run $startBatPath to start Elasticsearch and Kibana."
}

# ---------------------------------------------------------------------------
# Cleanup: remove the downloaded zip files once everything above succeeded
# ---------------------------------------------------------------------------
if ($Steps -contains 'Cleanup') {
    # Matches the zips, their .sha512 checksum files and any partial download.
    $downloads = @(Get-ChildItem -LiteralPath $ElkRoot -File |
        Where-Object { $_.Name -like 'elasticsearch-*-windows-x86_64.zip*' -or $_.Name -like 'kibana-*-windows-x86_64.zip*' })
    foreach ($file in $downloads) {
        Remove-Item -LiteralPath $file.FullName -Force
        Write-Info "Removed $($file.FullName)"
    }
    if ($downloads.Count -eq 0) { Write-Info 'No downloaded zip files to remove' }
}

Write-Host ''
Write-Host 'Endpoints (no username or password):'
Write-Host "  This workstation : http://localhost:$KibanaPort  (Kibana)   http://localhost:$ElasticsearchPort  (Elasticsearch)"
foreach ($addr in Get-HostIPv4Addresses) {
    Write-Host ("  {0,-17}: http://{1}:{2}  (Kibana)   http://{1}:{3}  (Elasticsearch)" -f $addr.InterfaceAlias, $addr.IPAddress, $KibanaPort, $ElasticsearchPort)
}
Write-Host ''
Write-Host 'From a VM, use the address of the adapter on that VM''s network, for example:'
Write-Host "  python3 SOF-ELK_CreateDataViews.py --kibana http://<workstation-ip>:$KibanaPort   (SOF-ELK + toolkit Data Views)"
Write-Host "  python3 SOF-ELK_ImportWrapper.py <case-dir> <hostname> --es http://<workstation-ip>:$ElasticsearchPort"
Write-Host "Later starts: run $startBatPath"
