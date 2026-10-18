param(
    [Parameter(Mandatory = $true)]
    [string]$Url,

    [Parameter(Mandatory = $true)]
    [string]$Destination,

    [string]$ExpectedSha256 = ""
)

$ErrorActionPreference = "Stop"
$benchmarkRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$destinationPath = [System.IO.Path]::GetFullPath($Destination)
$rootPrefix = $benchmarkRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar

if (-not $destinationPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Destination must stay below benchmark root: $benchmarkRoot"
}

$uri = [System.Uri]$Url
if ($uri.Scheme -ne "https") {
    throw "Only HTTPS artifact URLs are allowed"
}

$allowedHosts = @(
    "downloads.wordpress.org",
    "plugins.svn.wordpress.org",
    "github.com",
    "objects.githubusercontent.com",
    "codeload.github.com"
)
if ($uri.Host -notin $allowedHosts) {
    throw "Host is not in the mechanical download allowlist: $($uri.Host)"
}

if (Test-Path -LiteralPath $destinationPath) {
    throw "Destination already exists; refusing to overwrite: $destinationPath"
}

$parent = Split-Path -Parent $destinationPath
New-Item -ItemType Directory -Path $parent -Force | Out-Null
$partialPath = $destinationPath + ".partial"
if (Test-Path -LiteralPath $partialPath) {
    throw "Partial destination already exists: $partialPath"
}

try {
    $response = Invoke-WebRequest -Uri $uri.AbsoluteUri -OutFile $partialPath -MaximumRedirection 5 -PassThru
    $finalUri = $uri
    if ($response.BaseResponse -and $response.BaseResponse.ResponseUri) {
        $finalUri = [System.Uri]$response.BaseResponse.ResponseUri.AbsoluteUri
    }
    if ($finalUri.Scheme -ne "https" -or $finalUri.Host -notin $allowedHosts) {
        throw "Final artifact URL is outside the HTTPS allowlist: $($finalUri.AbsoluteUri)"
    }
    $hash = (Get-FileHash -LiteralPath $partialPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ExpectedSha256 -and $hash -ne $ExpectedSha256.ToLowerInvariant()) {
        throw "SHA-256 mismatch: expected=$ExpectedSha256 actual=$hash"
    }
    Move-Item -LiteralPath $partialPath -Destination $destinationPath
    [pscustomobject]@{
        source_url = $uri.AbsoluteUri
        final_url = $finalUri.AbsoluteUri
        local_path = $destinationPath
        sha256 = $hash
        bytes = (Get-Item -LiteralPath $destinationPath).Length
    } | ConvertTo-Json -Compress
}
finally {
    if (Test-Path -LiteralPath $partialPath) {
        Remove-Item -LiteralPath $partialPath -Force
    }
}
