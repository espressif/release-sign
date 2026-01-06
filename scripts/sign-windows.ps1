# Sign Windows files using Azure Key Vault and Jsign (Windows version)
# Usage: sign-windows.ps1 -Path <path>

param(
    [Parameter(Mandatory=$true)]
    [string]$Path
)

$ErrorActionPreference = "Stop"

# Validate path
if (-not (Test-Path $Path)) {
    Write-Error "Path not found: $Path"
    exit 1
}

# Required environment variables
$requiredVars = @("JSIGN_JAR", "AZURE_TOKEN", "KEYVAULT_URI", "CERT_NAME")
foreach ($var in $requiredVars) {
    if (-not (Get-Item "Env:$var" -ErrorAction SilentlyContinue)) {
        Write-Error "$var environment variable required"
        exit 1
    }
}

$JsignJar = $env:JSIGN_JAR
$AzureToken = $env:AZURE_TOKEN
$KeyvaultUri = $env:KEYVAULT_URI
$CertName = $env:CERT_NAME
$DigestAlg = if ($env:DIGEST_ALG) { $env:DIGEST_ALG } else { "SHA-256" }

# Optional certificate chain
$CertchainArg = @()
if ($env:CERT_CHAIN) {
    $CertchainFile = Join-Path $env:GITHUB_WORKSPACE "certchain.p7b"
    $env:CERT_CHAIN | Out-File -FilePath $CertchainFile -Encoding UTF8
    $CertchainArg = @("-certchain", $CertchainFile)
    Write-Host "Using certificate chain file"
}

function Sign-WindowsFile {
    param([string]$FilePath)

    Write-Host "Signing: $FilePath"
    $args = @(
        "-jar", $JsignJar,
        "--storetype", "AZUREKEYVAULT",
        "--keystore", $KeyvaultUri,
        "--storepass", $AzureToken,
        "--alias", $CertName,
        "--alg", $DigestAlg,
        "--tsaurl", "http://timestamp.digicert.com",
        "--tsretries", "3",
        "--tsretrywait", "10",
        $FilePath
    )

    & java $args
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to sign: $FilePath"
        exit 1
    }
    Write-Host "Successfully signed: $FilePath"
}

function Sign-JarFile {
    param([string]$FilePath)

    Write-Host "Signing JAR: $FilePath"
    $args = @(
        "-J-cp", "-J$JsignJar",
        "-J--add-modules", "-Jjava.sql",
        "-providerClass", "net.jsign.jca.JsignJcaProvider",
        "-providerArg", $KeyvaultUri,
        "-keystore", "NONE",
        "-storetype", "AZUREKEYVAULT",
        "-storepass", $AzureToken,
        "-tsa", "http://timestamp.digicert.com"
    ) + $CertchainArg + @($FilePath, $CertName)

    & jarsigner $args
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to sign: $FilePath"
        exit 1
    }
    Write-Host "Successfully signed: $FilePath"
}

function Verify-File {
    param([string]$FilePath)

    Write-Host "Verifying: $FilePath"
    if ($FilePath -like "*.jar") {
        & jarsigner -verify -verbose $FilePath 2>&1 | Out-Null
    } else {
        & java -jar $JsignJar extract $FilePath 2>&1 | Out-Null
    }
}

Write-Host "=== Signing files in: $Path ==="

# Get files to sign
$windowsExtensions = @("*.exe", "*.dll", "*.cat", "*.sys", "*.msi", "*.ps1")
$jarExtension = @("*.jar")

if (Test-Path $Path -PathType Container) {
    # Directory: find and sign all supported files
    foreach ($ext in $windowsExtensions) {
        Get-ChildItem -Path $Path -Filter $ext -Recurse -File | ForEach-Object {
            Sign-WindowsFile -FilePath $_.FullName
        }
    }

    Get-ChildItem -Path $Path -Filter "*.jar" -Recurse -File | ForEach-Object {
        Sign-JarFile -FilePath $_.FullName
    }
} else {
    # Single file
    if ($Path -like "*.jar") {
        Sign-JarFile -FilePath $Path
    } else {
        Sign-WindowsFile -FilePath $Path
    }
}

Write-Host "=== Verifying signatures ==="

if (Test-Path $Path -PathType Container) {
    $allExtensions = $windowsExtensions + $jarExtension
    foreach ($ext in $allExtensions) {
        Get-ChildItem -Path $Path -Filter $ext -Recurse -File | ForEach-Object {
            Verify-File -FilePath $_.FullName
        }
    }
} else {
    Verify-File -FilePath $Path
}

Write-Host "=== Signing complete ==="
