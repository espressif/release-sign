<a href="https://www.espressif.com">
    <img src="https://www.espressif.com/sites/all/themes/espressif/logo-black.svg" alt="Espressif logo" title="Espressif" align="right" height="20" />
</a>

# Signing Action

This is a composite action that makes it easy to sign the files across Espressif organization. It runs on all platforms.

- Signs Windows files
  - `.exe`, `.dll`, `.cat`, `.sys`, `.msi`, `.ps1`, `.jar` using Azure Key Vault and [Jsign](https://ebourg.github.io/jsign/).

<!-- GitHub Badges -->

<div align="center">
  <p>
    <hr>
    <a href="/LICENSE">
      <img alt="Project License" src="https://img.shields.io/github/license/espressif/release-sign"/>
    </a>
    <img alt="GitHub contributors" src="https://img.shields.io/github/contributors/espressif/release-sign?logo=github&label=Contributors&color=purple">
    <img alt="GitHub commit activity" src="https://img.shields.io/github/commit-activity/y/espressif/release-sign?logo=git&logoColor=white&label=Commits&color=purple">
    <img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/espressif/release-sign?logo=git&logoColor=white&label=Last%20commit">
    <br>
    <a href="https://results.pre-commit.ci/latest/github/espressif/release-sign/master">
      <img alt="pre-commit.ci status" src="https://results.pre-commit.ci/badge/github/espressif/release-sign/master.svg">
    </a>
    <a href="https://github.com/espressif/release-sign/actions/workflows/test-sign.yml">
      <img alt="GitHub workflow Signing Tests" src="https://img.shields.io/github/actions/workflow/status/espressif/release-sign/.github%2Fworkflows%2Ftest-sign.yml?branch=master&logo=githubactions&logoColor=white&label=Tests&link=https%3A%2F%2Fgithub.com%2Fespressif%2Frelease-sign%2Factions%2Fworkflows%2Ftest-sign.yml">
    </a>
  </p>
  <hr>
</div>

- [Quick Start](#quick-start)
- [Input](#input)
- [Full Example](#full-example)
- [Supported File Types](#supported-file-types)
- [Action Inputs](#action-inputs)


## Quick Start

```yaml
- uses: espressif/release-sign@master
  with:
    path: ./build
    azure-client-id: ${{ secrets.AZURE_CLIENT_ID }}
    azure-client-secret: ${{ secrets.AZURE_CLIENT_SECRET }}
    azure-tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    azure-keyvault-uri: ${{ secrets.AZURE_KEYVAULT_URI }}
    azure-keyvault-cert-name: ${{ secrets.AZURE_KEYVAULT_CERT_NAME }}
```

## Input

The `path` input accepts:
- **Single file**: `./build/myapp.exe`
- **Directory**: `./dist` (signs all supported files recursively)

## Full Example

```yaml
jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: |
          mkdir -p build
          # ... your build steps

      - name: Sign files
        uses: espressif/release-sign@master
        with:
          path: ./build
          azure-client-id: ${{ secrets.AZURE_CLIENT_ID }}
          azure-client-secret: ${{ secrets.AZURE_CLIENT_SECRET }}
          azure-tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          azure-keyvault-uri: ${{ secrets.AZURE_KEYVAULT_URI }}
          azure-keyvault-cert-name: ${{ secrets.AZURE_KEYVAULT_CERT_NAME }}

      - name: Upload signed files
        uses: actions/upload-artifact@v4
        with:
          name: signed-files
          path: ./build
```

## Supported File Types

| Extension | Type |
|-----------|------|
| `.exe` | Executables |
| `.dll` | Libraries |
| `.cat`, `.sys` | Drivers |
| `.msi`, `.cab` | Installers |
| `.ps1` | PowerShell scripts |
| `.jar` | Java archives (signed with jarsigner) |

## Action Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `path` | Yes | - | Path to file or directory to sign |
| `digest-algorithm` | No | `SHA-256` | Hash algorithm (SHA-256, SHA-384, SHA-512) |
| `azure-client-id` | Yes | - | Azure Service Principal Client ID |
| `azure-client-secret` | Yes | - | Azure Service Principal Client Secret |
| `azure-tenant-id` | Yes | - | Azure Tenant ID |
| `azure-keyvault-uri` | Yes | - | Azure Key Vault URI |
| `azure-keyvault-cert-name` | Yes | - | Certificate name in Key Vault |
| `azure-keyvault-certchain` | No | - | Certificate chain (.p7b) for JAR signing |
| `jsign-version` | No | `7.4` | Jsign version to use |
