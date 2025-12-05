# Signing Action

Sign Windows files (.exe, .dll, .cat, .sys, .msi, .ps1, .jar) using Azure Key Vault and [Jsign](https://ebourg.github.io/jsign/).

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

## Path Input

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

## Inputs

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
