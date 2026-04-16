# Installer Guide

The wrapped installers bootstrap only the Beta-1 SDK and MCP components in this repository.

## PowerShell

```powershell
pwsh ./installers/install-sdk.ps1 -DotNet -Node -Java -Python -Go -Mcp
```

Supported switches:

- `-DotNet`
- `-Node`
- `-Java`
- `-Python`
- `-Go`
- `-Mcp`
- `-All`

## Shell

```bash
bash ./installers/install-sdk.sh --dotnet --node --java --python --go --mcp
```

Supported flags:

- `--dotnet`
- `--node`
- `--java`
- `--python`
- `--go`
- `--mcp`
- `--all`

## Behavior

The installers:

- print the Beta-1 SDK version
- install package-level dependencies where required
- build the local Node package when requested
- prepare the MCP package for local use
- do not publish anything

