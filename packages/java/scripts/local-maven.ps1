param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Goals
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot "target"
$classesRoot = Join-Path $targetRoot "classes"
$testClassesRoot = Join-Path $targetRoot "test-classes"
$artifactName = "aegir-security-0.1.0-Beta.1.jar"
$artifactPath = Join-Path $targetRoot $artifactName

function Compile-Sources {
    param(
        [string]$SourceRoot,
        [string]$OutputRoot,
        [string[]]$AdditionalClassPath = @()
    )

    New-Item -ItemType Directory -Force $OutputRoot | Out-Null
    $sources = Get-ChildItem -Recurse $SourceRoot -Filter *.java | ForEach-Object FullName
    if ($sources.Count -eq 0) {
        return
    }

    $args = @("-d", $OutputRoot)
    if ($AdditionalClassPath.Count -gt 0) {
        $args += @("-cp", ($AdditionalClassPath -join [IO.Path]::PathSeparator))
    }
    $args += $sources

    & javac @args
    if ($LASTEXITCODE -ne 0) {
        throw "javac failed."
    }
}

if ($Goals.Count -eq 0) {
    $Goals = @("test")
}

if ($Goals -contains "clean") {
    Remove-Item -Recurse -Force $targetRoot -ErrorAction SilentlyContinue
}

if ($Goals -contains "compile" -or $Goals -contains "test" -or $Goals -contains "package") {
    Compile-Sources -SourceRoot (Join-Path $projectRoot "src\main\java") -OutputRoot $classesRoot
}

if ($Goals -contains "test") {
    Compile-Sources -SourceRoot (Join-Path $projectRoot "src\test\java") -OutputRoot $testClassesRoot -AdditionalClassPath @($classesRoot)
    & java -cp ($classesRoot + [IO.Path]::PathSeparator + $testClassesRoot) cloud.foxlin.aegir.security.AegirSecurityClientTest
    if ($LASTEXITCODE -ne 0) {
        throw "Java test run failed."
    }
}

if ($Goals -contains "package") {
    New-Item -ItemType Directory -Force $targetRoot | Out-Null
    & jar --create --file $artifactPath -C $classesRoot .
    if ($LASTEXITCODE -ne 0) {
        throw "jar packaging failed."
    }

    Write-Host "Created $artifactPath"
}
