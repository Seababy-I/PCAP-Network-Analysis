$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$environmentRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot '.venv-parser'))
if (-not $environmentRoot.StartsWith($projectRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) { throw 'Environment path escapes project' }
$environmentPython = Join-Path $environmentRoot 'Scripts\python.exe'
if ((Test-Path -LiteralPath $environmentRoot) -and -not (Test-Path -LiteralPath $environmentPython)) {
    throw 'An incomplete .venv-parser already exists; inspect it before choosing a new environment path.'
}
if (-not (Test-Path -LiteralPath $environmentPython)) {
    & python -m venv --system-site-packages $environmentRoot
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the isolated parser environment' }
}
& $environmentPython -m pip install --disable-pip-version-check --only-binary=:all: -r (Join-Path $projectRoot 'requirements-parser.txt')
if ($LASTEXITCODE -ne 0) { throw 'Parser dependency installation failed' }
& $environmentPython -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Dependency compatibility check failed' }
& $environmentPython -c "import sys,pyshark,scapy,cryptography; import importlib.metadata as m; print('Parser environment:',sys.executable); print('PyShark:',m.version('pyshark')); print('Application dependencies import successfully')"
if ($LASTEXITCODE -ne 0) { throw 'Parser environment import check failed' }
Write-Output 'Python parser-preview dependencies are prepared. TShark and owner real-capture acceptance remain separate readiness requirements.'
