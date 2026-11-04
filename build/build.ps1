# Build PILA Suite Community .exe. Run from the repo root on Bryant-PC (Windows).
$ErrorActionPreference = "Stop"
Remove-Item -Recurse -Force dist, build\build, build\__pycache__, build\version_info.generated.txt -ErrorAction SilentlyContinue
python -m venv .buildvenv
.\.buildvenv\Scripts\Activate.ps1
python -m pip install --upgrade pip pyinstaller
pyinstaller --clean --noconfirm build\pila-suite.spec
deactivate
Get-ChildItem dist\pila-suite-*.exe | ForEach-Object { Write-Host "Built:" $_.FullName }
