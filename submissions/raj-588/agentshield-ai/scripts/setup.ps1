# AgentShield AI — Windows 11 setup
# Run from the project root in PowerShell.
Write-Host "== Checking Python 3.12 ==" -ForegroundColor Cyan
py -3.12 --version
Write-Host "== Creating virtual environment ==" -ForegroundColor Cyan
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if (-Not (Test-Path .env)) { Copy-Item .env.example .env; Write-Host "Created .env from template" }
Write-Host "== Initializing database ==" -ForegroundColor Cyan
$env:PYTHONPATH="backend"; python -m app.db.init_db
Write-Host "Setup complete." -ForegroundColor Green
Write-Host "Optional (live LLM): 'ollama pull qwen2.5:3b' then start Ollama."
