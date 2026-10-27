# Seed database with realistic demo tasks, audit events, and governance approvals
.\.venv\Scripts\Activate.ps1
$env:PYTHONPATH="backend"
python -m app.db.seed_demo_data
