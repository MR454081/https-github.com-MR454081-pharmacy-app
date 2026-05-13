@echo off
setlocal
cd /d "%~dp0"

echo Starting Healthcare Pharmacy...
start "" cmd /c "timeout /t 2 /nobreak >nul && start \"\" http://127.0.0.1:5000"
python -c "from app import app, ensure_dirs, ensure_db_migrations; ensure_dirs(); ctx=app.app_context(); ctx.push(); ensure_db_migrations(); ctx.pop(); app.run(host='127.0.0.1', port=5000, debug=False)"

endlocal
