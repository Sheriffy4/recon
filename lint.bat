@echo off
echo Running Black code formatter...
black .

echo.
echo Running Ruff linter...
ruff check . --fix

echo.
echo Code quality check complete.
pause