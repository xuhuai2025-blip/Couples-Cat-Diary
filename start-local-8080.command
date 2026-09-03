#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -P "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
cd "$SCRIPT_DIR"

PYTHON_EXECUTABLE="${PYTHON_EXECUTABLE:-python3}"
if ! command -v "$PYTHON_EXECUTABLE" >/dev/null 2>&1; then
    echo "Python 3 was not found. Install Python 3.10 or newer first."
    exit 1
fi

VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python3"
if [ ! -x "$VENV_PYTHON" ]; then
    echo "[1/3] Creating a Python virtual environment..."
    "$PYTHON_EXECUTABLE" -m venv "$SCRIPT_DIR/.venv"
fi

echo "[2/3] Installing or checking dependencies..."
"$VENV_PYTHON" -m pip install --disable-pip-version-check -r "$SCRIPT_DIR/requirements.txt"

if [ ! -f "$SCRIPT_DIR/diary.db" ]; then
    echo "[3/3] Initializing the local preview database..."
    "$VENV_PYTHON" "$SCRIPT_DIR/init_db.py" \
        --user1 "preview_a" --name1 "Preview A" --pass1 "PreviewCat-A!8080" \
        --user2 "preview_b" --name2 "Preview B" --pass2 "PreviewCat-B!8080"
else
    echo "[3/3] diary.db already exists; keeping the existing local data."
fi

export HOST="127.0.0.1"
export PORT="8080"

echo
echo "Couples Cat Diary is ready to start:"
echo "  URL: http://127.0.0.1:8080/"
echo "  Account A: preview_a / PreviewCat-A!8080"
echo "  Account B: preview_b / PreviewCat-B!8080"
echo "  Press Control+C to stop the server."
echo

exec "$VENV_PYTHON" "$SCRIPT_DIR/app.py"
