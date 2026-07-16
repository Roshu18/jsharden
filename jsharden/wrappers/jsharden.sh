#!/usr/bin/env bash
# ============================================================
#  jsharden drag-and-drop wrapper (macOS / Linux)
#  Usage:
#    - Drag a .js file (or folder) onto this script in your file
#      manager (works on most Linux DEs; macOS users can use
#      Automator's "Run Shell Script" action pointed at this file).
#    - Or run from a terminal:
#        ./jsharden.sh path/to/file.js
#        ./jsharden.sh path/to/folder
#  Output: <filename>.hardened.js in the same folder.
#
#  To change the profile, edit the PROFILE env var below.
#  Profiles: light | balanced | max
# ============================================================
set -euo pipefail

PROFILE="${JSHARDEN_PROFILE:-balanced}"

# Locate jsharden.
if command -v jsharden >/dev/null 2>&1; then
  JSHARDEN="jsharden"
elif [ -x "$(dirname "$0")/node_modules/.bin/jsharden" ]; then
  JSHARDEN="$(dirname "$0")/node_modules/.bin/jsharden"
else
  echo "[error] jsharden not found."
  echo "        Install with:  npm install -g jsharden"
  if [ -t 0 ]; then read -r -p "Press Enter to close..." _; fi
  exit 1
fi

if [ "$#" -eq 0 ]; then
  echo "Drag a .js file or folder onto this script to harden it."
  echo
  echo "Or run from a terminal:"
  echo "  $0 <file.js>"
  echo "  $0 <folder>"
  if [ -t 0 ]; then read -r -p "Press Enter to close..." _; fi
  exit 0
fi

echo "[jsharden] hardening $*  (profile=$PROFILE)"
"$JSHARDEN" "$@" --profile "$PROFILE" || {
  echo
  echo "[jsharden] FAILED — see error above."
  if [ -t 0 ]; then read -r -p "Press Enter to close..." _; fi
  exit 1
}

echo
echo "[jsharden] done. Output written next to the input."
if [ -t 0 ]; then read -r -p "Press Enter to close..." _; fi
