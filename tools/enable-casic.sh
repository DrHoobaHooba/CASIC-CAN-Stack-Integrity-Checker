#!/usr/bin/env bash
set -euo pipefail

PERSIST=0
if [[ "${1:-}" == "--persist" ]]; then
  PERSIST=1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_BIN="${REPO_ROOT}/.venv/bin"

if [[ ! -d "${VENV_BIN}" ]]; then
  echo "Missing virtual environment at ${VENV_BIN}. Create it first: python3 -m venv .venv" >&2
  exit 1
fi

case ":${PATH}:" in
  *":${VENV_BIN}:"*) ;;
  *) export PATH="${VENV_BIN}:${PATH}" ;;
esac

echo "CASIC commands enabled for current shell: cansic, udsic, j1939sic, cosic"
echo "Try: cansic -h"

if [[ "${PERSIST}" -eq 1 ]]; then
  LINE="export PATH=\"${VENV_BIN}:\$PATH\""
  for RC in "${HOME}/.bashrc" "${HOME}/.zshrc"; do
    if [[ -f "${RC}" ]]; then
      if ! grep -Fq "${VENV_BIN}" "${RC}"; then
        printf "\n# CASIC\n%s\n" "${LINE}" >> "${RC}"
        echo "Updated ${RC}"
      fi
    fi
  done
  echo "Open a new terminal or run: source ~/.bashrc (or ~/.zshrc)"
fi
