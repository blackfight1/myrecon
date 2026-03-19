#!/usr/bin/env bash
set -Eeuo pipefail

# Hunter/MyRecon external tools installer.
# Installs:
# subfinder, chaos, findomain, bbot, shosubgo, dnsx, httpx, naabu, nmap, gowitness, nuclei, subzy
#
# Usage:
#   bash scripts/install-tools.sh

log() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
err() { printf '[ERR ] %s\n' "$*" >&2; }

ensure_path() {
  local gopath_bin
  gopath_bin="$(go env GOPATH 2>/dev/null)/bin"
  export PATH="$HOME/.local/bin:$gopath_bin:$PATH"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "missing required command: $1"
    exit 1
  fi
}

install_go_tool() {
  local name="$1"
  local module="$2"
  log "Installing $name via go install ($module)"
  go install -v "$module"
}

install_findomain() {
  if command -v findomain >/dev/null 2>&1; then
    log "findomain already installed: $(command -v findomain)"
    return
  fi

  if command -v cargo >/dev/null 2>&1; then
    log "Installing findomain via cargo"
    cargo install findomain
    return
  fi

  if command -v brew >/dev/null 2>&1; then
    log "Installing findomain via brew"
    brew install findomain
    return
  fi

  warn "findomain install skipped (cargo/brew not found). Install manually from release or cargo."
}

ensure_pipx() {
  if command -v pipx >/dev/null 2>&1; then
    return
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    warn "python3 not found; cannot auto-install pipx/bbot"
    return
  fi
  log "pipx not found, installing with python3 --user"
  python3 -m pip install --user --upgrade pipx
  python3 -m pipx ensurepath || true
  export PATH="$HOME/.local/bin:$PATH"
}

install_bbot() {
  if command -v bbot >/dev/null 2>&1; then
    log "bbot already installed: $(command -v bbot)"
    return
  fi
  ensure_pipx
  if command -v pipx >/dev/null 2>&1; then
    log "Installing bbot via pipx"
    pipx install bbot || pipx upgrade bbot || true
  else
    warn "bbot install skipped (pipx unavailable)"
  fi
}

install_nmap() {
  if command -v nmap >/dev/null 2>&1; then
    log "nmap already installed: $(command -v nmap)"
    return
  fi

  if command -v apt-get >/dev/null 2>&1; then
    log "Installing nmap via apt-get (requires sudo)"
    sudo apt-get update
    sudo apt-get install -y nmap
    return
  fi
  if command -v dnf >/dev/null 2>&1; then
    log "Installing nmap via dnf (requires sudo)"
    sudo dnf install -y nmap
    return
  fi
  if command -v yum >/dev/null 2>&1; then
    log "Installing nmap via yum (requires sudo)"
    sudo yum install -y nmap
    return
  fi
  if command -v pacman >/dev/null 2>&1; then
    log "Installing nmap via pacman (requires sudo)"
    sudo pacman -Sy --noconfirm nmap
    return
  fi
  if command -v brew >/dev/null 2>&1; then
    log "Installing nmap via brew"
    brew install nmap
    return
  fi

  warn "nmap install skipped (supported package manager not found)"
}

verify_tools() {
  local missing=0
  local tools=(
    subfinder chaos findomain bbot shosubgo dnsx httpx naabu nmap gowitness nuclei subzy
  )
  echo
  log "Tool check:"
  for t in "${tools[@]}"; do
    if command -v "$t" >/dev/null 2>&1; then
      printf '  [OK]   %s -> %s\n' "$t" "$(command -v "$t")"
    else
      printf '  [MISS] %s\n' "$t"
      missing=1
    fi
  done
  echo
  if [[ "$missing" -eq 0 ]]; then
    log "All tools are available."
  else
    warn "Some tools are missing. Install manually if needed."
  fi
}

main() {
  need_cmd go
  ensure_path

  install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  install_go_tool "chaos" "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
  install_findomain
  install_bbot
  install_go_tool "shosubgo" "github.com/incogbyte/shosubgo@latest"
  install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  install_go_tool "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  install_nmap
  install_go_tool "gowitness" "github.com/sensepost/gowitness@latest"
  install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  install_go_tool "subzy" "github.com/PentestPad/subzy@latest"

  if command -v nuclei >/dev/null 2>&1; then
    log "Updating nuclei templates"
    nuclei -update-templates || warn "nuclei template update failed"
  fi

  verify_tools
  log "Done."
}

main "$@"
