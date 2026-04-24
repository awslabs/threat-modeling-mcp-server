#!/usr/bin/env bash
#
# Install the Threat Modeling Kiro CLI agent globally.
#
# This script copies the agent configuration, prompt, and skills
# to ~/.kiro/ so the agent is available from any directory.
#
# Usage:
#   ./install-kiro-agent.sh          # Install
#   ./install-kiro-agent.sh --remove  # Uninstall

set -euo pipefail

KIRO_HOME="${HOME}/.kiro"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIRO_SRC="${SCRIPT_DIR}/.kiro"

# Files to install
AGENT_CONFIG="agents/threat-modeler.json"
PROMPT_FILE="prompts/threat-modeler.md"
SKILL_DIRS=(
    "skills/phase-1-business-context"
    "skills/phase-2-architecture"
    "skills/phase-3-threat-actors"
    "skills/phase-4-trust-boundaries"
    "skills/phase-5-asset-flows"
    "skills/phase-6-threat-identification"
    "skills/phase-7-mitigation-planning"
    "skills/phase-7-5-code-validation"
    "skills/phase-8-residual-risk"
    "skills/phase-9-output-generation"
)

info()  { printf "\033[0;34m[INFO]\033[0m  %s\n" "$1"; }
ok()    { printf "\033[0;32m[OK]\033[0m    %s\n" "$1"; }
warn()  { printf "\033[0;33m[WARN]\033[0m  %s\n" "$1"; }
error() { printf "\033[0;31m[ERROR]\033[0m %s\n" "$1"; exit 1; }

remove() {
    info "Removing threat-modeler agent from ${KIRO_HOME}..."

    rm -f "${KIRO_HOME}/${AGENT_CONFIG}"
    rm -f "${KIRO_HOME}/${PROMPT_FILE}"
    for skill_dir in "${SKILL_DIRS[@]}"; do
        rm -rf "${KIRO_HOME}/${skill_dir}"
    done

    ok "Threat-modeler agent removed."
    exit 0
}

install() {
    # Verify source files exist
    if [ ! -d "${KIRO_SRC}" ]; then
        error ".kiro directory not found at ${KIRO_SRC}. Run this script from the repo root."
    fi

    if [ ! -f "${KIRO_SRC}/${AGENT_CONFIG}" ]; then
        error "Agent config not found at ${KIRO_SRC}/${AGENT_CONFIG}"
    fi

    # Check for conflicts
    if [ -f "${KIRO_HOME}/${AGENT_CONFIG}" ]; then
        warn "Existing agent config found at ${KIRO_HOME}/${AGENT_CONFIG}"
        read -rp "Overwrite? [y/N] " confirm
        if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
            info "Aborted."
            exit 0
        fi
    fi

    # Also check for underscore variant (old naming convention)
    if [ -f "${KIRO_HOME}/agents/threat_modeler.json" ]; then
        warn "Found old agent config: ${KIRO_HOME}/agents/threat_modeler.json"
        read -rp "Remove it to avoid conflicts? [Y/n] " confirm
        if [[ ! "${confirm}" =~ ^[Nn]$ ]]; then
            rm -f "${KIRO_HOME}/agents/threat_modeler.json"
            ok "Removed old agent config."
        fi
    fi

    # Create directories
    info "Creating directories..."
    mkdir -p "${KIRO_HOME}/agents"
    mkdir -p "${KIRO_HOME}/prompts"
    for skill_dir in "${SKILL_DIRS[@]}"; do
        mkdir -p "${KIRO_HOME}/${skill_dir}"
    done

    # Copy prompt and skills first
    info "Installing prompt..."
    cp "${KIRO_SRC}/${PROMPT_FILE}" "${KIRO_HOME}/${PROMPT_FILE}"
    ok "Prompt installed: ${KIRO_HOME}/${PROMPT_FILE}"

    info "Installing skills..."
    for skill_dir in "${SKILL_DIRS[@]}"; do
        cp "${KIRO_SRC}/${skill_dir}/SKILL.md" "${KIRO_HOME}/${skill_dir}/SKILL.md"
        ok "Skill installed: ${KIRO_HOME}/${skill_dir}/SKILL.md"
    done

    # Install agent config with adjusted resource paths for global install
    # The README resource (file://../../README.md) doesn't make sense globally,
    # so we remove it and keep only the skills reference.
    info "Installing agent config..."
    python3 -c "
import json, sys

with open('${KIRO_SRC}/${AGENT_CONFIG}') as f:
    config = json.load(f)

# Adjust resources for global install: remove project-specific README,
# keep skills (which resolve correctly from ~/.kiro/agents/ -> ~/.kiro/skills/)
config['resources'] = [r for r in config.get('resources', []) if not r.startswith('file://../../')]

with open('${KIRO_HOME}/${AGENT_CONFIG}', 'w') as f:
    json.dump(config, f, indent=2)
    f.write('\n')
"
    ok "Agent config installed: ${KIRO_HOME}/${AGENT_CONFIG}"

    # Verify installation
    info "Verifying installation..."
    if python3 -c "import json; json.load(open('${KIRO_HOME}/${AGENT_CONFIG}'))" 2>/dev/null; then
        ok "Agent config is valid JSON."
    else
        error "Agent config is invalid JSON!"
    fi

    echo ""
    ok "Threat-modeler agent installed successfully!"
    echo ""
    info "Usage:"
    echo "  kiro-cli chat --agent threat-modeler --no-interactive \"Threat model this project\""
    echo ""
    info "Or interactively:"
    echo "  kiro-cli chat --agent threat-modeler"
    echo ""
}

# Main
case "${1:-}" in
    --remove|--uninstall)
        remove
        ;;
    --help|-h)
        echo "Usage: $0 [--remove]"
        echo ""
        echo "Install the Threat Modeling Kiro CLI agent globally to ~/.kiro/"
        echo ""
        echo "Options:"
        echo "  --remove    Remove the agent from ~/.kiro/"
        echo "  --help      Show this help message"
        ;;
    *)
        install
        ;;
esac
