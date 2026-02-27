# Firewall Configuration Tool

A Python-based CLI tool to configure firewall rules on Windows (PowerShell) and Linux (iptables) using a unified YAML policy format.

## Prerequisites

- **Python 3.8+**
- **Administrator or Root privileges** (for applying rules)
- **Dependencies**: `pyyaml`

Install dependencies:
```bash
pip install pyyaml
```

## Usage

### 1. GUI Mode (Recommended)
Launch the graphical interface to manage rules visually.
```bash
python gui.py
```

### 2. CLI Mode
Run the tool from the command line using `main.py`.

#### Dry Run (Safe Mode)
Check what commands would be executed without actually applying them.

**Windows:**
```bash
python main.py firewall_tool/policies/sample_policy.yaml --dry-run
```

**Linux:**
```bash
python main.py firewall_tool/policies/sample_policy.yaml --dry-run
```

### 2. Apply Rules
**WARNING**: This will modify your active firewall rules. Ensure you do not lock yourself out (especially if using SSH/RDP).

```bash
python main.py firewall_tool/policies/sample_policy.yaml
```

### 3. Force Platform (Optional)
You can test logic for a specific platform regardless of your current OS (mostly for dry-run testing).

```bash
python main.py firewall_tool/policies/sample_policy.yaml --dry-run --platform linux
```

## Structure
- `firewall_tool/policies/`: Place your YAML policy files here.
- `firewall_tool/platforms/`: Logic for Windows/Linux specific commands.
