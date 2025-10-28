"""Configuration management for the scanner."""

import json
from pathlib import Path
from typing import Dict, Any

DEFAULT_CONFIG = {
    "scan": {
        "default_timeout": 1.0,
        "default_workers": 100,
        "max_workers": 500,
        "default_ports": "1-1024",
    },
    "reports": {"output_dir": "reports", "save_format": "json"},
    "logging": {"level": "INFO", "file": "scanner.log"},
    "security": {"rate_limit": 100, "max_retries": 3},  # requests per second
}


def load_config(config_file: str = "config.json") -> Dict[str, Any]:
    """Load configuration from file or return defaults."""
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
            # Merge with defaults to ensure all required fields exist
            return {**DEFAULT_CONFIG, **config}
    except FileNotFoundError:
        # Create default config file
        save_config(DEFAULT_CONFIG, config_file)
        return DEFAULT_CONFIG
    except json.JSONDecodeError:
        print(f"Error parsing {config_file}. Using defaults.")
        return DEFAULT_CONFIG


def save_config(config: Dict[str, Any], config_file: str = "config.json") -> None:
    """Save configuration to file."""
    with open(config_file, "w") as f:
        json.dump(config, f, indent=4)
