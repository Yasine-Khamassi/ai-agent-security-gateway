"""Configuration for the Northwind IT-support agent."""

from __future__ import annotations

import os

MODEL = os.environ.get("AISEC_MODEL", "llama3.2:3b")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
REQUEST_TIMEOUT = float(os.environ.get("AISEC_TIMEOUT", "60"))
TEMPERATURE = float(os.environ.get("AISEC_TEMPERATURE", "0.1"))
MAX_STEPS = int(os.environ.get("AISEC_MAX_STEPS", "4"))
