# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Avowa, Inc.
"""
Minimal example: instrument an Anthropic client so every call emits an Avowa signal.

    export AVOWA_RUNTIME_KEY="..."
    export AVOWA_BASE_URL="http://localhost:8000"
    python example.py
"""
import os
from avowa_runtime import AvowaRuntime

avowa = AvowaRuntime(region=os.getenv("AVOWA_REGION", "us-east-1"))

avowa.capture(model="claude-opus-4-8", region="us-east-1",
              train_on_data=False, guardrail_blocked=False, latency_ms=512)
print("sent a sample runtime signal")

avowa.capture(model="claude-opus-4-8", region="us-east-1", train_on_data=False,
              injection_blocked=False,
              pii_redacted=True,
              model_pinned=True,
              output_validated=True,
              tool_authorized=True,
              action_authorized=True,
              system_prompt_protected=True,
              grounded=True,
              rate_limited=False,
              eval_score=0.94)
print("sent an AI-security runtime signal (OWASP LLM Top 10 + agentic)")


avowa.flush()
print("flushed — check Avowa → Connections → Avowa Runtime SDK → Capture signals")
