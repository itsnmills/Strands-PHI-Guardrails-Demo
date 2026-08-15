#!/usr/bin/env python3
"""Launch the PHI Guardrails web console."""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8502, reload=False)
