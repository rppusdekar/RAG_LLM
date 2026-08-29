---
name: Managed AI verification
description: Provisioning behavior for Replit-managed OpenAI access in this workspace.
---

Replit-managed OpenAI provisioning can return an awaiting-phone-verification status before it creates the required managed environment variables. Retry the same provider setup after the user completes verification.

**Why:** The first provisioning attempt paused at phone verification even though the application code and integration package were otherwise ready.

**How to apply:** If managed OpenAI setup reports that status, do not request or handle a personal API key. Let the user complete Replit verification, then rerun provider setup and restart the consuming workflow.