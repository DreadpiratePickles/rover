# Third-party notices for internal/dlp

No code or regular expression in this package is copied from another
project. The detectors are hand-written byte scanners built from the
vendors' own published token formats:

- AWS access key ids (`AKIA`/`ASIA` + 16) and secret access keys (40
  characters): AWS IAM documentation.
- GitHub tokens (`ghp_`, `gho_`, `ghs_`, `ghu_`, `ghr_`, `github_pat_`):
  GitHub's "About authentication to GitHub" documentation.
- Slack tokens (`xoxa-`, `xoxb-`, `xoxp-`, `xoxr-`) and incoming webhooks
  (`hooks.slack.com/services/`): Slack API documentation.
- Stripe secret and restricted keys (`sk_live_`, `rk_live_`): Stripe API keys
  documentation.
- PEM private keys: RFC 7468; JWTs: RFC 7519.

The list of kinds was informed by gitleaks (https://github.com/gitleaks/gitleaks,
MIT License, Copyright (c) 2019 Zachary Rice). If a pattern is ever copied
from it, its MIT notice must be added here in full and the PR must say so.
