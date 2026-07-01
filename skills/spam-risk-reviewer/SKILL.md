---
name: spam-risk-reviewer
description: Review outbound campaign inputs and emit a deterministic spam-risk verdict before send-as can clear its preflight.
source:
  type: agent
---
# Spam Risk Reviewer

Use this skill to review outbound messaging plans before a campaign is sent.
It classifies spam/compliance risk from a fixture JSON file and emits a
deterministic packet with a verdict, risk score, evidence signals, policy
checks, and required fixes.

Inputs:

- `case_path`: package-relative JSON file describing the campaign, recipient
  relationship, consent basis, sender identity, volume, and safety controls.
- `case_json`: inline JSON string with the same campaign fields. This is used
  by registry harnesses so the published package can run without bundled
  fixture files.
- `schema_path`: package-relative JSON Schema file used as the declared output
  contract.
- `schema_json`: inline schema identity JSON, usually
  `{"$id":"runx.spam_risk_review.result.v1"}`.
- `minimum_confidence`: optional numeric confidence floor for the review.

Verdicts:

- `allow`: low-risk transactional or opt-in messaging with sender identity,
  unsubscribe handling where needed, and bounded volume.
- `revise`: moderate risk that can be fixed before sending.
- `block`: high-risk spam pattern, usually involving scraped/rented lists,
  missing consent, missing opt-out, deception, or unsafe scale.

The output packet is `runx.spam_risk_review.result.v1`.
