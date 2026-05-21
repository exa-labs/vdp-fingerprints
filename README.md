# Vulnerability Fingerprints

Exa uses vulnerability fingerprints to help identify reports that appear to match issues we have already found, reviewed, or are actively tracking.

## What this means for researchers

When you submit a vulnerability report, Exa may compare the report against fingerprints of previously identified issues.

If your report appears to match an issue that Exa has already flagged, the report may be marked as a duplicate.


When a report is classified as a duplicate, we aim to provide enough information for you to understand and verify the decision. Where possible, you will be redirected to the matching fingerprint hash in Exa’s GitHub repository, along with a short, non-sensitive summary of the duplicate finding. This lets you confirm that the matching finding existed before your report was submitted, without exposing sensitive vulnerability details.

## Verifying a fingerprint locally

If you want to inspect the verification code and verify a proof on your local machine, review `prove.py` and run it against the published root record and the proof packet:

```sh
python3 prove.py fingerprint.json proof.json
```

The script checks that the proof packet's safe summary, finding commitment, proof path, and root all match the published fingerprint root in `fingerprint.json`. A successful verification prints:

```text
OK: proof matches fingerprint root <root>
```

## Why we use fingerprints

Fingerprints help us:

- Identify duplicate reports more consistently.
- Avoid treating the same issue as a new finding multiple times.
- Route reports to reviewers with the right context.
- Keep triage focused on unresolved or newly discovered security issues.

## What a match means

A fingerprint match means the report appears to correspond to a known issue.

A match does not necessarily mean:

- The report was invalid.
- The researcher acted incorrectly.
- The issue is unimportant.
- The issue has already been fully remediated.

It only means Exa had already identified or flagged the same underlying issue before or during the triage process.

We value the time and effort researchers put into finding, validating, and reporting security issues. When a report is classified as a duplicate, we aim to have sufficient evidence to support that decision and to distinguish true duplicates from new variants or materially different findings.

## Researcher report handling

If your report matches a known fingerprint, Exa may use that result as part of triage.

Depending on the circumstances, this may affect duplicate classification, bounty eligibility, prioritization, and response timing under the applicable vulnerability disclosure or bug bounty policy.

## If you believe a match is incorrect

If your report is marked as already flagged but you believe it describes a distinct vulnerability, please reply with additional detail explaining how it differs.

Useful clarifications include:

- A different affected asset or feature.
- A different exploit path.
- A different security impact.
- A different affected user role or permission boundary.
- Evidence that the issue is still exploitable in a way not covered by the known finding.

We will review the additional information under the applicable disclosure policy.
