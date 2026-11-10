# secrets-scanner

Find leaked credentials in a Git repository before someone else does.

`secrets-scanner` checks the files in a repository and, with `--history`, every line that was ever committed. A key that was committed once and deleted later is still in the history, and this tool finds it.

- One Python file, standard library only. Python 3.9+.
- 12 detection rules: AWS, GitHub, Google, Slack, Stripe, Telegram, Anthropic and OpenAI keys, private key blocks, JWTs, database URLs with passwords, and hardcoded passwords.
- Entropy check on generic passwords, so `password = "changeme"` is not reported but a random-looking value is.
- Secrets are never printed in full. Output shows the first 4 characters and the length.
- Exit code 1 when something is found, so it can block a commit or a CI run.

## Usage

```bash
# scan the current folder
python secrets_scanner.py

# scan another repository, including its full Git history
python secrets_scanner.py /path/to/repo --history

# machine-readable output
python secrets_scanner.py --json

# only fail the run for high and critical findings
python secrets_scanner.py --fail-on high
```

Example output:

```
CRITICAL AWS access key ID
         app.py:1
         AKIA****** (20 chars)
MEDIUM   Hardcoded secret in assignment
         app.py:2
         T9#k****** (15 chars)

2 finding(s): 1 critical, 1 medium
```

## How it works

1. **File list.** In a Git repository the scanner asks Git for tracked and untracked files, so anything in `.gitignore` is skipped. Outside Git it walks the folder. Binary files and files over 1 MB are skipped.
2. **Rules.** Each line is matched against a list of regular expressions, one per credential type. Each rule has a severity.
3. **Entropy filter.** The generic rule (`password = "..."`) also requires a Shannon entropy of at least 3.0 bits per character and rejects common placeholders. This removes most false positives.
4. **History.** `--history` reads `git log -p` and scans every added line, with the commit hash, file and line number.

## Ignoring false positives

Add `# nosecret` on a line to skip it:

```python
EXAMPLE_KEY = "not-a-real-key-123"  # nosecret
```

Or list paths in a `.secretsignore` file at the repository root:

```
# test data
tests/fixtures/
docs/*.md
```

## Use as a pre-commit hook

```bash
cat > .git/hooks/pre-commit <<'EOF'
#!/bin/sh
python secrets_scanner.py --fail-on medium
EOF
chmod +x .git/hooks/pre-commit
```

## Use in GitHub Actions

```yaml
name: secrets
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - run: python secrets_scanner.py --history --fail-on high
```

## Tests

```bash
python -m unittest -v
```

20 tests cover each rule, false positives, redaction, the ignore file, binary files and the history scan.

## Limits

- Regular expressions find known key formats. A secret in an unknown format is only caught by the generic rule, and only when it is assigned to a name like `password` or `token`.
- A finding is not proof that a key is live. The scanner does not call any service to check.
- If a real key was committed, deleting it is not enough. Revoke the key and create a new one.

## Roadmap

- Verify findings against the provider where a safe check exists
- SARIF output for the GitHub Security tab
- Custom rules from a config file

Use this tool on repositories you own or have permission to test.

Part of a 10-day security sprint. Day 1 of 10.
