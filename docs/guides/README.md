# Integration guides

Step-by-step guides to connect `mitre-coverage-kit` to each SIEM with a read-only credential, from creating the account to the first report. Every screenshot comes from a real run in the [integration lab](../../lab): Splunk Enterprise 10, Elastic Security 8.17 and Wazuh 4.12, one at a time on a laptop.

| Guide | Credential | Time |
|---|---|---|
| [Splunk](splunk.md) | a role that inherits `user`, a dedicated user, optionally a token | 10 minutes |
| [Elastic Security](elastic.md) | an API key limited to reading detection rules and the log indices | 5 minutes |
| [Wazuh](wazuh.md) | a server API user with the built-in `readonly` role | 5 minutes |
| [Several SIEMs and the web app](serve.md) | the above, one environment prefix per source | 10 minutes |

## Before you start

Install the tool once, on a machine that can reach the SIEM APIs:

```bash
git clone https://github.com/lfjuarez/mitre-coverage-kit.git
cd mitre-coverage-kit
python3 -m venv .venv && .venv/bin/pip install -e .
```

Three things hold for every SIEM:

- **Read-only.** The tool only lists rules and runs one search that counts events per source. It never creates, edits or deletes anything.
- **Credentials only in environment variables.** Never in a flag, a file or the config. They go in request headers and are never written to disk or printed.
- **TLS verified.** Pass `--ca` with your CA bundle when the SIEM uses a private certificate. `--insecure` exists for labs with self-signed certificates and prints a warning every time.

If you cannot give the tool network access to the SIEM, every guide also shows the manual route: export the same two files by hand and run `coveragekit import`.
