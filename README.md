# hivesight

A hive of honeypots with sight into everything they catch. Cowrie
(SSH/Telnet) and Dionaea (FTP, HTTP,
SMB, MSSQL, MQTT, SIP, Redis, Memcached, MongoDB, ...) run in Docker, with
logs shipped through Promtail to Loki and visualized in Grafana. An orchestrator
sidecar feeds attacker commands to a local LLM (Ollama, qwen2.5:0.5b) for
triage, streams Dionaea's captured binaries to ClamAV, and pushes the
results back to Loki with per-country geo enrichment.

## Quick start

The stack is split into four bundles you can mix and match:

- `cowrie` - SSH/Telnet honeypot
- `dionaea` - multi-protocol honeypot (FTP, HTTP, SMB, MySQL, Redis, Mongo, ...)
- `logging` - Loki + Promtail + Grafana dashboards
- `ai` - local-LLM triage + ClamAV malware scanning (~4 GB RAM)

```
sudo ./bin/up.sh                     # pick bundles interactively, then start
sudo ./bin/up.sh --all               # start every bundle
sudo ./bin/up.sh --cowrie --logging  # start only the named bundles
sudo ./bin/up.sh --pull --all        # pull images first, then start
sudo ./bin/up.sh --stop              # stop and remove containers
sudo ./bin/up.sh --reset             # stop + destroy all data volumes
```

The bundles are independent: `logging` and `ai` run fine with no honeypot (the
dashboards are just empty and the orchestrator has nothing to triage), and a
honeypot runs fine without them. `ai` and `logging` publish no attack surface,
so `./bin/up.sh --logging --ai` needs no free ports beyond Grafana's loopback
3000 and no root.

Grafana lives at http://localhost:3000 (admin / admin unless you set
`GRAFANA_ADMIN_PASSWORD` in a `.env` file). The port is bound to loopback
only. For remote access use an SSH tunnel, never expose it on the honeypot
interface.

## Running on a workstation

This is built for a dedicated, internet-facing host, but it runs locally if
you keep it closed: don't port-forward it, and pick only the bundles you
want. The one guaranteed clash on a desktop is cowrie's port 22 fighting your
real sshd, so copy `.env.example` to `.env` and set `COWRIE_SSH_PORT` /
`COWRIE_TELNET_PORT` (e.g. 2222/2223). Dionaea publishes a dozen fake services
on all interfaces by design; skip that bundle if you'd rather not.

## Host ports

Cowrie takes 22 (SSH) and 23 (Telnet) by default; override with
`COWRIE_SSH_PORT` / `COWRIE_TELNET_PORT` in `.env`. Dionaea takes 21, 80, 443,
445, 1433, 1883, 3306, 5060, 5061, 6379, 8081, 11211 and 27017.

## Egress blocking

When a honeypot bundle is running, `bin/up.sh` installs iptables rules (in the
DOCKER-USER chain, see `egress-block.sh`) so honeypot containers can answer
inbound connections and reach the log backend but cannot initiate anything
toward the internet. `--stop` and `--reset` remove the rules again. Re-run
`sudo ./egress-block.sh` after a docker daemon restart.

## Layout

- `docker-compose.yml` - honeypots + logging (cowrie, dionaea, loki,
  promtail, grafana, sqlite pump)
- `docker-compose-ai-av.yml` - AI/AV layer (ollama, clamav, orchestrator).
  Both files are always passed to compose; which services actually start is
  decided by Compose profiles (`cowrie`, `dionaea`, `logging`, `ai`) that
  `bin/up.sh` selects from your flags or the menu.
- `.env.example` - copy to `.env` to set cowrie's ports and the Grafana
  password (`.env` is gitignored).
- `orchestrator.py` - tails both honeypot logs, calls Ollama per command,
  drives ClamAV scans of captured binaries, pushes events to Loki
- `dionaea-sqlite-pump.py` - tails dionaea.sqlite and rewrites rows as JSON
  lines for promtail. Exists because the image's log_json ihandler loads
  but never receives incidents; log_sqlite works, so the pump bridges the
  gap.
- `dashboards/` - source of truth for Grafana dashboards. up.sh copies them
  into `grafana-provisioning/dashboards/files/` (generated, gitignored).
- `dionaea-ihandlers/` - reference copies of the image's ihandler configs,
  not mounted anywhere.

## Notes

- Cowrie uses AuthRandom (see `cowrie.cfg`): each new attacker IP must fail
  3 to 5 login attempts before one succeeds, and the winning pair is then
  cached per IP so repeat logins look consistent.
- Loki stream labels are kept low-cardinality on purpose. Attacker IPs,
  usernames and passwords stay in the JSON event body and dashboards group
  by them at query time with `| json`.
