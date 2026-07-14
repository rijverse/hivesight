# hivesight

A hive of honeypots with sight into everything they catch. Cowrie
(SSH/Telnet) and Dionaea (FTP, HTTP,
SMB, MSSQL, MQTT, SIP, Redis, Memcached, MongoDB, ...) run in Docker, with
logs shipped through Promtail to Loki and visualized in Grafana. An orchestrator
sidecar feeds attacker commands to a local LLM (Ollama, qwen2.5:0.5b) for
triage, streams Dionaea's captured binaries to ClamAV, and pushes the
results back to Loki with per-country geo enrichment.

## Quick start

```
sudo ./bin/up.sh          # start everything
sudo ./bin/up.sh --stop   # stop
sudo ./bin/up.sh --reset  # stop and destroy all data volumes
```

Grafana lives at http://localhost:3000 (admin / admin unless you set
`GRAFANA_ADMIN_PASSWORD` in a `.env` file). The port is bound to loopback
only. For remote access use an SSH tunnel, never expose it on the honeypot
interface.

## Host ports

Cowrie takes 22 (SSH) and 23 (Telnet), so move the real sshd first.
Dionaea takes 21, 80, 443, 445, 1433, 1883, 3306, 5060, 5061, 6379, 8081,
11211 and 27017.

## Egress blocking

`bin/up.sh` installs iptables rules (in the DOCKER-USER chain, see
`egress-block.sh`) so honeypot containers can answer inbound connections
and reach the log backend but cannot initiate anything toward the
internet. Re-run `sudo ./egress-block.sh` after a docker daemon restart.

## Layout

- `docker-compose.yml` - honeypots + logging (cowrie, dionaea, loki,
  promtail, grafana, sqlite pump)
- `docker-compose-ai-av.yml` - AI/AV layer (ollama, clamav, orchestrator).
  Always used together with the base file.
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
