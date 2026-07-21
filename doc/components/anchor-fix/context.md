# Anchor Fix — Outbound Blocking Bug (2026-07-21)

## What was wrong

The original Milestone 1 anchor rules used `pass out quick to <blocklist>` instead of `block out`. This allowed outbound connections to blocked IPs and created pf state entries — meaning the IPS did not actually block outbound traffic to known-bad IPs.

## How it was caught

Functional verification test against a real reachable IP (8.8.8.8) after Milestone 1 was declared "verified working":

```
# With IP in blocklist:
curl -v --connect-timeout 5 http://8.8.8.8/
* Connected to 8.8.8.8 (8.8.8.8) port 80     ← TCP succeeded
* Request completely sent off
* Recv failure: Connection reset by peer

# pf state confirmed:
pfctl -s state -vv | grep 8.8.8.8
ALL tcp 192.168.0.100:64323 -> 8.8.8.8:80  TIME_WAIT  ← state created

# UDP also passed:
echo "test" | nc -u -w 3 8.8.8.8 53
pfctl -s state -vv | grep 8.8.8.8
ALL udp 192.168.0.100:57555 -> 8.8.8.8:53  SINGLE:NO_TRAFFIC
```

## The fix

Changed `pass out quick to <blocklist>` → `block out quick to <blocklist>` in `ensure_anchor()` (`helper/main.rs`).

## Verification after fix

```
# With IP in blocklist (after helper restart):
curl -v --connect-timeout 5 http://8.8.8.8/
* Failed to connect to 8.8.8.8 port 80 after 5005 ms: Timeout was reached

# pf state — empty:
pfctl -s state -vv | grep 8.8.8.8
(no output — no state created)

# UDP — also blocked:
echo "test" | nc -u -w 3 8.8.8.8 53
pfctl -s state -vv | grep 8.8.8.8
(no output — no state created)
```

## Why `block in` is still needed

Even with outbound blocked, `block in quick from <blocklist>` does independent work: it stops blocked IPs from initiating contact toward this machine (remote host scanning/attacking), a different attack direction than outbound C2/exfil.

## Lesson

Milestone 1 was declared "verified working" based on pfctl table add/delete and KillState tests — but outbound blocking was never tested with a real reachable IP. The TEST-NET address (198.51.100.1) used in initial tests couldn't distinguish "blocked" from "unreachable." Always test against a real, responding endpoint.

## Commit

`68e1da1` — "fix: anchor rules block outbound to blocklist + move agent to own crate"
