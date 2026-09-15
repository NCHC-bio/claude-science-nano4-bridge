# ssh-2fa-bridge

Makes a cluster that requires interactive two-factor login usable as an
ordinary SSH target, so automation can drive it.

## Why

Many HPC sites enforce keyboard-interactive 2FA — a method menu, then a
password, then a one-time code — and some split services across two ports:

| Endpoint | Typical port | Provides |
|---|---|---|
| login node | 22 | shell, `exec`, scheduler commands; often **no** sftp |
| transfer node | 2222 | sftp / scp / rsync; often **no** shell |

No automation can complete that login. A client holds one secret and cannot
answer three sequential prompts, and the fresh OTP each session needs is
exactly what a non-interactive client cannot produce. Where the server also
declines public-key auth, there is no automated path at all: CI, orchestrators,
agent platforms, and configuration-management tools all hit the same wall.

## How

You authenticate **once, by hand**. The bridge holds those sessions open and
serves a plain SSH endpoint on your own machine that speaks ordinary
single-prompt auth, forwarding each channel type to the endpoint that supports
it:

```
 client ──ssh──▶ your machine:2200
                      ├── exec ──▶ cluster:22     (2FA session, held open)
                      └── sftp ──▶ cluster:2222   (transfer node)
```

Anything that speaks SSH can then drive the cluster, with the two-port split
hidden behind one apparent host. Your password and OTP are typed by you, kept
in memory for the two upstream logins only, and never written to disk.

This is what OpenSSH connection multiplexing
(`ControlMaster`/`ControlPersist`) would give you, for clients that don't
support it — Windows among them.

---

# Setup

Five steps. Steps 1–4 are once per machine; step 5 is once per client.

## 1. Install prerequisites

- Python 3.9+ and [`uv`](https://docs.astral.sh/uv/). The script carries a
  PEP 723 header, so `uv run` fetches paramiko into a throwaway environment —
  nothing touches your global Python or a project venv.
- An authenticator app enrolled for your cluster account.

## 2. Point the bridge at your cluster

Create `bridge.conf` beside the script:

```ini
BRIDGE_USER=your_account
BRIDGE_HOST=login.your-cluster.example
BRIDGE_PORT=22
BRIDGE_SFTP_PORT=2222
```

| Key | Required | Meaning |
|---|---|---|
| `BRIDGE_USER` | yes | your cluster account |
| `BRIDGE_HOST` | yes | cluster hostname |
| `BRIDGE_PORT` | no | upstream shell port (default 22) |
| `BRIDGE_SFTP_PORT` | no | upstream sftp port (default 2222) |
| `BRIDGE_EXPECT` | no | the address your client will dial; checked at startup (step 3) |

Environment variables of the same names take precedence, so CI or a wrapper
script can override any of them.

If your cluster serves sftp on the same port as the shell, run with
`--no-transfer` and let a single session carry both.

## 3. Decide which address the client will dial

The bridge binds `0.0.0.0` by default, because a client running in a container
or VM — as managed agent platforms typically do — has its own `127.0.0.1`, and
a loopback bind is unreachable from it.

Choose an address that won't move:

| Candidate | Stability |
|---|---|
| A virtual adapter address (hypervisor host-only switch, or a loopback adapter with a static IP) | Internal to the OS; unaffected by which network you join |
| The machine's LAN address | Works, but changes with every network joined — poor for laptops |
| `host.docker.internal` | Depends on the client's runtime; test before relying on it |

Start the bridge once and it lists what's available, so you don't need
`ipconfig` or `ip addr`:

```
  local addresses:
     <address of each local interface, one per line>
```

Put your choice in `bridge.conf` as `BRIDGE_EXPECT`. Every later start then
verifies it still exists:

```
  client target address <BRIDGE_EXPECT>: present
```

Some virtual switches get reassigned across reboots or OS updates. When that
happens the check fails loudly and prints the current addresses, instead of
leaving you with an unexplained timeout.

## 4. Allow the port inbound

Your OS firewall must accept connections from the client. Windows, from an
**Administrator** PowerShell:

```powershell
New-NetFirewallRule -DisplayName "ssh bridge 2200" `
  -Direction Inbound -Protocol TCP -LocalPort 2200 -Action Allow `
  -RemoteAddress 172.16.0.0/12,192.168.0.0/16,10.0.0.0/8
```

Linux:

```bash
sudo ufw allow from 172.16.0.0/12 to any port 2200 proto tcp
```

Restrict the source addresses as shown — the port fronts an authenticated
session on your cluster account, so it should not be reachable from beyond your
own machine's networks. Scope Windows rules to all profiles rather than one:
the virtual adapter a container client uses is often classified differently
from your Wi-Fi.

## 5. Configure the client

### Any SSH client

In `~/.ssh/config` (`%USERPROFILE%\.ssh\config` on Windows):

```
Host cluster-bridge
    HostName <the address from step 3>
    Port 2200
    User your_account
    PreferredAuthentications password
    PubkeyAuthentication no
    StrictHostKeyChecking accept-new
```

Why each line matters:

- `Port 2200` — the bridge's port, not 22. Omitting it is the most common
  mistake, and it presents as `Connection refused`.
- `PreferredAuthentications password`, `PubkeyAuthentication no` — the bridge
  offers password auth; without these the client offers every key in your agent
  first and can exhaust `MaxAuthTries` before reaching the password.
- `StrictHostKeyChecking accept-new` — the bridge generates its own host key on
  first run. Otherwise the first connection stops for interactive confirmation
  and looks like a hang. `accept-new` trusts it once and still warns if it
  changes later.

Check it:

```
ssh cluster-bridge hostname
```

A cluster login-node name means the whole chain works.

### Claude for Science

Open **Customize → Compute** in the sidebar and add an SSH host. Depending on
the build, either paste the `ssh_config` block above or fill in fields:

| Field | Value |
|---|---|
| Host / HostName | the address from step 3 |
| Port | `2200` |
| User | your cluster account |
| Auth | password |

Then ask the agent to run a command on that host. The first attempt surfaces a
password prompt in the conversation. Type it into that prompt, not into the
chat itself.

**Which password:** the one the **bridge** generated and printed at startup —
the value stored in `local_password.enc`. **Not** your cluster password, and
**not** an OTP. See [Two different passwords](#two-different-passwords) below.

Because the bridge persists that password across restarts, the credential you
save here keeps working — you are not asked for it again on every start.

Because sftp is proxied to the transfer node, the platform's file staging works
as well: command execution, downloads, and job submission with input/output
transfer all behave as they would against a normal host.

---

# Running it

1. Start the bridge — `start-bridge.cmd` on Windows, or `uv run nano4_sshd.py`.
2. Answer the prompts **once**: method, password, OTP. The transfer-node login
   replays those answers, so a single OTP usually covers both.
3. Leave it running and work normally.

The process *is* the session. Closing it, or Ctrl-C, closes both upstream
logins.

## Two different passwords

Two credentials are in play, and they are never interchangeable:

| Credential | Where you type it | What it authenticates |
|---|---|---|
| Your cluster password, then an OTP | the bridge's own prompts, at startup | the **bridge** to the **cluster** (the 2FA login) |
| The bridge password — generated, printed at startup, stored encrypted in `local_password.enc` | your SSH client, or the platform's password prompt | a **client** to the **bridge** |

Your cluster password and OTP never leave the bridge process: they are used for
the two upstream logins and never written to disk, never sent to a client, and
never stored by whatever tool is driving the bridge. A client only ever sees the
generated password.

The practical consequence: if a client asks for a password, it wants the
generated one. If the bridge asks, it wants your real cluster credentials.

### How the bridge password is stored

Never in plaintext. `local_password.enc` is encrypted with AES-256-GCM under a
key derived from **your cluster password** via scrypt, and on Windows the whole
blob is additionally wrapped with DPAPI, binding it to your OS account:

```
local_password.enc = DPAPI( salt | nonce | AES-GCM(scrypt(cluster password, salt)) )
```

You already type your cluster password at startup, so decryption needs no extra
input, and the password itself is never written anywhere.

What each layer buys you:

- **scrypt + AES-GCM** — a stolen file is useless without your cluster
  password, which exists only in your head. Code running as your OS account
  cannot read the bridge password either.
- **DPAPI wrapper** — without your OS account the file cannot even be
  *attempted* offline, so it is not a dictionary target for your cluster
  password. This is why the two layers are combined rather than chosen between.

If you change your cluster password, the file can no longer be decrypted: the
bridge says so, generates a fresh password, and you update it once in your
client. `--new-password` forces the same rotation deliberately.

A heartbeat runs every four minutes — a real no-op command on the login node
plus an sftp `stat` — because protocol keepalives alone don't always prevent
idle reaping:

```
[sshd] 15:12:04 alive (login node + sftp)
```

If an upstream session dies it says so. It cannot reconnect by itself: that
needs a fresh OTP, which only you can supply.

The password it prints is generated once and persisted, so a client credential
you save keeps working across restarts. `--new-password` rotates it.

---

# Troubleshooting

Client errors are diagnostic — each failure mode is distinct:

| Symptom | Meaning | Fix |
|---|---|---|
| `Connection refused`, `Connection to UNKNOWN port -1` | Reached a host that rejected the handshake | Wrong address (often the client's own loopback), or `Port` missing from the config |
| Connection timeout | Packets sent, nothing answered | Firewall (step 4), or an address that doesn't route to this machine (step 3) |
| `Permission denied (password)` | **The connection works** | Only the credential is missing — supply the bridge password |
| `Permission denied (keyboard-interactive)` | The client is hitting the cluster directly | Point it at the bridge, not at the cluster |
| `sftp unavailable (EOF during negotiation)` | The upstream shell port has no sftp subsystem | Expected — sftp comes from the transfer node |
| Host key mismatch | `local_hostkey` was deleted and regenerated | `ssh-keygen -R "[<address>]:2200"` |
| `UPSTREAM LOST` in the bridge output | An upstream session died | Restart; needs fresh OTPs |
| `no scratch_root configured yet` (Claude for Science) | The connection probe has not finished populating the target | Wait a few seconds and retry the transfer |
| Commands suddenly failing | The bridge exited | Check it is still running before debugging anything else |

---

# Options

| Flag | Default | Effect |
|---|---|---|
| `--port` | `2200` | local listen port |
| `--bind` | `0.0.0.0` | local bind address; `127.0.0.1` if the client is on this machine |
| `--expect` | from config | warn if that address is absent; empty disables the check |
| `--heartbeat` | `240` | seconds between keep-warm pokes; `0` disables |
| `--no-transfer` | off | skip the sftp login — one login, exec only |
| `--password` | saved value | pin a password instead of the saved one |
| `--new-password` | off | rotate the saved password |
| `--authorized-key` | `authorized_key.pub` | public key accepted instead of a password |

# Files

| Path | Purpose |
|---|---|
| `nano4_sshd.py` | the SSH front end — this is the bridge |
| `start-bridge.cmd` | Windows launcher |
| `nano4_bridge.py` | alternative file-watching bridge: drop a JSON request in `in/`, read the reply from `out/`. For when no SSH client can be pointed at the endpoint |
| `bridge.conf` | your machine-local settings (step 2) |
| `local_password.enc` | the client password, encrypted (see above) |

`bridge.conf`, the generated host key, and the encrypted password file are
gitignored; keep them that way.
