# nano4-bridge

Every time you connect to nano4 it asks you three things: which login method,
your iService password, and a one-time code from your phone. Programs can't
answer those questions, so programs can't use nano4 by themselves.

This tool lets **you** log in once, by hand. After that your programs — Claude
for Science, for example — can work with nano4 through your login, for as long
as you leave it running.

You don't need to know anything about networks or programming to set this up.

## What you need

- A Windows computer
- Your iService account name
- The authenticator app on your phone, the one that shows the one-time code

---

# Setting it up

## 1. Double-click `start-bridge.cmd`

That is the whole setup. The first time you run it, it prepares everything by
itself, which takes a couple of minutes:

- it asks for your **iService account name** — type it and press Enter
- Windows asks for permission to change firewall settings — click **Yes**
- then it asks you to log in

If Windows warns you about running the file, choose **More info → Run anyway**.

## 2. Log in

Three questions, the same ones nano4 always asks:

```
Login method:   type 1  and press Enter
Password:       your iService password
OTP:            the six digits from your phone app
```

While you type your password **nothing appears on screen** — no dots, no stars.
That is normal.

## 3. Add it to Claude for Science

Only needed once. In the left sidebar open **Customize → Compute**, then
**Add SSH host**:

1. Under **From ~/.ssh/config**, choose **`nano4-bridge`** — the bridge already
   created this entry for you, so there is nothing to type.
2. Under **Authentication**, click **Password**. This matters: **Public key** is
   selected by default and will not work.
3. Save.

Then ask Claude to run something on nano4. A password box appears — paste the
`Password` line from the bridge window into that box, not into the chat.

The optional notes box is a good place for anything Claude should know about the
cluster, for example: *Slurm cluster, submit jobs with sbatch.*

**Leave the bridge window open.** Closing it ends the connection.

---

# Every day after this

Double-click `start-bridge.cmd`, answer the three questions, leave the window
open while you work.

Nothing else needs setting up again, and the password stays the same, so you
won't have to change anything in Claude for Science.

---

# If something isn't working

| What you see | What to do |
|---|---|
| Claude can't connect to nano4 | Check the `start-bridge.cmd` window is still open. That window is the connection. |
| The bridge window is gone | Double-click `start-bridge.cmd` again and log in. |
| `UPSTREAM LOST` in the window | nano4 dropped the connection. Close the window and start it again. |
| It said the firewall was **NOT allowed** | Close the window, double-click `start-bridge.cmd` again, and click **Yes** on the Windows prompt. |
| It says the address changed | Nothing to do — the bridge updates the entry itself. If Claude still cannot connect, add the host again in Customize → Compute. |
| Anything else | Copy what the window shows and send it to whoever maintains this. |

| Claude can run commands but cannot send or fetch files | Wait a minute — the first connection is still finishing. If it persists, click **Retry probe** on the host in **Customize → Compute**. |
| Claude asks for a password and rejects it | Run `start-bridge.cmd` and re-copy the `Password` line from the window. |
| Claude says `Permission denied (publickey)` | The host was added with **Public key**. Add it again and choose **Password**. |

---

# Two passwords — don't mix them up

| Password | Where you type it | What it's for |
|---|---|---|
| Your **iService** password, plus the one-time code | The `start-bridge.cmd` window, when it asks | Logging you in to nano4 |
| The **bridge** password, shown in the box | Claude for Science, or another program | Letting that program use your login |

Your iService password and one-time code are only ever typed into the bridge
window. They are not saved to a file and no program is ever given them.

The bridge password is stored on your computer, scrambled using your iService
password. If someone copies that file they can't read it, because they'd also
need your iService password — which is only in your head.

If you ever change your iService password, the bridge will say it can no longer
read the stored file, print a new bridge password, and you paste that one into
Claude for Science. Nothing breaks.

---

<details>
<summary><b>Technical notes</b> (for whoever maintains this)</summary>

## What it does

nano4 accepts only keyboard-interactive 2FA, and splits services across two
ports: `22` for shell/exec with no sftp subsystem, `2222` for sftp with no
shell. No automation can satisfy a three-prompt login with a per-session OTP,
and the server does not offer publickey auth, so there is no non-interactive
path.

`nano4_sshd.py` authenticates both upstream endpoints once, interactively, then
serves a single-prompt SSH endpoint locally and routes by channel type:

```
 client ──ssh──▶ this machine:2200
                      ├── exec ──▶ nano4:22     (2FA session, held open)
                      └── sftp ──▶ nano4:2222   (transfer node)
```

Effectively `ControlMaster`/`ControlPersist` for a client that can't multiplex —
Windows OpenSSH among them. The transfer-node login replays the first login's
answers, so one OTP covers both.

## Configuration

`bridge.conf` (gitignored, written on first run); environment variables of the
same names take precedence:

| Key | Default | Meaning |
|---|---|---|
| `BRIDGE_USER` | — | iService account, required |
| `BRIDGE_HOST` | `nano4.nchc.org.tw` | upstream host |
| `BRIDGE_PORT` | `22` | upstream shell port |
| `BRIDGE_SFTP_PORT` | `2222` | upstream sftp port |
| `BRIDGE_EXPECT` | — | address clients dial; verified at startup |

## Flags

| Flag | Default | Effect |
|---|---|---|
| `--port` | `2200` | local listen port |
| `--bind` | `0.0.0.0` | local bind address |
| `--show-address` | — | print the recommended address and exit |
| `--expect` | from config | warn if that address is absent |
| `--heartbeat` | `240` | keep-warm interval, seconds; `0` disables |
| `--no-transfer` | off | skip the sftp login |
| `--password` / `--new-password` | — | pin or rotate the client password |
| `--authorized-key` | `authorized_key.pub` | accept a public key instead |

## Address selection

`--bind 0.0.0.0` is required: the client may run in a container or VM, where
`127.0.0.1` is its own loopback. `address_candidates()` enumerates interfaces
(`ipconfig` on Windows, matching the locale-invariant `IPv4` label, plus
`gethostbyname_ex` and a UDP route probe) and ranks virtual-adapter addresses
above the routed one, since the routed address moves with the network.
`host.docker.internal` was tested against the Claude for Science client and does
not resolve to anything reachable.

## Credential storage

```
local_password.enc = DPAPI( salt | nonce | AES-256-GCM( scrypt(iService password, salt) ) )
```

scrypt at `n=2**15, r=8, p=1`, with `maxmem` raised — OpenSSL's default 32 MB
cap rejects exactly these parameters. The iService password is captured from the
first non-echo prompt and held in memory only. The outer DPAPI layer binds the
file to the Windows account so a stolen copy is not an offline guessing target
for the iService password; the inner layer means an attacker with the OS account
still cannot read it. Password resolution therefore happens after the
login-node connect.

## Manual setup

What `bridge.ps1` does on first run, if you'd rather do it by hand:

```powershell
# firewall (Administrator)
New-NetFirewallRule -DisplayName "nano4 bridge 2200" -Direction Inbound `
  -Protocol TCP -LocalPort 2200 -Action Allow `
  -RemoteAddress 172.16.0.0/12,192.168.0.0/16,10.0.0.0/8
```

```
# %USERPROFILE%\.ssh\config
Host nano4-bridge
    HostName <uv run nano4_sshd.py --show-address>
    Port 2200
    User <iService account>
    PreferredAuthentications password
    PubkeyAuthentication no
    StrictHostKeyChecking accept-new
```

The last three lines matter: the bridge offers password auth only, and it
presents a self-generated host key that would otherwise stop a probe with an
interactive confirmation.

## Diagnosing a failed connection

| Client error | Cause |
|---|---|
| `Connection refused` / `Connection to UNKNOWN port -1` | wrong address (often the client's own loopback) or missing `Port 2200` |
| probe timeout | firewall, or an address that doesn't route to this machine |
| `Permission denied (password)` | connection fine, credential missing |
| `Permission denied (keyboard-interactive)` | client is dialling nano4 directly, not the bridge |
| `sftp unavailable (EOF during negotiation)` | expected on port 22; sftp comes from 2222 |
| `no scratch_root configured yet` | probe hasn't finished populating it; it cleared on its own within a couple of minutes on 2026-09-15, otherwise **Retry probe** in Customize → Compute |
| host key mismatch | `local_hostkey` regenerated; `ssh-keygen -R "[<addr>]:2200"` |

## Files

| Path | Purpose |
|---|---|
| `nano4_sshd.py` | the bridge |
| `start-bridge.cmd` | the only thing a user runs |
| `bridge.ps1` | first-run setup (uv, bridge.conf, firewall, ssh entry) then starts the bridge |
| `nano4_bridge.py` | alternative file-watching bridge (`in/` → `out/` JSON), for when no SSH client can be pointed at the endpoint |
| `bridge.conf.example` | template; `bridge.conf` is gitignored |

</details>
