#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["paramiko>=3.4"]
# ///
"""nano4 bridge -- you log in interactively, the assistant drives the session.

Run this in YOUR OWN terminal.  nano4's login prompts (method -> password ->
OTP) are handed to your keyboard; your answers go only to nano4 over SSH.
Nothing is stored and nothing is sent anywhere else.

Once authenticated the script keeps the SSH session open and services request
files that appear in ./in, writing replies to ./out.  Every command is printed
before it runs.  Ctrl-C stops the bridge and closes the session.

    uv run nano4_bridge.py              # uv reads the header above and fetches paramiko
    uv run nano4_bridge.py --confirm    # ask before each command

Override the account with:  set BRIDGE_USER=youruser
"""
import base64
import getpass
import json
import os
import pathlib
import shlex
import sys
import time
import traceback

try:
    import paramiko
except ImportError:
    sys.exit("paramiko is not installed ->  run this with:  uv run nano4_bridge.py")

HOST = os.environ.get("BRIDGE_HOST", "")
PORT = int(os.environ.get("BRIDGE_PORT", "22"))              # shell / exec
SFTP_PORT = int(os.environ.get("BRIDGE_SFTP_PORT", "2222"))  # sftp only
USER = os.environ.get("BRIDGE_USER", "")

# The transfer node is a separate service with its own 2FA login, so it is not
# opened automatically -- queue {"op": "transfer_connect"} when you want it.
SFTP_TRANSPORT = None
SFTP = None

ROOT = pathlib.Path(__file__).resolve().parent
IN_DIR = ROOT / "in"
OUT_DIR = ROOT / "out"

MAX_INLINE = 200_000          # bytes of stdout embedded in the JSON reply
POLL_S = 0.5
CONFIRM = "--confirm" in sys.argv


# --------------------------------------------------------------- auth

def _handler(title, instructions, prompt_list):
    """Relay the server's keyboard-interactive prompts to the user."""
    if title.strip():
        print(title.strip())
    if instructions.strip():
        print(instructions.strip())
    answers = []
    for prompt, echo in prompt_list:
        text = prompt.strip() or "response:"
        answers.append(input(text + " ") if echo else getpass.getpass(text + " "))
    return answers


def connect(port, label):
    """Authenticate one transport.  nano4 asks method -> password -> OTP."""
    print(f"[bridge] connecting to {label} {USER}@{HOST}:{port}")
    transport = paramiko.Transport((HOST, port))
    transport.start_client(timeout=30)
    try:
        transport.auth_interactive(USER, _handler)
    except paramiko.ssh_exception.BadAuthenticationType as exc:
        print(f"[bridge] keyboard-interactive refused: {exc}")
        raise
    if not transport.is_authenticated():
        raise SystemExit(f"[bridge] authentication failed on {label}")
    transport.set_keepalive(30)
    print(f"[bridge] {label} authenticated")
    return transport


def ensure_transfer(ask=True):
    """Open the port-2222 transfer node on demand (it needs its own 2FA).

    The login node (port 22) refuses the sftp subsystem by design -- per the
    nano4 manual, sftp/rsync live on the separate transfer node, which in turn
    offers no shell.  Until this is connected, get/put use base64-over-exec.
    """
    global SFTP, SFTP_TRANSPORT
    if SFTP is not None and SFTP_TRANSPORT is not None and SFTP_TRANSPORT.is_active():
        return SFTP
    if ask:
        print(f"[bridge] the transfer node ({HOST}:{SFTP_PORT}) needs a SEPARATE 2FA login.")
        if input("[bridge] connect it now? [y/N] ").strip().lower() not in ("y", "yes"):
            print("[bridge] staying on base64-over-exec")
            return None
    try:
        SFTP_TRANSPORT = connect(SFTP_PORT, "transfer node")
        SFTP = paramiko.SFTPClient.from_transport(SFTP_TRANSPORT)
        print("[bridge] sftp available on the transfer node")
    except Exception as exc:
        print(f"[bridge] transfer node unavailable ({type(exc).__name__}: {exc})")
        print("[bridge] keeping base64-over-exec for transfers")
        SFTP, SFTP_TRANSPORT = None, None
    return SFTP


# --------------------------------------------------------------- ops

def run_cmd(transport, cmd, timeout, stdin_data=None):
    """Run cmd under a login shell so `module` and conda are available."""
    chan = transport.open_session(timeout=30)
    chan.settimeout(timeout)
    chan.exec_command("bash -lc " + shlex.quote(cmd))
    if stdin_data is not None:
        chan.sendall(stdin_data)
        chan.shutdown_write()
    out, err = bytearray(), bytearray()
    started = time.time()
    while True:
        got = False
        if chan.recv_ready():
            out += chan.recv(65536)
            got = True
        if chan.recv_stderr_ready():
            err += chan.recv_stderr(65536)
            got = True
        if chan.exit_status_ready() and not got:
            break
        if timeout and time.time() - started > timeout:
            chan.close()
            raise TimeoutError(f"command exceeded {timeout}s")
        if not got:
            time.sleep(0.05)
    while chan.recv_ready():
        out += chan.recv(65536)
    while chan.recv_stderr_ready():
        err += chan.recv_stderr(65536)
    rc = chan.recv_exit_status()
    chan.close()
    return rc, bytes(out), bytes(err), time.time() - started


def handle(path, transport):
    req_id = path.stem
    try:
        req = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        reply(req_id, {"error": f"unreadable request: {exc}"})
        path.rename(path.with_suffix(".json.bad"))
        return

    op = req.get("op", "exec")
    print(f"\n[bridge] {req_id}  op={op}")
    if op == "exec":
        print("--- command ---")
        print(req.get("cmd", ""))
        print("---------------")
    else:
        print(f"    {json.dumps({k: v for k, v in req.items() if k != 'op'})}")

    if CONFIRM:
        if input("[bridge] run this? [y/N] ").strip().lower() not in ("y", "yes"):
            reply(req_id, {"error": "declined by user"})
            path.rename(path.with_suffix(".json.done"))
            return

    body = {"id": req_id, "op": op}
    try:
        if op == "ping":
            body.update(ok=True, host=HOST, user=USER,
                        active=transport.is_active(),
                        sftp="transfer-node" if SFTP is not None else "base64-exec")

        elif op == "exec":
            rc, out, err, wall = run_cmd(
                transport, req["cmd"], req.get("timeout_s", 900))
            full = OUT_DIR / f"{req_id}.stdout.txt"
            full.write_bytes(out)
            body.update(
                exit_code=rc,
                wall_s=round(wall, 2),
                stdout=out[:MAX_INLINE].decode("utf-8", "replace"),
                stderr=err[:MAX_INLINE].decode("utf-8", "replace"),
                stdout_truncated=len(out) > MAX_INLINE,
                stdout_bytes=len(out),
                stdout_file=str(full),
            )

        elif op == "get":           # nano4 -> this machine
            remote = req["remote"]
            local = OUT_DIR / (req.get("local") or os.path.basename(remote))
            local.parent.mkdir(parents=True, exist_ok=True)
            if SFTP is not None:
                SFTP.get(remote, str(local))
                via = "sftp"
            else:
                rc, out, err, _ = run_cmd(
                    transport, "base64 " + shlex.quote(remote),
                    req.get("timeout_s", 900))
                if rc != 0:
                    raise RuntimeError(
                        f"remote base64 failed (rc={rc}): "
                        f"{err.decode('utf-8', 'replace')[:400]}")
                local.write_bytes(base64.b64decode(out))
                via = "base64-exec"
            body.update(ok=True, via=via, local=str(local),
                        size_bytes=local.stat().st_size)

        elif op == "put":           # this machine -> nano4
            src = pathlib.Path(req["local"])
            if not src.is_absolute():
                src = ROOT / src
            remote = req["remote"]
            if SFTP is not None:
                SFTP.put(str(src), remote)
                via = "sftp"
            else:
                q = shlex.quote(remote)
                rc, _out, err, _ = run_cmd(
                    transport,
                    f"mkdir -p \"$(dirname {q})\" && base64 -d > {q}",
                    req.get("timeout_s", 900),
                    stdin_data=base64.b64encode(src.read_bytes()),
                )
                if rc != 0:
                    raise RuntimeError(
                        f"remote write failed (rc={rc}): "
                        f"{err.decode('utf-8', 'replace')[:400]}")
                via = "base64-exec"
            body.update(ok=True, via=via, remote=remote,
                        size_bytes=src.stat().st_size)

        elif op == "transfer_connect":
            got = ensure_transfer(ask=req.get("ask", True))
            body.update(ok=got is not None,
                        sftp="transfer-node" if got is not None else "base64-exec")

        elif op == "listdir":
            if SFTP is not None:
                body.update(ok=True, via="sftp",
                            entries=sorted(SFTP.listdir(req["remote"])))
            else:
                rc, out, err, _ = run_cmd(
                    transport, "ls -1A -- " + shlex.quote(req["remote"]), 120)
                body.update(
                    ok=(rc == 0), via="base64-exec", exit_code=rc,
                    entries=out.decode("utf-8", "replace").split(),
                    stderr=err.decode("utf-8", "replace")[:2000])

        else:
            body.update(error=f"unknown op: {op}")

    except Exception as exc:
        body.update(error=f"{type(exc).__name__}: {exc}",
                    traceback=traceback.format_exc()[-2000:])

    reply(req_id, body)
    path.rename(path.with_suffix(".json.done"))
    print(f"[bridge] {req_id} -> {body.get('exit_code', body.get('error', 'ok'))}")


def reply(req_id, body):
    """Write the reply atomically so a half-written file is never read."""
    tmp = OUT_DIR / f".{req_id}.tmp"
    tmp.write_text(json.dumps(body, indent=1), encoding="utf-8")
    os.replace(tmp, OUT_DIR / f"{req_id}.json")


# --------------------------------------------------------------- main

def main():
    if not HOST or not USER:
        sys.exit("set BRIDGE_HOST and BRIDGE_USER in the environment")
    IN_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    transport = connect(PORT, "login node")
    if "--transfer" in sys.argv:
        ensure_transfer(ask=False)
    print(f"[bridge] watching {IN_DIR}")
    print("[bridge] Ctrl-C to stop\n")
    try:
        while True:
            if not transport.is_active():
                print("[bridge] session dropped -- log in again to resume")
                transport = connect(PORT, "login node")
            for req in sorted(IN_DIR.glob("*.json")):
                handle(req, transport)
            time.sleep(POLL_S)
    except KeyboardInterrupt:
        print("\n[bridge] closing session")
    finally:
        for t in (transport, SFTP_TRANSPORT):
            try:
                if t is not None:
                    t.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
