#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["paramiko>=3.4"]
# ///
"""Local SSH front end for a 2FA-only cluster.

The upstream host accepts only keyboard-interactive 2FA and splits shell and
sftp across two ports.  You log in by hand once; this then serves a plain
single-prompt SSH endpoint that forwards exec to the login node and sftp to the
transfer node, so ordinary SSH tooling can drive the cluster.

    uv run nano4_sshd.py --help

Security: the default bind is 0.0.0.0, because a loopback bind is unreachable
from a client in another network namespace.  The port fronts a live
authenticated session on your account, guarded by your upstream password (or
authorized_key.pub), so keep a host firewall rule limited to the sources you
intend.  See README.md.

Your upstream password and OTP are typed by you and never written to disk.  The
password stays in memory while the bridge runs, to check clients against; the
OTP is kept only for the two logins.
"""
import argparse
import errno
import getpass
import os
import pathlib
import secrets
import re
import socket
import subprocess
import sys
import threading
import time
import traceback

import paramiko
from paramiko import (SFTPAttributes, SFTPHandle, SFTPServer,
                      SFTPServerInterface, SFTP_OK)

ROOT = pathlib.Path(__file__).resolve().parent
HOSTKEY_PATH = ROOT / "local_hostkey"


# Bridge-password files from older versions, removed at startup.
OLD_SECRET_PATHS = (ROOT / "local_password.enc", ROOT / "local_password.txt")
CLUSTER_PW = None          # first hidden answer; clients present it, never stored

# Clients now present a person-chosen password, not a random token, so wrong
# guesses are taken one at a time and each one costs this long.
WRONG_PASSWORD_DELAY = 2.0
_PASSWORD_CHECK = threading.Lock()


def resolve_password(args):
    """What clients must present, and how to describe it to the operator."""
    if args.password:
        return args.password, "the BRIDGE_PASSWORD in bridge.conf"
    if CLUSTER_PW:
        return CLUSTER_PW, "your iService password (the one you just typed)"
    pw = secrets.token_urlsafe(12)
    return pw, f"{pw}   (works only until this window closes)"


def _conf():
    """Machine-local settings from bridge.conf (KEY=VALUE lines, gitignored)."""
    path = ROOT / "bridge.conf"
    out = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                out[key.strip()] = val.strip()
    return out


CONF = _conf()


def setting(name, default=""):
    return os.environ.get(name) or CONF.get(name, default)


def _colour_console():
    """Enable colour escapes when stdout is a console that can show them."""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)          # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING: off by default in a Windows 10 console
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


COLOUR = False
HIGHLIGHT, READY = "1;30;103", "1;92"


def paint(text, sgr):
    return f"\x1b[{sgr}m{text}\x1b[0m" if COLOUR else text


HOST = setting("BRIDGE_HOST", "nano4.nchc.org.tw")
SSH_PORT = int(setting("BRIDGE_PORT", "22"))
SFTP_PORT = int(setting("BRIDGE_SFTP_PORT", "2222"))
USER = setting("BRIDGE_USER")

UP = None                       # upstream Transport -> login node (exec)
UPSFTP = None                   # upstream SFTPClient -> transfer node
UPSFTP_LOCK = threading.Lock()  # SFTPClient is not thread-safe
LOCAL_PASSWORD = None
PASSWORD_HINT = ""              # what LOCAL_PASSWORD is, in words for the operator
AUTHORIZED_KEY = None
HOSTKEY = None


# ----------------------------------------------------------------- upstream

RECORDED = []      # first login's answers, replayed to the second
_REPLAY_AT = 0


def _prompt_handler(title, instructions, prompt_list):
    """Prompt the operator, recording answers for the second login."""
    if title.strip():
        print(title.strip())
    if instructions.strip():
        print(instructions.strip())
    out = []
    for prompt, echo in prompt_list:
        text = prompt.strip() or "response:"
        ans = input(text + " ") if echo else getpass.getpass(text + " ")
        if not echo and CLUSTER_PW is None:
            globals()["CLUSTER_PW"] = ans
        RECORDED.append(ans)
        out.append(ans)
    return out


def _replay_handler(title, instructions, prompt_list):
    """Reuse the first login's answers; one TOTP usually covers both."""
    global _REPLAY_AT
    out = []
    for prompt, echo in prompt_list:
        text = prompt.strip() or "response:"
        if _REPLAY_AT < len(RECORDED):
            out.append(RECORDED[_REPLAY_AT])
            _REPLAY_AT += 1
            print(f"{text} [reusing your answer]")
        else:
            out.append(input(text + " ") if echo else getpass.getpass(text + " "))
    return out


LOGIN_ATTEMPTS = 3
LOGIN_ERRORS = (paramiko.SSHException, OSError, EOFError)


def _authenticate(port, handler):
    """One login attempt: an authenticated transport, or an exception."""
    t = paramiko.Transport((HOST, port))
    try:
        t.start_client(timeout=30)
        # No local limit: the prompts run inside this wait, and paramiko's 30 s
        # default expires while the operator is still reading the phone app.
        # The server's own login grace period still ends an abandoned login.
        t.auth_timeout = None
        t.auth_interactive(USER, handler)
        if not t.is_authenticated():
            raise paramiko.AuthenticationException("login not accepted")
    except BaseException:
        t.close()
        raise
    t.set_keepalive(30)
    return t


def upstream_connect(port, label, replay=False):
    """Authenticate one transport; replay=True reuses recorded answers."""
    global _REPLAY_AT, CLUSTER_PW
    print(f"[sshd] logging in to {label} {USER}@{HOST}:{port}")
    if replay:
        try:
            t = _authenticate(port, _replay_handler)
            print(f"[sshd] {label} authenticated")
            return t
        except LOGIN_ERRORS as exc:
            _REPLAY_AT = 0
            print(f"[sshd] reused answers rejected ({exc}); please type them")
    for attempt in range(1, LOGIN_ATTEMPTS + 1):
        if not replay:
            # A failed attempt's answers must not unlock the password file
            # or be replayed to the transfer node.
            RECORDED.clear()
            _REPLAY_AT = 0
            CLUSTER_PW = None
        try:
            t = _authenticate(port, _prompt_handler)
            print(f"[sshd] {label} authenticated")
            return t
        except LOGIN_ERRORS as exc:
            print(f"\n[sshd] login to {label} did not succeed ({exc})")
            if attempt < LOGIN_ATTEMPTS:
                print("[sshd] check your password, wait for a NEW code in your"
                      f" phone app, and try again (attempt {attempt + 1} of"
                      f" {LOGIN_ATTEMPTS})")
    raise SystemExit(f"[sshd] could not log in to {label} after"
                     f" {LOGIN_ATTEMPTS} attempts")


# ----------------------------------------------------------------- exec proxy

def _pump(local, up):
    """Shuttle bytes between the local channel and the upstream channel."""
    stdin_done = False
    while True:
        moved = False
        try:
            if up.recv_ready():
                data = up.recv(65536)
                if data:
                    local.sendall(data)
                    moved = True
            if up.recv_stderr_ready():
                data = up.recv_stderr(65536)
                if data:
                    local.sendall_stderr(data)
                    moved = True
            if not stdin_done and local.recv_ready():
                data = local.recv(65536)
                if data:
                    up.sendall(data)
                    moved = True
                else:
                    up.shutdown_write()
                    stdin_done = True
        except (OSError, EOFError, paramiko.SSHException):
            break
        if (up.exit_status_ready() and not up.recv_ready()
                and not up.recv_stderr_ready()):
            break
        if not moved:
            time.sleep(0.02)
    try:
        return up.recv_exit_status()
    except Exception:
        return 255


def proxy_exec(chan, command):
    if isinstance(command, bytes):
        command = command.decode("utf-8", "replace")
    head = command.replace("\n", " ")[:160]
    print(f"[sshd] exec: {head}{'...' if len(command) > 160 else ''}")
    rc = 255
    try:
        up = UP.open_session(timeout=30)
        up.exec_command(command)
        rc = _pump(chan, up)
        up.close()
    except Exception as exc:
        traceback.print_exc()
        try:
            chan.sendall_stderr(f"local bridge error: {exc}\n".encode())
        except Exception:
            pass
    finally:
        try:
            chan.send_exit_status(rc)
        except Exception:
            pass
        try:
            chan.close()
        except Exception:
            pass


def proxy_shell(chan):
    print("[sshd] shell session")
    try:
        up = UP.open_session(timeout=30)
        up.get_pty()
        up.invoke_shell()
        _pump(chan, up)
        up.close()
    except Exception:
        traceback.print_exc()
    finally:
        try:
            chan.close()
        except Exception:
            pass


# ----------------------------------------------------------------- sftp proxy

def _sftp_err(exc):
    return SFTPServer.convert_errno(getattr(exc, "errno", None) or errno.EIO)


def _flags_to_mode(flags):
    if flags & os.O_WRONLY:
        mode = "a" if flags & os.O_APPEND else "w"
    elif flags & os.O_RDWR:
        mode = "a+" if flags & os.O_APPEND else "r+"
    else:
        mode = "r"
    return mode + "b"


class ProxyHandle(SFTPHandle):
    def __init__(self, remote_file, flags=0):
        super().__init__(flags)
        self.readfile = remote_file
        self.writefile = remote_file
        self._f = remote_file

    def stat(self):
        try:
            with UPSFTP_LOCK:
                return SFTPAttributes.from_stat(self._f.stat())
        except Exception as exc:
            return _sftp_err(exc)

    def chattr(self, attr):
        return SFTP_OK


class ProxySFTP(SFTPServerInterface):
    """Forward every sftp operation to nano4's transfer node."""

    def list_folder(self, path):
        try:
            with UPSFTP_LOCK:
                return UPSFTP.listdir_attr(path)
        except Exception as exc:
            return _sftp_err(exc)

    def stat(self, path):
        try:
            with UPSFTP_LOCK:
                return UPSFTP.stat(path)
        except Exception as exc:
            return _sftp_err(exc)

    def lstat(self, path):
        try:
            with UPSFTP_LOCK:
                return UPSFTP.lstat(path)
        except Exception as exc:
            return _sftp_err(exc)

    def open(self, path, flags, attr):
        try:
            with UPSFTP_LOCK:
                f = UPSFTP.open(path, _flags_to_mode(flags))
            f.set_pipelined(True)
            return ProxyHandle(f, flags)
        except Exception as exc:
            return _sftp_err(exc)

    def remove(self, path):
        try:
            with UPSFTP_LOCK:
                UPSFTP.remove(path)
            return SFTP_OK
        except Exception as exc:
            return _sftp_err(exc)

    def rename(self, oldpath, newpath):
        try:
            with UPSFTP_LOCK:
                UPSFTP.rename(oldpath, newpath)
            return SFTP_OK
        except Exception as exc:
            return _sftp_err(exc)

    def mkdir(self, path, attr):
        try:
            with UPSFTP_LOCK:
                UPSFTP.mkdir(path)
            return SFTP_OK
        except Exception as exc:
            return _sftp_err(exc)

    def rmdir(self, path):
        try:
            with UPSFTP_LOCK:
                UPSFTP.rmdir(path)
            return SFTP_OK
        except Exception as exc:
            return _sftp_err(exc)

    def chattr(self, path, attr):
        try:
            if getattr(attr, "st_mode", None) is not None:
                with UPSFTP_LOCK:
                    UPSFTP.chmod(path, attr.st_mode & 0o7777)
            return SFTP_OK
        except Exception as exc:
            return _sftp_err(exc)

    def symlink(self, target_path, path):
        try:
            with UPSFTP_LOCK:
                UPSFTP.symlink(target_path, path)
            return SFTP_OK
        except Exception as exc:
            return _sftp_err(exc)

    def readlink(self, path):
        try:
            with UPSFTP_LOCK:
                return UPSFTP.readlink(path)
        except Exception as exc:
            return _sftp_err(exc)

    def canonicalize(self, path):
        try:
            with UPSFTP_LOCK:
                return UPSFTP.normalize(path)
        except Exception:
            return path if path.startswith("/") else "/" + path


# ----------------------------------------------------------------- local sshd

class LocalServer(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "publickey,password" if AUTHORIZED_KEY else "password"

    def check_auth_password(self, username, password):
        with _PASSWORD_CHECK:
            # bytes: compare_digest refuses str with non-ASCII characters
            if LOCAL_PASSWORD and secrets.compare_digest(
                    password.encode("utf-8"), LOCAL_PASSWORD.encode("utf-8")):
                print(f"[sshd] client authenticated (password) as {username!r}")
                return paramiko.AUTH_SUCCESSFUL
            print("[sshd] client rejected: wrong password -- it must be "
                  + PASSWORD_HINT)
            time.sleep(WRONG_PASSWORD_DELAY)
            return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if AUTHORIZED_KEY and key.asbytes() == AUTHORIZED_KEY.asbytes():
            print(f"[sshd] client authenticated (publickey) as {username!r}")
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_env_request(self, channel, name, value):
        return True

    def check_channel_exec_request(self, channel, command):
        threading.Thread(target=proxy_exec, args=(channel, command),
                         daemon=True).start()
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=proxy_shell, args=(channel,), daemon=True).start()
        return True


def handle_client(sock, addr):
    t = paramiko.Transport(sock)
    t.add_server_key(HOSTKEY)
    if UPSFTP is not None:
        t.set_subsystem_handler("sftp", SFTPServer, ProxySFTP)
    try:
        t.start_server(server=LocalServer())
        while t.is_active():
            chan = t.accept(30)
            if chan is None:
                continue
    except Exception:
        pass
    finally:
        try:
            t.close()
        except Exception:
            pass


def heartbeat(interval):
    """Keep both upstream sessions warm; protocol keepalives alone do not
    always prevent idle reaping.  Cannot reconnect by itself -- that needs a
    fresh OTP, so it points the operator at relogin()."""
    while True:
        time.sleep(interval)
        if RELOGGING.is_set():
            continue
        stamp = time.strftime("%H:%M:%S")
        exec_ok = False
        try:
            ch = UP.open_session(timeout=20)
            ch.exec_command("true")
            ch.recv_exit_status()
            ch.close()
            exec_ok = True
        except Exception as exc:
            print(f"[sshd] {stamp} login node heartbeat failed: {exc}")
        sftp_ok = None
        if UPSFTP is not None:
            try:
                with UPSFTP_LOCK:
                    UPSFTP.stat(".")
                sftp_ok = True
            except Exception as exc:
                sftp_ok = False
                print(f"[sshd] {stamp} transfer node heartbeat failed: {exc}")
        if RELOGGING.is_set():
            continue          # the sessions were swapped mid-check
        if exec_ok and sftp_ok is not False:
            extra = " + sftp" if sftp_ok else ""
            print(f"[sshd] {stamp} alive (login node{extra})")
        else:
            print(f"[sshd] {stamp} !! UPSTREAM LOST -- {RELOGIN_KEYS} to log"
                  " in again, with a new code from your phone app")


# ----------------------------------------------------------------- re-login

RELOGGING = threading.Event()   # set while the operator types; heartbeat waits
RELOGIN_KEYS = "press R" if os.name == "nt" else "type r and press Enter"


def _wait_for_key():
    """Block until the operator asks to log in again; False once stdin closes."""
    if os.name == "nt":
        import msvcrt
        while True:
            # Poll: a blocking getwch puts the console in raw mode and would
            # read Ctrl-C as an ordinary character instead of stopping.
            while not msvcrt.kbhit():
                time.sleep(0.1)
            if msvcrt.getwch().lower() == "r":
                return True
    while True:
        line = sys.stdin.readline()
        if not line:
            return False
        if line.strip().lower() == "r":
            return True


def _close_quietly(transport):
    try:
        transport.close()
    except Exception:
        pass


def relogin(args):
    """Replace both upstream sessions in place; the listener never stops."""
    global UP, UPSFTP, LOCAL_PASSWORD, PASSWORD_HINT
    RELOGGING.set()
    try:
        print("\n[sshd] logging in to nano4 again:  1) type 1   2) your"
              " iService password   3) a NEW code from your phone app")
        try:
            up = upstream_connect(SSH_PORT, "login node")
        except (Exception, SystemExit) as exc:
            print(exc)
            print(f"[sshd] still disconnected -- {RELOGIN_KEYS} to try again")
            return
        old, UP = UP, up
        _close_quietly(old)
        before = LOCAL_PASSWORD
        LOCAL_PASSWORD, PASSWORD_HINT = resolve_password(args)
        if LOCAL_PASSWORD != before:
            print("[sshd] client password is now " + paint(PASSWORD_HINT, HIGHLIGHT))

        if not args.no_transfer:
            try:
                up2 = upstream_connect(SFTP_PORT, "transfer node", replay=True)
                sftp = paramiko.SFTPClient.from_transport(up2)
                print("[sshd] sftp proxy enabled")
            except (Exception, SystemExit) as exc:
                sftp = None
                print(f"[sshd] transfer node unavailable ({exc}) -- sftp disabled")
            with UPSFTP_LOCK:
                old, UPSFTP = UPSFTP, sftp
            if old is not None:
                _close_quietly(old.get_channel().get_transport())

        files = "" if UPSFTP or args.no_transfer else " (files are OFF)"
        print("[sshd] " + paint("RECONNECTED", READY)
              + f" - nano4 is connected again{files}. Leave this window open.")
    finally:
        RELOGGING.clear()


def watch_keys(args):
    while _wait_for_key():
        relogin(args)


VIRTUAL_HINTS = ("vethernet", "vmware", "virtualbox", "hyper-v", "loopback",
                 "wsl", "tap-", "default switch", "vmnet")


def _routed_address():
    """The address used to reach the outside world -- i.e. the one that moves
    when the machine joins a different network. No packets are sent."""
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("192.0.2.1", 1))
        addr = probe.getsockname()[0]
        probe.close()
        return addr
    except Exception:
        return None


def _windows_interfaces():
    """{address: adapter description} from ipconfig. 'IPv4' is locale-invariant."""
    found = {}
    try:
        out = subprocess.run(["ipconfig"], capture_output=True,
                             timeout=10).stdout.decode("utf-8", "replace")
    except Exception:
        return found
    adapter = ""
    for line in out.splitlines():
        if line.strip() and not line[0].isspace():
            adapter = line.strip().rstrip(":")
        elif "IPv4" in line:
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            if m:
                found[m.group(1)] = adapter
    return found


def address_candidates():
    """[(address, kind, advice)] best first.

    'kind' is virtual / current-network / other. Virtual adapters keep the same
    address on every network, so they are what a client should be pointed at.
    """
    routed = _routed_address()
    seen = dict(_windows_interfaces()) if os.name == "nt" else {}
    try:
        for a in socket.gethostbyname_ex(socket.gethostname())[2]:
            seen.setdefault(a, "")
    except Exception:
        pass
    if routed:
        seen.setdefault(routed, "")

    out = []
    for addr, adapter in seen.items():
        if addr.startswith(("127.", "169.254.")):
            continue
        low = adapter.lower()
        if any(h in low for h in VIRTUAL_HINTS):
            out.append((addr, "virtual", "same address on every network"))
        elif addr == routed:
            out.append((addr, "current-network",
                        "CHANGES when this machine joins another network"))
        else:
            out.append((addr, "other", "may change"))
    rank = {"virtual": 0, "other": 1, "current-network": 2}
    out.sort(key=lambda row: (rank[row[1]], row[0]))
    return out


def print_address_advice(expected):
    """Tell the operator exactly which address to give the client."""
    cands = address_candidates()
    if not cands:
        print("  no usable network address found on this machine")
        return
    best = cands[0][0]
    if expected and expected in [c[0] for c in cands]:
        print(f"  address for your client: {expected}  (already set, still valid)")
        return
    print("  address to give your SSH client / compute target:")
    print(f"     {best}   <-- USE THIS")
    for addr, _kind, advice in cands[1:]:
        print(f"     {addr}       {advice}")
    if expected:
        print(f"  NOTE: BRIDGE_EXPECT={expected} is not on this machine any more;"
              f" use {best} instead")
    else:
        print(f"  save it so this check runs next time:  BRIDGE_EXPECT={best}")


def load_hostkey():
    if HOSTKEY_PATH.exists():
        return paramiko.RSAKey(filename=str(HOSTKEY_PATH))
    print("[sshd] generating local host key (first run)")
    k = paramiko.RSAKey.generate(3072)
    k.write_private_key_file(str(HOSTKEY_PATH))
    return k


def print_ready(args):
    """The banner the operator reads to set up their client."""
    cands = [c[0] for c in address_candidates()]
    host = args.expect if args.expect in cands else (cands[0] if cands else args.bind)
    print("\n" + "=" * 68)
    print("  " + paint("READY", READY) + " - nano4 is connected. Leave this window open.")
    print("=" * 68)
    print("  When Claude for Science asks for a password, use")
    print("     " + paint(PASSWORD_HINT, HIGHLIGHT))
    print("-" * 68)
    print("  Connection details (Customize -> Compute, host nano4-bridge):")
    print(f"     Host      {host}")
    print(f"     Port      {args.port}")
    print(f"     User      {USER}   (any username is accepted)")
    print(f"     Files     {'on (via transfer node)' if UPSFTP else 'OFF - sending and fetching files will fail'}")
    if host != args.expect:
        print("-" * 68)
        print_address_advice(args.expect)
    print("-" * 68)
    print(f"  test it:  ssh -p {args.port} {USER}@{host} hostname")
    hb = f"every {args.heartbeat}s" if args.heartbeat > 0 else "disabled"
    print(f"  keep-alive heartbeat: {hb} -- safe to leave unattended")
    print(f"  if nano4 disconnects, {RELOGIN_KEYS} to log in again")
    print("  Ctrl-C to close both nano4 sessions\n")


def main():
    global UP, UPSFTP, HOSTKEY, LOCAL_PASSWORD, PASSWORD_HINT, AUTHORIZED_KEY, COLOUR

    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=2200, help="local listen port")
    ap.add_argument("--bind", default="0.0.0.0",
                    help="local bind address (default: all interfaces -- "
                         "a loopback bind is unreachable from the client)")
    ap.add_argument("--password", default=setting("BRIDGE_PASSWORD") or None,
                    help="fixed client password instead of your iService password")
    ap.add_argument("--authorized-key", default=str(ROOT / "authorized_key.pub"))
    ap.add_argument("--expect", default=setting("BRIDGE_EXPECT"),
                    help="address the client dials; warn if absent ('' to skip)")
    ap.add_argument("--heartbeat", type=int, default=240,
                    help="seconds between upstream keep-warm pokes (0 disables)")
    ap.add_argument("--show-address", action="store_true",
                    help="print the recommended address and exit (no login)")
    ap.add_argument("--host-key", action="store_true",
                    help="print the public host key clients should pin, creating"
                         " it if needed, and exit (no login)")
    ap.add_argument("--no-transfer", action="store_true",
                    help="skip the port-2222 login (no sftp, exec only)")
    args = ap.parse_args()

    if args.show_address:
        cands = address_candidates()
        if not cands:
            sys.exit("no usable network address found on this machine")
        print(cands[0][0])
        return

    if args.host_key:
        key = load_hostkey()
        print(f"{key.get_name()} {key.get_base64()}")
        return

    if not USER:
        sys.exit("set BRIDGE_USER (your iService account) in bridge.conf"
                 " or the environment")
    COLOUR = _colour_console()

    keypath = pathlib.Path(args.authorized_key)
    if keypath.exists():
        blob = keypath.read_text().split()
        if len(blob) >= 2:
            import base64 as _b64
            AUTHORIZED_KEY = paramiko.PKey.from_type_string(
                blob[0], _b64.b64decode(blob[1]))
            print(f"[sshd] authorized key loaded from {keypath}")

    HOSTKEY = load_hostkey()

    UP = upstream_connect(SSH_PORT, "login node")
    LOCAL_PASSWORD, PASSWORD_HINT = resolve_password(args)
    for old in OLD_SECRET_PATHS:
        try:
            old.unlink()
            print(f"[sshd] removed {old.name} -- clients now use your iService password")
        except FileNotFoundError:
            pass
        except OSError as exc:
            print(f"[sshd] could not remove {old.name} ({exc}) -- delete it by hand")
    if not args.no_transfer:
        try:
            up2 = upstream_connect(SFTP_PORT, "transfer node", replay=True)
            UPSFTP = paramiko.SFTPClient.from_transport(up2)
            print("[sshd] sftp proxy enabled")
        except (Exception, SystemExit) as exc:
            print(f"[sshd] transfer node unavailable ({exc}) -- sftp disabled")

    if args.heartbeat > 0:
        threading.Thread(target=heartbeat, args=(args.heartbeat,),
                         daemon=True).start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(16)
    # A blocking accept() on Windows ignores Ctrl-C until a client connects.
    srv.settimeout(1.0)

    print_ready(args)
    threading.Thread(target=watch_keys, args=(args,), daemon=True).start()

    try:
        while True:
            try:
                sock, addr = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle_client, args=(sock, addr),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\n[sshd] shutting down")
    finally:
        for t in (UP, getattr(UPSFTP, "sock", None)):
            try:
                t.close()
            except Exception:
                pass
        srv.close()


if __name__ == "__main__":
    main()
