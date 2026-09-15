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
authenticated session on your account, guarded only by the generated password
in local_password.enc (or authorized_key.pub), so keep a host firewall rule
limited to the sources you intend.  See README.md.

Your upstream password and OTP are typed by you, kept in memory for the two
logins only, and never written to disk.
"""
import argparse
import errno
import getpass
import hashlib
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


SECRET_PATH = ROOT / "local_password.enc"
LEGACY_PATH = ROOT / "local_password.txt"
_AAD = b"ssh-2fa-bridge/v1"
_DPAPI_ENTROPY = b"ssh-2fa-bridge/local-password"
CLUSTER_PW = None          # first hidden answer; unlocks SECRET_PATH, never stored


def _dpapi(data, protect=True):
    """Wrap/unwrap with the Windows user account key (CryptProtectData)."""
    import ctypes
    import ctypes.wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    def mk(raw):
        buf = ctypes.create_string_buffer(raw, len(raw))
        return BLOB(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    src, _a = mk(data)
    ent, _b = mk(_DPAPI_ENTROPY)
    out = BLOB()
    fn = (ctypes.windll.crypt32.CryptProtectData if protect
          else ctypes.windll.crypt32.CryptUnprotectData)
    if not fn(ctypes.byref(src), None, ctypes.byref(ent), None, None, 0,
              ctypes.byref(out)):
        raise OSError(ctypes.GetLastError(), "DPAPI call failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def _key(cluster_pw, salt):
    # scrypt: deliberately slow, so a stolen file is a poor dictionary target
    # maxmem must be raised explicitly: OpenSSL defaults to a 32 MB cap,
    # and n=2**15, r=8 needs 128*n*r = 32 MB exactly.
    return hashlib.scrypt(cluster_pw.encode("utf-8"), salt=salt,
                          n=2 ** 15, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024)


def seal(bridge_pw, cluster_pw):
    """Encrypt the bridge password under the cluster password, then wrap in DPAPI."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    body = (b"B1" + salt + nonce
            + AESGCM(_key(cluster_pw, salt)).encrypt(nonce,
                                                     bridge_pw.encode("utf-8"), _AAD))
    if os.name == "nt":
        try:
            return b"D1" + _dpapi(body, protect=True)
        except OSError:
            pass
    return body


def unseal(data, cluster_pw):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if data[:2] == b"D1":
        data = _dpapi(data[2:], protect=False)
    if data[:2] != b"B1":
        raise ValueError("unrecognised password file")
    salt, nonce, ct = data[2:18], data[18:30], data[30:]
    return AESGCM(_key(cluster_pw, salt)).decrypt(nonce, ct, _AAD).decode("utf-8")


def resolve_password(args):
    """The client-facing password: decrypted if possible, else freshly sealed."""
    if args.password:
        return args.password, "--password"
    if not CLUSTER_PW:
        return secrets.token_urlsafe(12), "session only -- no key material captured"
    if SECRET_PATH.exists() and not args.new_password:
        try:
            return unseal(SECRET_PATH.read_bytes(), CLUSTER_PW), \
                   f"decrypted from {SECRET_PATH.name}"
        except Exception as exc:
            print(f"[sshd] {SECRET_PATH.name} could not be decrypted ({type(exc).__name__});"
                  " generating a new password -- update it in your client")
    pw = secrets.token_urlsafe(12)
    SECRET_PATH.write_bytes(seal(pw, CLUSTER_PW))
    try:
        os.chmod(SECRET_PATH, 0o600)
    except OSError:
        pass
    return pw, f"new, encrypted to {SECRET_PATH.name}"


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


HOST = setting("BRIDGE_HOST", "nano4.nchc.org.tw")
SSH_PORT = int(setting("BRIDGE_PORT", "22"))
SFTP_PORT = int(setting("BRIDGE_SFTP_PORT", "2222"))
USER = setting("BRIDGE_USER")

UP = None                       # upstream Transport -> login node (exec)
UPSFTP = None                   # upstream SFTPClient -> transfer node
UPSFTP_LOCK = threading.Lock()  # SFTPClient is not thread-safe
LOCAL_PASSWORD = None
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
        if LOCAL_PASSWORD and secrets.compare_digest(password, LOCAL_PASSWORD):
            print(f"[sshd] client authenticated (password) as {username!r}")
            return paramiko.AUTH_SUCCESSFUL
        print("[sshd] client rejected: wrong password")
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
    always prevent idle reaping.  Cannot reconnect -- that needs a fresh OTP."""
    while True:
        time.sleep(interval)
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
        if exec_ok and sftp_ok is not False:
            extra = " + sftp" if sftp_ok else ""
            print(f"[sshd] {stamp} alive (login node{extra})")
        else:
            print(f"[sshd] {stamp} !! UPSTREAM LOST -- Ctrl-C and restart, "
                  "you will need fresh OTPs")


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


def main():
    global UP, UPSFTP, HOSTKEY, LOCAL_PASSWORD, AUTHORIZED_KEY

    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=2200, help="local listen port")
    ap.add_argument("--bind", default="0.0.0.0",
                    help="local bind address (default: all interfaces -- "
                         "a loopback bind is unreachable from the client)")
    ap.add_argument("--password", default=setting("BRIDGE_PASSWORD") or None,
                    help="fixed password; default reuses the saved one")
    ap.add_argument("--new-password", action="store_true",
                    help="rotate the saved password")
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
    LOCAL_PASSWORD, pw_source = resolve_password(args)
    if LEGACY_PATH.exists():
        print(f"[sshd] {LEGACY_PATH.name} holds a plaintext password from an older"
              " version -- delete it")
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

    print("\n" + "=" * 68)
    print("  nano4 is now reachable as an ordinary SSH host:")
    print(f"     Host      {args.bind}")
    print(f"     Port      {args.port}")
    print(f"     User      {USER}   (any username is accepted)")
    print(f"     Password  {LOCAL_PASSWORD}   [{pw_source}]")
    print(f"     sftp      {'enabled (via transfer node)' if UPSFTP else 'DISABLED'}")
    print("-" * 68)
    print_address_advice(args.expect)
    print("=" * 68)
    print("  test it:  ssh -p %d %s@%s hostname" % (args.port, USER, args.bind))
    hb = f"every {args.heartbeat}s" if args.heartbeat > 0 else "disabled"
    print(f"  keep-alive heartbeat: {hb} -- safe to leave unattended")
    print("  Ctrl-C to close both nano4 sessions\n")

    try:
        while True:
            sock, addr = srv.accept()
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
