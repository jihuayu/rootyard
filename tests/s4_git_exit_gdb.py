"""GDB Python observer loaded by tests/s4_git_exit_debugger.py.

This file runs only inside a batch GDB process. It resolves one breakpoint at the
unsuccessful-child-exit return in ``run_git_bounded``, walks a bounded DWARF
frame prefix, keeps only physical repo-relative source locators, and writes the
bounded result grammar to a private file. It never prints target arguments,
locals, memory strings, stdout, stderr or a raw stack, and it never attaches to
an existing process or calls target code.
"""
import gdb
import os

_ENV_KEYS = (
    "S4_GIT_REPO_ROOT",
    "S4_GIT_RESULT_PATH",
    "S4_GIT_NONCE",
    "S4_GIT_BREAK_FILE",
    "S4_GIT_BREAK_LINE",
    "S4_GIT_MAX_FRAMES",
)

_SETTINGS = {key: os.environ.get(key, "") for key in _ENV_KEYS}
for _key in _ENV_KEYS:
    try:
        gdb.execute("unset environment " + _key, to_string=True)
    except gdb.error:
        pass

_REPO_ROOT = _SETTINGS["S4_GIT_REPO_ROOT"]
_RESULT_PATH = _SETTINGS["S4_GIT_RESULT_PATH"]
_NONCE = _SETTINGS["S4_GIT_NONCE"]
_BREAK_FILE = _SETTINGS["S4_GIT_BREAK_FILE"]
try:
    _BREAK_LINE = int(_SETTINGS["S4_GIT_BREAK_LINE"], 10)
except ValueError:
    _BREAK_LINE = 0
try:
    _MAX_FRAMES = int(_SETTINGS["S4_GIT_MAX_FRAMES"], 10)
except ValueError:
    _MAX_FRAMES = 12

_FRAMES = []
_FAILURE = False
_WRITTEN = False


def _write(lines):
    global _WRITTEN
    if _WRITTEN:
        return
    _WRITTEN = True
    fd = os.open(_RESULT_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def _header():
    return ["s4git-result 1 " + _NONCE]


def _repo_relative(full_name):
    if not full_name:
        return None
    try:
        root = os.path.realpath(_REPO_ROOT)
        full = os.path.realpath(full_name)
        if full != root and not full.startswith(root + os.sep):
            return None
        relative = os.path.relpath(full, root)
    except (OSError, ValueError):
        return None
    if not relative or relative == "." or relative == ".git" or relative.startswith(".git" + os.sep):
        return None
    if os.path.isabs(relative) or ".." in relative.split(os.sep):
        return None
    return relative


def _setup_error():
    try:
        _write(_header() + ["error setup_error"])
    except OSError:
        pass
    gdb.execute("quit 4")


class _FailureObserver(gdb.Breakpoint):
    def __init__(self, spec):
        super().__init__(spec, internal=True)
        self.silent = True

    def stop(self):
        global _FAILURE
        _FAILURE = True
        _FRAMES.clear()
        frame = gdb.newest_frame()
        seen = 0
        while frame is not None and seen < _MAX_FRAMES:
            sal = frame.find_sal()
            if sal is not None and sal.symtab is not None and sal.line and sal.line > 0:
                relative = _repo_relative(sal.symtab.fullname())
                if relative:
                    _FRAMES.append((relative, int(sal.line)))
            frame = frame.older()
            seen += 1
        self.enabled = False
        return False


def _on_exit(event):
    try:
        code = getattr(event, "exit_code", -1)
        signal_number = getattr(event, "exit_signal", 0)
        if not isinstance(code, int):
            code = -1
        if not isinstance(signal_number, int):
            signal_number = 0
        lines = _header() + [
            "breakpoint resolved " + _BREAK_FILE + " " + str(_BREAK_LINE),
            "failure " + ("1" if _FAILURE else "0"),
        ]
        if _FAILURE:
            for relative, line in _FRAMES:
                lines.append("frame " + relative + " " + str(line))
        lines.append("exit " + str(code))
        lines.append("signal " + str(signal_number))
        _write(lines)
    except OSError:
        pass


def _install():
    if not _REPO_ROOT or not _RESULT_PATH or not _NONCE or not _BREAK_FILE or _BREAK_LINE < 1:
        _setup_error()
        return
    gdb.execute("set pagination off", to_string=True)
    gdb.execute("set confirm off", to_string=True)
    gdb.execute("set breakpoint pending off", to_string=True)
    gdb.execute("set print frame-arguments none", to_string=True)
    gdb.execute("set follow-fork-mode parent", to_string=True)
    gdb.execute("set detach-on-fork on", to_string=True)
    for signal_name in ("SIGPIPE", "SIGCHLD", "SIGABRT", "SIGSEGV"):
        try:
            gdb.execute("handle " + signal_name + " nostop noprint pass", to_string=True)
        except gdb.error:
            pass
    spec = _REPO_ROOT + os.sep + _BREAK_FILE + ":" + str(_BREAK_LINE)
    try:
        observer = _FailureObserver(spec)
    except gdb.error:
        _write(_header() + [
            "breakpoint unresolved " + _BREAK_FILE + " " + str(_BREAK_LINE),
            "error breakpoint_unresolved",
        ])
        gdb.execute("quit 3")
        return
    if not observer.is_valid():
        _write(_header() + [
            "breakpoint unresolved " + _BREAK_FILE + " " + str(_BREAK_LINE),
            "error breakpoint_unresolved",
        ])
        gdb.execute("quit 3")
        return
    gdb.events.exited.connect(_on_exit)
    gdb.execute("run")


try:
    _install()
except Exception:
    _setup_error()
