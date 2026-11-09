# Undo the simulated compromise: kill whatever runs /tmp/.cache.py inside this container (slim image has no pkill).
import os, signal

for p in os.listdir("/proc"):
    if p.isdigit():
        try:
            if b".cache.py" in open(f"/proc/{p}/cmdline", "rb").read():
                os.kill(int(p), signal.SIGKILL)
                print("killed", p)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
