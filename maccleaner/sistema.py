"""Consultas de solo lectura al sistema: prioridad baja, ficheros abiertos, disco y snapshots."""
from __future__ import annotations

import bisect
import ctypes
import ctypes.util
import os
import shutil
import subprocess

IOPOL_TYPE_DISK = 0
IOPOL_SCOPE_PROCESS = 0
IOPOL_THROTTLE = 3


def bajar_prioridad() -> list[str]:
    """nice +10 y política de E/S «throttle» para este proceso. No requiere privilegios."""
    hecho = []
    try:
        os.nice(10)
        hecho.append("nice+10")
    except OSError:
        pass
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        if libc.setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_PROCESS, IOPOL_THROTTLE) == 0:
            hecho.append("io-throttle")
    except (OSError, AttributeError):
        pass
    return hecho


def ejecutar(argv: list[str], timeout: int = 30, env_extra: dict | None = None) -> tuple[int, str, str]:
    """Ejecuta un comando de consulta (lista blanca en quien llama). Nunca usa shell."""
    env = dict(os.environ)
    env.update(env_extra or {})
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, "", str(exc)


class FicherosAbiertos:
    """Instantánea única de los ficheros abiertos por el usuario (lsof -u <uid>)."""

    def __init__(self, rutas: list[str] | None = None, disponible: bool = False, error: str | None = None):
        self._rutas = sorted(set(rutas or []))
        self.disponible = disponible
        self.error = error

    @classmethod
    def capturar(cls, timeout: int = 60) -> "FicherosAbiertos":
        lsof = shutil.which("lsof") or "/usr/sbin/lsof"
        rc, out, err = ejecutar([lsof, "-n", "-P", "-w", "-Fn", "-u", str(os.getuid())], timeout=timeout)
        if rc not in (0, 1) or not out:
            return cls(disponible=False, error=(err or f"lsof rc={rc}").strip()[:300])
        rutas = [l[1:] for l in out.splitlines() if l.startswith("n/")]
        return cls(rutas, disponible=True)

    def __len__(self) -> int:
        return len(self._rutas)

    def abierto(self, ruta: str) -> bool:
        i = bisect.bisect_left(self._rutas, ruta)
        return i < len(self._rutas) and self._rutas[i] == ruta

    def contar_bajo(self, directorio: str) -> int:
        pref = directorio.rstrip("/") + "/"
        i = j = bisect.bisect_left(self._rutas, pref)
        while j < len(self._rutas) and self._rutas[j].startswith(pref):
            j += 1
        return j - i

    def alguno_bajo(self, directorio: str) -> bool:
        pref = directorio.rstrip("/") + "/"
        i = bisect.bisect_left(self._rutas, pref)
        return (i < len(self._rutas) and self._rutas[i].startswith(pref)) or self.abierto(directorio)


def disco(ruta: str = "/System/Volumes/Data") -> dict:
    try:
        st = os.statvfs(ruta)
    except OSError:
        st = os.statvfs("/")
        ruta = "/"
    total = st.f_blocks * st.f_frsize
    libre = st.f_bavail * st.f_frsize
    return {"volumen": ruta, "total": total, "libre": libre, "usado": total - libre}


def snapshots_locales() -> dict:
    """tmutil listlocalsnapshots / es una consulta de solo lectura."""
    rc, out, err = ejecutar(["/usr/bin/tmutil", "listlocalsnapshots", "/"], timeout=30)
    if rc != 0:
        return {"disponible": False, "error": (err or out).strip()[:300], "snapshots": []}
    snaps = [l.strip() for l in out.splitlines() if l.strip().startswith("com.apple.")]
    return {"disponible": True, "snapshots": snaps}
