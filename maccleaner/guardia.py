"""Guardia de solo lectura en tiempo de ejecución (audit hooks de Python, PEP 578).

Una vez activada no se puede desactivar dentro del proceso. Bloquea, lanzando PermissionError:
  * cualquier apertura en modo escritura fuera del directorio de resultados;
  * remove/rename/rmdir/chmod/chown/utime/truncate/link/symlink/mkdir/xattr fuera de ese directorio;
  * cualquier subproceso cuyo ejecutable no esté en la lista blanca.
"""
from __future__ import annotations

import fcntl
import os
import sys

_ESCRITURA = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
_EVENTOS_RUTA = {
    "os.remove", "os.rmdir", "os.rename", "os.replace", "os.chmod", "os.lchmod", "os.chown", "os.lchown",
    "os.utime", "os.truncate", "os.link", "os.symlink", "os.mkdir", "os.chflags", "os.lchflags",
    "os.setxattr", "os.removexattr", "shutil.rmtree", "shutil.move", "shutil.copyfile", "shutil.copytree",
}
# Posición del argumento dir_fd en los eventos de auditoría que lo admiten (os.remove(path, dir_fd), etc.).
_POS_DIR_FD = {"os.remove": (1,), "os.rmdir": (1,), "os.mkdir": (2,), "os.chmod": (2,), "os.chown": (3,),
               "os.utime": (3,), "os.rename": (2, 3), "os.replace": (2, 3), "os.link": (2, 3), "os.symlink": (None, 2)}
EJECUTABLES_PERMITIDOS = {"lsof", "tmutil", "brew", "pip3", "pip"}

registro: list[str] = []
_activa = False


def _ruta_de_fd(fd: int) -> str:
    """Ruta actual de un descriptor de directorio (fcntl F_GETPATH de macOS)."""
    return os.fsdecode(fcntl.fcntl(fd, fcntl.F_GETPATH, bytes(1024)).split(b"\0", 1)[0])


def _bajo(ruta, base: str, dir_fd=None) -> bool:
    if isinstance(ruta, int):          # descriptor ya abierto: no es una ruta nueva
        return True
    try:
        r = os.fsdecode(ruta)
        if not os.path.isabs(r):
            # Relativa a un descriptor (openat/unlinkat…): se resuelve contra la ruta REAL de ese
            # descriptor, no contra el directorio de trabajo.
            r = os.path.join(_ruta_de_fd(dir_fd) if isinstance(dir_fd, int) and dir_fd >= 0 else os.getcwd(), r)
        r = os.path.realpath(r)
    except (TypeError, ValueError, OSError):
        return False
    return r == base or r.startswith(base + "/")


def activar(directorio_permitido: str) -> None:
    global _activa
    if _activa:
        return
    base = os.path.realpath(directorio_permitido)

    def hook(evento: str, args: tuple) -> None:
        if evento == "open":
            ruta, modo, flags = (list(args) + [None, None, None])[:3]
            escribe = (isinstance(modo, str) and any(c in modo for c in "wax+")) or \
                      (isinstance(flags, int) and flags & _ESCRITURA)
            # /dev/null: subprocess lo abre en O_RDWR para stdin=DEVNULL; no es un fichero del usuario.
            if escribe and ruta is not None and ruta != os.devnull and not _bajo(ruta, base):
                registro.append(f"BLOQUEADO open({ruta!r}, {modo!r})")
                raise PermissionError(f"mac-cleaner (solo lectura): escritura bloqueada en {ruta}")
        elif evento in _EVENTOS_RUTA:
            pos = _POS_DIR_FD.get(evento, ())
            rutas = []
            for i, a in enumerate(args):
                if isinstance(a, (str, bytes, os.PathLike)) and len(rutas) < 2:
                    j = pos[len(rutas)] if len(rutas) < len(pos) else None
                    rutas.append((a, args[j] if j is not None and j < len(args) else None))
            if not rutas or not all(_bajo(r, base, fd) for r, fd in rutas):
                registro.append(f"BLOQUEADO {evento}{args!r}")
                raise PermissionError(f"mac-cleaner (solo lectura): {evento} bloqueado")
        elif evento == "subprocess.Popen":
            exe = args[0] if args[0] is not None else (args[1][0] if args[1] else None)
            nombre = os.path.basename(os.fsdecode(exe)) if exe is not None else ""
            if nombre not in EJECUTABLES_PERMITIDOS:
                registro.append(f"BLOQUEADO subprocess {exe!r}")
                raise PermissionError(f"mac-cleaner (solo lectura): ejecutable no permitido {exe}")
            registro.append(f"subprocess {nombre} {' '.join(map(str, args[1][1:]))}")

    sys.addaudithook(hook)
    _activa = True
