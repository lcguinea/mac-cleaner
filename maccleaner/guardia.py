"""Guardia de solo lectura en tiempo de ejecución (audit hooks de Python, PEP 578).

Una vez activada no se puede desactivar dentro del proceso. Bloquea, lanzando PermissionError:
  * cualquier apertura en modo escritura fuera del directorio de resultados;
  * remove/rename/rmdir/chmod/chown/utime/truncate/link/symlink/mkdir/xattr fuera de ese directorio;
  * cualquier subproceso cuyo ejecutable no esté en la lista blanca.
"""
from __future__ import annotations

import os
import sys

_ESCRITURA = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
_EVENTOS_RUTA = {
    "os.remove", "os.rmdir", "os.rename", "os.replace", "os.chmod", "os.lchmod", "os.chown", "os.lchown",
    "os.utime", "os.truncate", "os.link", "os.symlink", "os.mkdir", "os.chflags", "os.lchflags",
    "os.setxattr", "os.removexattr", "shutil.rmtree", "shutil.move", "shutil.copyfile", "shutil.copytree",
}
EJECUTABLES_PERMITIDOS = {"lsof", "tmutil", "brew", "pip3", "pip"}

registro: list[str] = []
_activa = False


def _bajo(ruta, base: str) -> bool:
    if isinstance(ruta, int):          # descriptor ya abierto: no es una ruta nueva
        return True
    try:
        r = os.path.realpath(os.fsdecode(ruta))
    except (TypeError, ValueError):
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
            rutas = [a for a in args if isinstance(a, (str, bytes, os.PathLike))][:2]
            if not rutas or not all(_bajo(r, base) for r in rutas):
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
