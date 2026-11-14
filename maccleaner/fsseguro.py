"""Primitivas de sistema de ficheros resistentes a enlaces simbólicos y a sustituciones de rutas.

* Los directorios se abren componente a componente desde una raíz canónica con O_NOFOLLOW|O_DIRECTORY
  (openat): ningún componente intermedio puede ser un enlace.
* Los movimientos usan renameatx_np(..., RENAME_EXCL) de macOS: es atómico dentro del volumen,
  nunca sobrescribe un destino existente (EEXIST) y no sigue enlaces en el último componente.
* Se comprueba la identidad (st_dev, st_ino) antes y después de cada movimiento.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import hashlib
import os
import stat

RENAME_EXCL = 0x00000004
RENAME_NOFOLLOW_ANY = 0x00000010   # macOS 13+: rechaza enlaces en cualquier componente

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_renameatx_np = getattr(_libc, "renameatx_np", None)
if _renameatx_np is not None:
    _renameatx_np.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    _renameatx_np.restype = ctypes.c_int

_ABRIR_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_NOFOLLOW_ANY_OK: bool | None = None


def disponible() -> bool:
    return _renameatx_np is not None


def _nombre_simple(nombre: str) -> None:
    if not nombre or "/" in nombre or nombre in (".", ".."):
        raise ValueError(f"nombre no válido: {nombre!r}")


def abrir_dir(raiz: str, rel_dir: str) -> int:
    """Abre raiz/rel_dir sin seguir enlaces en ningún componente. Devuelve un fd (cerrar con os.close)."""
    fd = os.open(raiz, _ABRIR_DIR)
    try:
        for comp in [c for c in rel_dir.split("/") if c]:
            _nombre_simple(comp)
            nfd = os.open(comp, _ABRIR_DIR, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


class DirectorioInseguro(PermissionError):
    pass


def asegurar_dir(raiz: str, rel_dir: str, modo: int = 0o700, privado: bool = False) -> int:
    """Como abrir_dir, pero crea los componentes que falten. Cada mkdir se hace RELATIVO al descriptor del
    padre (mkdirat): un enlace colocado en un componente intermedio no desvía la creación, y la apertura
    posterior con O_NOFOLLOW falla. Con privado=True cada componente debe ser del usuario y no escribible
    por el grupo ni por otros (la cuarentena); si no, DirectorioInseguro."""
    fd = os.open(raiz, _ABRIR_DIR)
    try:
        for comp in [c for c in rel_dir.split("/") if c]:
            _nombre_simple(comp)
            try:
                os.mkdir(comp, modo, dir_fd=fd)
            except FileExistsError:
                pass
            nfd = os.open(comp, _ABRIR_DIR, dir_fd=fd)
            os.close(fd)
            fd = nfd
            if privado:
                st = os.fstat(fd)
                if st.st_uid != os.getuid() or st.st_mode & 0o022:
                    raise DirectorioInseguro(errno.EPERM, f"directorio de cuarentena inseguro (propietario o permisos "
                                             f"{stat.filemode(st.st_mode)}): {os.path.join(raiz, rel_dir)}")
        return fd
    except BaseException:
        os.close(fd)
        raise


def stat_en(dir_fd: int, nombre: str) -> os.stat_result:
    _nombre_simple(nombre)
    return os.stat(nombre, dir_fd=dir_fd, follow_symlinks=False)


def existe_en(dir_fd: int, nombre: str) -> bool:
    try:
        stat_en(dir_fd, nombre)
        return True
    except FileNotFoundError:
        return False


def sha256_en(dir_fd: int, nombre: str, ino_esperado: int | None = None, bloque: int = 1 << 20) -> str:
    """SHA-256 del contenido, abriendo SIN seguir enlaces y comprobando que el inodo es el esperado."""
    _nombre_simple(nombre)
    fd = os.open(nombre, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (ino_esperado is not None and st.st_ino != ino_esperado):
            raise FileExistsError(errno.ESTALE, "el fichero cambió de identidad durante la lectura")
        h = hashlib.sha256()
        while True:
            b = os.read(fd, bloque)
            if not b:
                break
            h.update(b)
        return h.hexdigest()
    finally:
        os.close(fd)


def sha256_ruta(ruta: str, ino_esperado: int | None = None) -> str:
    fd = os.open(os.path.dirname(ruta), _ABRIR_DIR)
    try:
        return sha256_en(fd, os.path.basename(ruta), ino_esperado)
    finally:
        os.close(fd)


def mover_excl(src_fd: int, src: str, dst_fd: int, dst: str) -> None:
    """Movimiento atómico que NUNCA sobrescribe: lanza FileExistsError si el destino existe."""
    global _NOFOLLOW_ANY_OK
    _nombre_simple(src)
    _nombre_simple(dst)
    if _renameatx_np is None:  # pragma: no cover - macOS < 10.12
        raise OSError(errno.ENOTSUP, "renameatx_np no disponible: no se mueve nada sin RENAME_EXCL")
    flags = RENAME_EXCL | (RENAME_NOFOLLOW_ANY if _NOFOLLOW_ANY_OK is not False else 0)
    r = _renameatx_np(src_fd, os.fsencode(src), dst_fd, os.fsencode(dst), flags)
    if r != 0:
        e = ctypes.get_errno()
        if e == errno.EINVAL and _NOFOLLOW_ANY_OK is None:
            _NOFOLLOW_ANY_OK = False   # sistema sin RENAME_NOFOLLOW_ANY: los fds ya garantizan no seguir enlaces
            return mover_excl(src_fd, src, dst_fd, dst)
        raise OSError(e, os.strerror(e), src)
    if _NOFOLLOW_ANY_OK is None:
        _NOFOLLOW_ANY_OK = True
