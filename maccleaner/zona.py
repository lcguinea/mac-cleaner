"""Puerta de seguridad de F2: las operaciones que mueven o borran solo actúan en ZONAS SINTÉTICAS.

Una zona sintética es un directorio de pruebas que cumple TODO esto:
  * su ruta es canónica (sin enlaces simbólicos) y cuelga estrictamente del directorio temporal
    del usuario ($TMPDIR o tempfile.gettempdir()) o de /private/tmp, sin ser ese directorio;
  * no está dentro del HOME real;
  * es un directorio propiedad del usuario y no escribible por otros;
  * contiene el fichero marcador MARCADOR (regular, no enlace, del usuario) con el contenido exacto.

La limpieza de datos reales está deshabilitada por una CONSTANTE del código, no por una opción.
Habilitarla exige cambiar el código (ver docs/SEGURIDAD-F2.md, «Plan de habilitación»).
"""
from __future__ import annotations

import os
import stat
import tempfile

LIMPIEZA_REAL_HABILITADA = False

MARCADOR = ".mac-cleaner-zona-sintetica"
CONTENIDO_MARCADOR = b"mac-cleaner zona sintetica v1\n"
NOMBRE_CUARENTENA = ".mac-cleaner-cuarentena"


class ZonaNoValida(PermissionError):
    pass


# Se resuelve al importar: tempfile.gettempdir() escribe un fichero de prueba, y con la guardia de solo
# lectura ya activa esa escritura se bloquearía.
_TEMP_POR_DEFECTO = os.path.realpath(tempfile.gettempdir())


def _bases_temporales() -> list[str]:
    bases = {_TEMP_POR_DEFECTO, "/private/tmp"}
    if os.environ.get("TMPDIR"):
        bases.add(os.path.realpath(os.environ["TMPDIR"]))
    return sorted(bases)


def _bajo_estricto(ruta: str, base: str) -> bool:
    return ruta.startswith(base.rstrip("/") + "/")


def validar_zona(raiz: str | None) -> str:
    """Devuelve la ruta canónica de la zona o lanza ZonaNoValida explicando por qué."""
    if not raiz:
        if LIMPIEZA_REAL_HABILITADA:  # pragma: no cover - deshabilitado en F2
            raise ZonaNoValida("modo real no implementado")
        raise ZonaNoValida("F2: la limpieza de datos reales está deshabilitada; solo se admiten zonas sintéticas")
    absoluta = os.path.abspath(raiz)
    canon = os.path.realpath(absoluta)
    if canon != absoluta.rstrip("/"):
        raise ZonaNoValida(f"la ruta de la zona debe ser canónica (sin enlaces): usa {canon}")
    if not any(_bajo_estricto(canon, b) for b in _bases_temporales()):
        raise ZonaNoValida(f"la zona debe estar dentro del directorio temporal del usuario, no en {canon}")
    home = os.path.realpath(os.path.expanduser("~"))
    if canon == home or canon.startswith(home + "/"):
        raise ZonaNoValida("la zona no puede estar dentro del HOME real")
    try:
        st = os.lstat(canon)
    except OSError as exc:
        raise ZonaNoValida(f"zona no accesible: {exc}") from exc
    if not stat.S_ISDIR(st.st_mode):
        raise ZonaNoValida("la zona no es un directorio")
    if st.st_uid != os.getuid():
        raise ZonaNoValida("la zona no pertenece al usuario")
    if st.st_mode & 0o002:
        raise ZonaNoValida("la zona es escribible por cualquiera")
    marca = os.path.join(canon, MARCADOR)
    try:
        sm = os.lstat(marca)
    except OSError as exc:
        raise ZonaNoValida(f"falta el marcador {MARCADOR}") from exc
    if not stat.S_ISREG(sm.st_mode) or sm.st_uid != os.getuid():
        raise ZonaNoValida("el marcador no es un fichero regular del usuario")
    fd = os.open(marca, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        contenido = os.read(fd, 256)
    finally:
        os.close(fd)
    if contenido != CONTENIDO_MARCADOR:
        raise ZonaNoValida("el marcador no tiene el contenido esperado")
    return canon


def crear_zona(prefijo: str = "mac-cleaner-zona-") -> str:
    """Crea una zona sintética nueva (vacía, con marcador) bajo el directorio temporal del usuario."""
    raiz = os.path.realpath(tempfile.mkdtemp(prefix=prefijo))
    fd = os.open(os.path.join(raiz, MARCADOR), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, CONTENIDO_MARCADOR)
    finally:
        os.close(fd)
    for d in ("home/Library/Caches", "home/Library/Logs", "tmp"):
        os.makedirs(os.path.join(raiz, d), exist_ok=True)
    return validar_zona(raiz)


def exigir_dentro(ruta: str, zona: str) -> str:
    """La ruta (ya absoluta) debe colgar estrictamente de la zona, sin '..' ni componentes vacíos."""
    norm = os.path.normpath(ruta)
    if norm != ruta or not _bajo_estricto(norm, zona):
        raise ZonaNoValida(f"ruta fuera de la zona o no normalizada: {ruta}")
    rel = norm[len(zona) + 1:]
    if any(c in ("", ".", "..") for c in rel.split("/")):
        raise ZonaNoValida(f"ruta con componentes no válidos: {ruta}")
    if rel.split("/")[0] in (NOMBRE_CUARENTENA, MARCADOR):
        raise ZonaNoValida("la ruta apunta a la cuarentena o al marcador de la zona")
    return rel
