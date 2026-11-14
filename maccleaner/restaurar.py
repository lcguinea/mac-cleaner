"""`restore`: devuelve a su sitio los ficheros de una operación (todos o uno), sin sobrescribir nunca.

Comprobaciones por elemento:
  * manifiesto íntegro (cadena SHA-256) y zona sintética válida;
  * en la cuarentena: directorio abierto con O_NOFOLLOW, fichero regular con el MISMO inodo, tamaño,
    mtime_ns, modo y propietario que al moverlo, y SHA-256 igual si se calculó;
  * en el destino: directorio padre existente y abierto con O_NOFOLLOW, y nombre libre. El movimiento usa
    RENAME_EXCL: si aparece un fichero en el último instante, el resultado es un conflicto, no una sobrescritura.

Robustez (F2.5):
  * la operación se restaura con el manifiesto bloqueado (flock); un apply, restore o purge simultáneo de la
    misma operación se rechaza con ManifiestoOcupado;
  * un error durante la restauración de un elemento `movido` se registra como `restaurar_error` SIN cambiar
    su estado: el fichero sigue en cuarentena y un nuevo restore lo reintenta;
  * si un restore anterior murió después de devolver el fichero y antes de anotarlo, el reintento lo
    encuentra en el origen por su inodo y lo anota como restaurado;
  * los ficheros sin SHA-256 (mayores que hash_max) se comprueban también por ctime: si cambió desde que
    entraron en la cuarentena, alguien los tocó (contenido, permisos o atributos) y no se devuelven.

Autenticación (F3): el manifiesto debe tener MAC válidos con su clave. Si la clave se perdió, la opción
`sin_clave=True` (CLI: --recuperacion-sin-clave) carga el manifiesto comprobando solo la cadena; las demás
comprobaciones (inodo, metadatos, SHA-256 o ctime, RENAME_EXCL, puerta de zona) se mantienen y lo anotado
queda marcado como `recuperacion`. purge nunca actúa sin MAC válidos.

Metadatos: el movimiento es un rename dentro del mismo volumen, así que el inodo es el mismo y se conservan
el contenido, el modo, el propietario, mtime, atime, birthtime, los atributos extendidos, las ACL y los
flags. NO se conservan: ctime (rename lo actualiza siempre), la mtime de los directorios padre (cambia al
salir y al volver una entrada) y la «Fecha de añadido» de Finder (kMDItemDateAdded), que depende de cuándo
llegó la entrada al directorio.
"""
from __future__ import annotations

import os
import stat

from . import fsseguro, zona as zona_mod
from .aplicar import DIR_ARCHIVOS, DIR_PLANES, directorio_cuarentena
from .manifiesto import Manifiesto, ManifiestoOcupado  # noqa: F401  (ManifiestoOcupado: lo captura la CLI)


class ErrorRestauracion(ValueError):
    pass


def cargar_operacion(zona: str, op: str, sin_clave: bool = False) -> tuple[str, Manifiesto]:
    zona = zona_mod.validar_zona(zona)
    if not op or "/" in op or op.startswith(".") or op == DIR_PLANES:
        raise ErrorRestauracion(f"identificador de operación no válido: {op!r}")
    qop = os.path.join(directorio_cuarentena(zona), op)
    man = Manifiesto.cargar(os.path.join(qop, "manifiesto.jsonl"), verificar=not sin_clave)
    if man.inicio.get("zona") != zona or man.inicio.get("cuarentena") != qop:
        raise ErrorRestauracion("el manifiesto pertenece a otra zona u operación")
    return zona, man


def _localizar(fd: int, nombre: str, ino: int) -> bool:
    try:
        st = fsseguro.stat_en(fd, nombre)
    except FileNotFoundError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_ino == ino


def _en_origen(zona: str, rel_dir: str, nombre: str, ino: int) -> bool:
    try:
        ofd = fsseguro.abrir_dir(zona, rel_dir)
    except OSError:
        return False
    try:
        return _localizar(ofd, nombre, ino)
    except OSError:
        return False
    finally:
        os.close(ofd)


def restaurar(zona: str, op: str, *, elemento: str | None = None, ruta: str | None = None,
              sin_clave: bool = False) -> dict:
    zona, man = cargar_operacion(zona, op, sin_clave)
    with man.bloquear():                     # recarga el manifiesto con la operación bloqueada
        return _restaurar(zona, op, man, elemento, ruta)


def _restaurar(zona: str, op: str, man: Manifiesto, elemento: str | None, ruta: str | None) -> dict:
    qarch = os.path.join(man.inicio["cuarentena"], DIR_ARCHIVOS)
    estados = man.estados()
    seleccion = [e for e in estados.values()
                 if (elemento is None or e["id"] == elemento) and (ruta is None or e.get("origen") == ruta)]
    if (elemento or ruta) and not seleccion:
        raise ErrorRestauracion("el elemento indicado no existe en la operación")
    res = {"op": op, "restaurados": 0, "conflictos": 0, "errores": 0, "sin_cambios": 0, "detalle": []}

    for e in seleccion:
        if e.get("estado") not in ("movido", "intento"):
            res["sin_cambios"] += 1
            continue
        rel = zona_mod.exigir_dentro(e["origen"], zona)
        rel_dir, nombre = os.path.dirname(rel), os.path.basename(rel)
        meta = e["meta"]
        if e.get("destino") != os.path.join(qarch, rel):
            # apply guarda cada fichero en archivos/<ruta relativa del origen>: si no coinciden, alguien editó
            # el origen o el destino (relevante sobre todo en la recuperación sin clave).
            man.anotar("restaurar_error", id=e["id"], motivo="origen y destino incoherentes en el manifiesto")
            res["errores"] += 1
            res["detalle"].append({"id": e["id"], "resultado": "error: origen y destino incoherentes"})
            continue
        try:
            qfd = fsseguro.abrir_dir(qarch, rel_dir)
        except OSError as exc:
            qfd = None
            q_err = exc
        try:
            en_cuarentena = qfd is not None and _localizar(qfd, nombre, meta["ino"])
            if e["estado"] == "intento" and not en_cuarentena:
                # Caída entre «intento» y el movimiento: el fichero debería seguir en su sitio.
                sigue = _en_origen(zona, rel_dir, nombre, meta["ino"])
                # Si no aparece, no se cambia el estado («intento»): un restore posterior lo vuelve a buscar.
                man.anotar("no_movido" if sigue else "restaurar_error", id=e["id"],
                           motivo=None if sigue else "no está ni en el origen ni en la cuarentena")
                res["sin_cambios" if sigue else "errores"] += 1
                res["detalle"].append({"id": e["id"], "resultado": "no se llegó a mover" if sigue else "no localizado"})
                continue
            if not en_cuarentena:
                # ¿Un restore anterior lo devolvió y murió antes de anotarlo? Se busca por inodo en el origen.
                if _en_origen(zona, rel_dir, nombre, meta["ino"]):
                    man.anotar("restaurado", id=e["id"], ino=meta["ino"], recuperado=True)
                    res["restaurados"] += 1
                    res["detalle"].append({"id": e["id"], "resultado": "ya estaba en su sitio (restore anterior interrumpido)"})
                    continue
            if qfd is None:
                raise ErrorRestauracion(f"cuarentena inaccesible: {q_err}")
            if not en_cuarentena:
                raise ErrorRestauracion("el fichero en cuarentena no existe o cambió de identidad (inodo)")
            st = fsseguro.stat_en(qfd, nombre)
            if (st.st_size, st.st_mtime_ns, st.st_mode, st.st_uid) != (meta["tam"], meta["mtime_ns"], meta["modo"], meta["uid"]):
                raise ErrorRestauracion("el fichero en cuarentena fue modificado (tamaño, mtime, modo o propietario)")
            if meta.get("sha256"):
                if fsseguro.sha256_en(qfd, nombre, st.st_ino) != meta["sha256"]:
                    raise ErrorRestauracion("el contenido en cuarentena no coincide (SHA-256)")
            elif e.get("ctime_movido") is not None and st.st_ctime_ns != e["ctime_movido"]:
                raise ErrorRestauracion("el fichero en cuarentena cambió desde que entró (ctime) y no tiene SHA-256 "
                                        "con que verificar el contenido: no se devuelve; revísalo a mano")
            try:
                ofd = fsseguro.abrir_dir(zona, rel_dir)
            except FileNotFoundError:
                man.anotar("conflicto", id=e["id"], motivo="el directorio de destino ya no existe")
                res["conflictos"] += 1
                res["detalle"].append({"id": e["id"], "resultado": "conflicto: falta el directorio de destino"})
                continue
            except OSError as exc:
                man.anotar("conflicto", id=e["id"], motivo=f"destino no seguro: {exc.strerror or exc}")
                res["conflictos"] += 1
                res["detalle"].append({"id": e["id"], "resultado": "conflicto: destino no seguro (¿enlace?)"})
                continue
            try:
                if fsseguro.existe_en(ofd, nombre):
                    man.anotar("conflicto", id=e["id"], motivo="ya existe un fichero en el destino")
                    res["conflictos"] += 1
                    res["detalle"].append({"id": e["id"], "resultado": "conflicto: el destino existe (no se sobrescribe)"})
                    continue
                man.anotar("restaurar_intento", id=e["id"])
                try:
                    fsseguro.mover_excl(qfd, nombre, ofd, nombre)
                except FileExistsError:
                    man.anotar("conflicto", id=e["id"], motivo="el destino apareció durante la restauración")
                    res["conflictos"] += 1
                    continue
                st2 = fsseguro.stat_en(ofd, nombre)
                if st2.st_ino != meta["ino"]:  # pragma: no cover - imposible con RENAME_EXCL salvo carrera extrema
                    raise ErrorRestauracion("identidad distinta tras restaurar")
                man.anotar("restaurado", id=e["id"], ino=st2.st_ino)
                res["restaurados"] += 1
            finally:
                os.close(ofd)
        except (ErrorRestauracion, OSError) as exc:
            # Sin cambiar el estado: el elemento sigue en cuarentena y se puede reintentar.
            man.anotar("restaurar_error", id=e["id"], motivo=str(exc))
            res["errores"] += 1
            res["detalle"].append({"id": e["id"], "resultado": f"error: {exc}"})
        finally:
            if qfd is not None:
                os.close(qfd)
    return res
