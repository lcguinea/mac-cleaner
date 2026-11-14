"""`restore`: devuelve a su sitio los ficheros de una operación (todos o uno), sin sobrescribir nunca.

Comprobaciones por elemento:
  * manifiesto íntegro (cadena SHA-256) y zona sintética válida;
  * en la cuarentena: directorio abierto con O_NOFOLLOW, fichero regular con el MISMO inodo, tamaño,
    mtime_ns, modo y propietario que al moverlo, y SHA-256 igual si se calculó;
  * en el destino: directorio padre existente y abierto con O_NOFOLLOW, y nombre libre. El movimiento usa
    RENAME_EXCL: si aparece un fichero en el último instante, el resultado es un conflicto, no una sobrescritura.

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
from .aplicar import DIR_ARCHIVOS, directorio_cuarentena
from .manifiesto import Manifiesto


class ErrorRestauracion(ValueError):
    pass


def cargar_operacion(zona: str, op: str) -> tuple[str, Manifiesto]:
    zona = zona_mod.validar_zona(zona)
    if not op or "/" in op or op.startswith("."):
        raise ErrorRestauracion(f"identificador de operación no válido: {op!r}")
    qop = os.path.join(directorio_cuarentena(zona), op)
    man = Manifiesto.cargar(os.path.join(qop, "manifiesto.jsonl"))
    if man.inicio.get("zona") != zona or man.inicio.get("cuarentena") != qop:
        raise ErrorRestauracion("el manifiesto pertenece a otra zona u operación")
    return zona, man


def _localizar(fd: int, nombre: str, ino: int) -> bool:
    try:
        st = fsseguro.stat_en(fd, nombre)
    except FileNotFoundError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_ino == ino


def restaurar(zona: str, op: str, *, elemento: str | None = None, ruta: str | None = None) -> dict:
    zona, man = cargar_operacion(zona, op)
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
        try:
            qfd = fsseguro.abrir_dir(qarch, rel_dir)
        except OSError as exc:
            qfd = None
            q_err = exc
        try:
            en_cuarentena = qfd is not None and _localizar(qfd, nombre, meta["ino"])
            if e["estado"] == "intento" and not en_cuarentena:
                # Caída entre «intento» y el movimiento: el fichero debería seguir en su sitio.
                try:
                    ofd = fsseguro.abrir_dir(zona, rel_dir)
                    sigue = _localizar(ofd, nombre, meta["ino"])
                    os.close(ofd)
                except OSError:
                    sigue = False
                man.anotar("no_movido" if sigue else "error", id=e["id"],
                           motivo=None if sigue else "no está ni en el origen ni en la cuarentena")
                res["sin_cambios" if sigue else "errores"] += 1
                res["detalle"].append({"id": e["id"], "resultado": "no se llegó a mover" if sigue else "no localizado"})
                continue
            if qfd is None:
                raise ErrorRestauracion(f"cuarentena inaccesible: {q_err}")
            if not en_cuarentena:
                raise ErrorRestauracion("el fichero en cuarentena no existe o cambió de identidad (inodo)")
            st = fsseguro.stat_en(qfd, nombre)
            if (st.st_size, st.st_mtime_ns, st.st_mode, st.st_uid) != (meta["tam"], meta["mtime_ns"], meta["modo"], meta["uid"]):
                raise ErrorRestauracion("el fichero en cuarentena fue modificado (tamaño, mtime, modo o propietario)")
            if meta.get("sha256") and fsseguro.sha256_en(qfd, nombre, st.st_ino) != meta["sha256"]:
                raise ErrorRestauracion("el contenido en cuarentena no coincide (SHA-256)")
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
            man.anotar("error", id=e["id"], motivo=str(exc))
            res["errores"] += 1
            res["detalle"].append({"id": e["id"], "resultado": f"error: {exc}"})
        finally:
            if qfd is not None:
                os.close(qfd)
    return res
