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

Autenticación (F3): el manifiesto debe tener MAC válidos con su clave. purge nunca actúa sin MAC válidos.

Recuperación sin clave (F3.5): sin la clave el manifiesto NO prueba nada (su cadena SHA-256 no tiene clave:
quien escriba en la cuarentena puede recalcularla). Por eso no hay restauración automática:
  1. inventario_recuperacion(): solo lectura. Clasifica cada elemento como «restaurable» (todas las fuentes
     coherentes: ruta en la cuarentena = archivos/<ruta relativa del origen>, origen dentro de la zona y fuera
     de la cuarentena, inodo, tamaño, mtime, modo y propietario iguales a los del manifiesto, SHA-256 o ctime
     coincidentes, destino libre y directorio padre seguro) o «ambiguo» (cualquier discrepancia), calcula el
     SHA-256 ACTUAL de cada fichero y devuelve un código ligado al inventario. Lista también los ficheros de la
     cuarentena que el manifiesto no menciona. No mueve ni escribe nada.
  2. restaurar_recuperacion(): exige el inventario revisado y su código, que tenga menos de 1 h y que el
     manifiesto no haya cambiado desde entonces. Solo mueve los «restaurable» (o el subconjunto indicado),
     vuelve a comprobarlo todo, exige que el SHA-256 actual sea el del inventario y nunca sobrescribe. Lo ambiguo
     se queda en la cuarentena. NO escribe en el manifiesto: anota en <op>/recuperacion.jsonl, de modo que si la
     clave reaparece el manifiesto sigue siendo verificable.

Metadatos: el movimiento es un rename dentro del mismo volumen, así que el inodo es el mismo y se conservan
el contenido, el modo, el propietario, mtime, atime, birthtime, los atributos extendidos, las ACL y los
flags. NO se conservan: ctime (rename lo actualiza siempre), la mtime de los directorios padre (cambia al
salir y al volver una entrada) y la «Fecha de añadido» de Finder (kMDItemDateAdded), que depende de cuándo
llegó la entrada al directorio.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import time

from . import fsseguro, zona as zona_mod
from .aplicar import DIR_ARCHIVOS, DIR_PLANES, directorio_cuarentena
from .manifiesto import Manifiesto, ManifiestoOcupado  # noqa: F401  (ManifiestoOcupado: lo captura la CLI)


class ErrorRestauracion(ValueError):
    pass


CADUCIDAD_INVENTARIO_S = 3600
AVISO_RECUPERACION = ("Manifiesto no autenticado: la clasificación comprueba la COHERENCIA de las fuentes, no su "
                      "autenticidad. Revisa cada origen antes de confirmar; lo ambiguo nunca se restaura.")


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


def restaurar(zona: str, op: str, *, elemento: str | None = None, ruta: str | None = None) -> dict:
    zona, man = cargar_operacion(zona, op)
    with man.bloquear():                     # recarga el manifiesto con la operación bloqueada
        if man.cola_incompleta:
            man.reparar_cola()               # caída a mitad de un registro: se recorta y se anota
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


# ── recuperación sin clave (intervención manual) ───────────────────────────────

def _sha_manifiesto(ruta: str) -> str:
    fd = os.open(ruta, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _codigo(inv: dict) -> str:
    cuerpo = {k: v for k, v in inv.items() if k != "codigo"}
    return hashlib.sha256(json.dumps(cuerpo, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()[:12]


def _evaluar(zona: str, qarch: str, e: dict) -> tuple[str, str | None, int | None]:
    """(clasificación, sha256 actual, inodo) de un elemento según TODAS las fuentes disponibles."""
    try:
        if e.get("estado") not in ("movido", "intento"):
            return f"ambiguo: estado {e.get('estado')!r}", None, None
        meta = e["meta"]
        rel = zona_mod.exigir_dentro(e["origen"], zona)
        if e.get("destino") != os.path.join(qarch, rel):
            return "ambiguo: origen y destino incoherentes", None, None
        rel_dir, nombre = os.path.dirname(rel), os.path.basename(rel)
        qfd = fsseguro.abrir_dir(qarch, rel_dir)
        try:
            st = fsseguro.stat_en(qfd, nombre)
            if not stat.S_ISREG(st.st_mode) or st.st_ino != meta["ino"]:
                return "ambiguo: el fichero de la cuarentena no es el registrado (inodo)", None, None
            if (st.st_size, st.st_mtime_ns, st.st_mode, st.st_uid) != (meta["tam"], meta["mtime_ns"], meta["modo"], meta["uid"]):
                return "ambiguo: tamaño, mtime, modo o propietario distintos", None, st.st_ino
            sha = fsseguro.sha256_en(qfd, nombre, st.st_ino)
            if meta.get("sha256"):
                if sha != meta["sha256"]:
                    return "ambiguo: SHA-256 distinto del registrado", sha, st.st_ino
            elif e.get("ctime_movido") is None or st.st_ctime_ns != e["ctime_movido"]:
                return "ambiguo: sin SHA-256 registrado y ctime no verificable", sha, st.st_ino
        finally:
            os.close(qfd)
        try:
            ofd = fsseguro.abrir_dir(zona, rel_dir)
        except OSError as exc:
            return f"ambiguo: directorio de destino ausente o no seguro ({exc.strerror or exc})", sha, st.st_ino
        try:
            if fsseguro.existe_en(ofd, nombre):
                return "ambiguo: ya existe un fichero en el destino", sha, st.st_ino
        finally:
            os.close(ofd)
        return "restaurable", sha, st.st_ino
    except (zona_mod.ZonaNoValida, KeyError, TypeError, ValueError) as exc:
        return f"ambiguo: ruta o datos no válidos ({exc})", None, None
    except OSError as exc:
        return f"ambiguo: {exc.strerror or exc}", None, None


def inventario_recuperacion(zona: str, op: str, ahora: float | None = None) -> dict:
    """Paso 1 (solo lectura): qué se podría restaurar sin clave y qué es ambiguo. No mueve ni escribe nada."""
    zona, man = cargar_operacion(zona, op, sin_clave=True)
    qop = man.inicio["cuarentena"]
    qarch = os.path.join(qop, DIR_ARCHIVOS)
    with man.bloquear():
        sha_man = _sha_manifiesto(man.ruta)
        elementos, citados = [], set()
        for e in man.estados().values():
            if e.get("estado") in ("restaurado", "purgado", "omitido", "no_movido"):
                continue
            clasif, sha, ino = _evaluar(zona, qarch, e)
            citados.add(e.get("destino"))
            elementos.append({"id": e["id"], "origen": e.get("origen"), "destino": e.get("destino"),
                              "ino": ino, "sha256_actual": sha, "estado_manifiesto": e.get("estado"),
                              "clasificacion": "restaurable" if clasif == "restaurable" else "ambiguo",
                              "motivo": None if clasif == "restaurable" else clasif.split(": ", 1)[-1]})
        huerfanos = []
        try:
            for raiz, _dirs, ficheros, _fd in os.fwalk(qarch):
                huerfanos += [os.path.join(raiz, f) for f in ficheros if os.path.join(raiz, f) not in citados]
        except OSError:
            pass
    inv = {"tipo": "mac-cleaner-recuperacion", "version": 1, "zona": zona, "op": op,
           "generado": ahora or time.time(), "manifiesto_sha256": sha_man,
           "manifiesto_autenticado": False, "cola_incompleta": man.cola_incompleta,
           "aviso": AVISO_RECUPERACION, "elementos": elementos, "huerfanos": sorted(huerfanos)[:500]}
    inv["codigo"] = _codigo(inv)
    return inv


def restaurar_recuperacion(zona: str, op: str, inventario: dict, codigo: str, *, ahora: float | None = None,
                           elementos: set[str] | None = None) -> dict:
    """Paso 2: restaura SOLO lo «restaurable» de un inventario revisado y confirmado con su código."""
    ahora = ahora or time.time()
    if not isinstance(inventario, dict) or inventario.get("tipo") != "mac-cleaner-recuperacion" \
            or inventario.get("version") != 1:
        raise ErrorRestauracion("no es un inventario de recuperación de mac-cleaner")
    if not isinstance(codigo, str) or codigo != inventario.get("codigo") or codigo != _codigo(inventario):
        raise ErrorRestauracion("el código no corresponde al inventario (¿inventario alterado?)")
    if not isinstance(inventario.get("generado"), (int, float)) or not 0 <= ahora - inventario["generado"] <= CADUCIDAD_INVENTARIO_S:
        raise ErrorRestauracion("inventario caducado (más de 1 h) o con fecha futura: vuelve a generarlo")
    zona, man = cargar_operacion(zona, op, sin_clave=True)
    if inventario.get("zona") != zona or inventario.get("op") != op:
        raise ErrorRestauracion("el inventario es de otra zona u operación")
    qop = man.inicio["cuarentena"]
    qarch = os.path.join(qop, DIR_ARCHIVOS)
    res = {"op": op, "restaurados": 0, "omitidos": 0, "errores": 0, "detalle": []}
    with man.bloquear():
        if _sha_manifiesto(man.ruta) != inventario.get("manifiesto_sha256"):
            raise ErrorRestauracion("el manifiesto cambió desde el inventario: vuelve a generarlo")
        estados = man.estados()
        for x in inventario.get("elementos", []):
            if x.get("clasificacion") != "restaurable" or (elementos is not None and x.get("id") not in elementos):
                continue
            e = estados.get(x.get("id"))
            clasif, sha, ino = _evaluar(zona, qarch, e) if e else ("ambiguo: no está en el manifiesto", None, None)
            if clasif != "restaurable" or sha != x.get("sha256_actual") or ino != x.get("ino") \
                    or e.get("origen") != x.get("origen"):
                res["omitidos"] += 1
                res["detalle"].append({"id": x.get("id"), "resultado": f"omitido: cambió desde el inventario ({clasif})"})
                continue
            rel = zona_mod.exigir_dentro(e["origen"], zona)
            rel_dir, nombre = os.path.dirname(rel), os.path.basename(rel)
            qfd = ofd = None
            try:
                qfd = fsseguro.abrir_dir(qarch, rel_dir)
                ofd = fsseguro.abrir_dir(zona, rel_dir)
                fsseguro.mover_excl(qfd, nombre, ofd, nombre)       # RENAME_EXCL: nunca sobrescribe
                if fsseguro.stat_en(ofd, nombre).st_ino != ino:      # pragma: no cover - carrera extrema
                    raise OSError("identidad distinta tras restaurar")
                _anotar_recuperacion(qop, {"id": x["id"], "evento": "restaurado_sin_clave", "origen": e["origen"],
                                           "ino": ino, "sha256": sha, "codigo": codigo})
                res["restaurados"] += 1
            except OSError as exc:
                res["omitidos"] += 1
                res["detalle"].append({"id": x["id"], "resultado": f"omitido: {exc.strerror or exc}"})
            finally:
                for fd in (qfd, ofd):
                    if fd is not None:
                        os.close(fd)
    return res


def _anotar_recuperacion(qop: str, reg: dict) -> None:
    """Registro aparte (sin MAC): el manifiesto autenticado no se toca."""
    reg = {"t": time.time(), **reg}
    fd = os.open(os.path.join(qop, "recuperacion.jsonl"), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (json.dumps(reg, ensure_ascii=False, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
