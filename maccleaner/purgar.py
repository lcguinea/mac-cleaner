"""`purge`: selección por antigüedad de las operaciones en cuarentena y, SOLO en zona sintética, borrado.

Reglas de selección (seleccionar):
  * manifiesto íntegro; operación cerrada (registro `cierre`). Una operación sin cierre (caída) nunca se purga;
  * antigüedad desde el `inicio` mayor o igual a `dias` (14 por defecto, configurable en [cuarentena]);
  * solo elementos en estado `movido` (no restaurados ni ya purgados).
El borrado (purgar con ejecutar=True) exige zona sintética válida, comprueba el inodo de cada fichero
contra el manifiesto antes de borrarlo, borra solo lo listado (nunca un rmtree) y solo retira directorios
vacíos dentro de la propia cuarentena. Sin ejecutar=True solo devuelve la selección.
"""
from __future__ import annotations

import os
import stat
import time

from . import fsseguro, zona as zona_mod
from .aplicar import DIR_ARCHIVOS, directorio_cuarentena
from .manifiesto import Manifiesto, ManifiestoCorrupto

DIA = 86400
DIAS_POR_DEFECTO = 14


def seleccionar(zona: str, *, dias: float = DIAS_POR_DEFECTO, ahora: float | None = None) -> dict:
    zona = zona_mod.validar_zona(zona)
    ahora = ahora or time.time()
    qbase = directorio_cuarentena(zona)
    ops, descartadas = [], []
    try:
        nombres = sorted(os.listdir(qbase))
    except FileNotFoundError:
        nombres = []
    for op in nombres:
        qop = os.path.join(qbase, op)
        if os.path.islink(qop) or not os.path.isdir(qop):
            descartadas.append({"op": op, "motivo": "no es un directorio de operación"})
            continue
        try:
            man = Manifiesto.cargar(os.path.join(qop, "manifiesto.jsonl"))
        except ManifiestoCorrupto as exc:
            descartadas.append({"op": op, "motivo": f"manifiesto no válido: {exc}"})
            continue
        if not man.cerrado:
            descartadas.append({"op": op, "motivo": "operación sin cierre (incompleta): no se purga"})
            continue
        edad = (ahora - man.inicio["t"]) / DIA
        pendientes = [e for e in man.estados().values() if e.get("estado") == "movido"]
        if edad < dias:
            descartadas.append({"op": op, "motivo": f"en periodo de retención ({edad:.1f} de {dias} días)",
                                "elementos": len(pendientes)})
            continue
        if not pendientes:
            descartadas.append({"op": op, "motivo": "nada que purgar (todo restaurado o purgado)"})
            continue
        ops.append({"op": op, "edad_dias": round(edad, 2), "elementos": [
            {"id": e["id"], "origen": e["origen"], "destino": e["destino"], "ino": e["meta"]["ino"], "tam": e["meta"]["tam"]}
            for e in pendientes]})
    return {"zona": zona, "dias": dias, "seleccionadas": ops, "descartadas": descartadas,
            "bytes": sum(x["tam"] for o in ops for x in o["elementos"])}


def purgar(zona: str, *, dias: float = DIAS_POR_DEFECTO, ahora: float | None = None, ejecutar: bool = False) -> dict:
    sel = seleccionar(zona, dias=dias, ahora=ahora)
    sel["ejecutado"] = False
    if not ejecutar:
        return sel
    zona = zona_mod.validar_zona(sel["zona"])   # vuelve a validar inmediatamente antes de borrar
    borrados = errores = 0
    for o in sel["seleccionadas"]:
        qop = os.path.join(directorio_cuarentena(zona), o["op"])
        qarch = os.path.join(qop, DIR_ARCHIVOS)
        man = Manifiesto.cargar(os.path.join(qop, "manifiesto.jsonl"))
        for x in o["elementos"]:
            rel = os.path.relpath(x["destino"], qarch)
            if rel.startswith("..") or os.path.isabs(rel):
                man.anotar("error", id=x["id"], motivo="destino fuera de la cuarentena")
                errores += 1
                continue
            try:
                fd = fsseguro.abrir_dir(qarch, os.path.dirname(rel))
                try:
                    st = fsseguro.stat_en(fd, os.path.basename(rel))
                finally:
                    os.close(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_ino != x["ino"]:
                    raise OSError("identidad distinta a la del manifiesto")
                os.unlink(os.path.join(qarch, rel))   # ruta absoluta dentro de la cuarentena (0700) para la guardia
                man.anotar("purgado", id=x["id"])
                borrados += 1
            except OSError as exc:
                man.anotar("error", id=x["id"], motivo=f"purga: {exc}")
                errores += 1
        for d, dirs, files in os.walk(qarch, topdown=False):
            if d != qarch and not os.listdir(d):
                try:
                    os.rmdir(d)
                except OSError:
                    pass
    sel.update(ejecutado=True, borrados=borrados, errores=errores)
    return sel
