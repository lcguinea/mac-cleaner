"""`purge`: selección por antigüedad de las operaciones en cuarentena y, SOLO en zona sintética, borrado.

Reglas de selección (seleccionar):
  * manifiesto íntegro; operación cerrada (registro `cierre`). Una operación sin cierre (caída) nunca se purga;
  * antigüedad desde el `inicio` mayor o igual a `dias` (14 por defecto, configurable en [cuarentena]);
  * solo elementos en estado `movido` (no restaurados ni ya purgados).
El borrado (purgar con ejecutar=True) exige zona sintética válida, comprueba el inodo de cada fichero
contra el manifiesto antes de borrarlo, borra solo lo listado (nunca un rmtree) y solo retira directorios
vacíos dentro de la propia cuarentena. Sin ejecutar=True solo devuelve la selección.

F2.5:
  * la retención mínima es 1 día también por línea de órdenes (`--dias`), no solo en el TOML;
  * cada operación se purga con su manifiesto BLOQUEADO y releído: solo se borra lo que en ese momento sigue
    en estado `movido` (un restore concurrente gana); si la operación está ocupada, se salta entera;
  * el borrado es unlinkat sobre el MISMO descriptor de directorio con el que se comprobó el inodo: sustituir
    un directorio intermedio por un enlace entre la comprobación y el borrado ya no desvía el borrado;
  * los directorios vacíos se retiran con fwalk + rmdirat, sin seguir enlaces.

F3: solo se seleccionan y purgan operaciones cuyo manifiesto tiene MAC válidos con su clave. Sin la clave
(o con un manifiesto F2 sin autenticar) la operación se descarta; nunca se borra nada «en recuperación».
"""
from __future__ import annotations

import os
import stat
import time

from . import fsseguro, zona as zona_mod
from .aplicar import DIR_ARCHIVOS, DIR_PLANES, directorio_cuarentena
from .manifiesto import Manifiesto, ManifiestoCorrupto, ManifiestoOcupado

DIA = 86400
DIAS_POR_DEFECTO = 14
DIAS_MINIMOS = 1


def seleccionar(zona: str, *, dias: float = DIAS_POR_DEFECTO, ahora: float | None = None) -> dict:
    if not isinstance(dias, (int, float)) or isinstance(dias, bool) or not dias >= DIAS_MINIMOS:
        raise ValueError(f"la retención debe ser de al menos {DIAS_MINIMOS} día (recibido: {dias!r})")
    zona = zona_mod.validar_zona(zona)
    ahora = ahora or time.time()
    qbase = directorio_cuarentena(zona)
    ops, descartadas = [], []
    try:
        nombres = sorted(os.listdir(qbase))
    except FileNotFoundError:
        nombres = []
    for op in nombres:
        if op == DIR_PLANES:
            continue                       # registro de planes aplicados (F3), no es una operación
        qop = os.path.join(qbase, op)
        if os.path.islink(qop) or not os.path.isdir(qop):
            descartadas.append({"op": op, "motivo": "no es un directorio de operación"})
            continue
        try:
            man = Manifiesto.cargar(os.path.join(qop, "manifiesto.jsonl"))
        except ManifiestoCorrupto as exc:
            descartadas.append({"op": op, "motivo": f"manifiesto no válido: {exc}"})
            continue
        if man.cola_incompleta or man.cola_descartada:
            descartadas.append({"op": op, "motivo": "manifiesto con un registro final incompleto (posible caída): "
                                                    "no se purga; restaura o revisa la operación"})
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
    borrados = errores = saltados = 0
    ocupadas = []
    for o in sel["seleccionadas"]:
        qop = os.path.join(directorio_cuarentena(zona), o["op"])
        qarch = os.path.join(qop, DIR_ARCHIVOS)
        try:
            man = Manifiesto.cargar(os.path.join(qop, "manifiesto.jsonl"))
            with man.bloquear():                    # recarga: decide con el estado más reciente
                if man.inicio.get("zona") != zona or man.inicio.get("cuarentena") != qop:
                    raise ManifiestoCorrupto("el manifiesto pertenece a otra zona u operación")
                if man.cola_incompleta or man.cola_descartada:
                    raise ManifiestoCorrupto("registro final incompleto: no se purga")
                b, er, sa = _purgar_operacion(man, qarch, {x["id"] for x in o["elementos"]})
        except ManifiestoOcupado as exc:
            ocupadas.append({"op": o["op"], "motivo": f"operación ocupada: {exc}"})
            continue
        except ManifiestoCorrupto as exc:
            ocupadas.append({"op": o["op"], "motivo": f"manifiesto no válido al purgar: {exc}"})
            continue
        borrados, errores, saltados = borrados + b, errores + er, saltados + sa
        _retirar_vacios(qarch)
    sel.update(ejecutado=True, borrados=borrados, errores=errores, saltados=saltados, ocupadas=ocupadas)
    return sel


def _purgar_operacion(man: Manifiesto, qarch: str, seleccionados: set[str]) -> tuple[int, int, int]:
    """Purga lo seleccionado que, releído bajo bloqueo, SIGUE en estado `movido`."""
    borrados = errores = saltados = 0
    estados = man.estados()
    for eid in sorted(seleccionados):
        x = estados.get(eid, {})
        if x.get("estado") != "movido":
            saltados += 1                   # restaurado o purgado por otro proceso entre selección y borrado
            continue
        try:
            rel = os.path.relpath(x["destino"], qarch)
            if rel.startswith("..") or os.path.isabs(rel):
                raise ValueError("destino fuera de la cuarentena")
            ino = x["meta"]["ino"]
            fd = fsseguro.abrir_dir(qarch, os.path.dirname(rel))
            try:
                nombre = os.path.basename(rel)
                st = fsseguro.stat_en(fd, nombre)
                if not stat.S_ISREG(st.st_mode) or st.st_ino != ino:
                    raise OSError("identidad distinta a la del manifiesto")
                # unlinkat sobre el mismo descriptor verificado (la guardia resuelve dir_fd con F_GETPATH).
                os.unlink(nombre, dir_fd=fd)
            finally:
                os.close(fd)
            man.anotar("purgado", id=x["id"])
            borrados += 1
        except (OSError, ValueError, KeyError, TypeError) as exc:
            man.anotar("error", id=x["id"], motivo=f"purga: {exc}")
            errores += 1
    return borrados, errores, saltados


def _retirar_vacios(qarch: str) -> None:
    """Retira directorios vacíos bajo la cuarentena de la operación, sin seguir enlaces (fwalk + rmdirat)."""
    try:
        # fwalk cierra cada descriptor tras entregarlo: hay que usarlo dentro del bucle. Con topdown=False los
        # hijos llegan antes que el padre, así que al llegar al padre sus subdirectorios ya están vacíos.
        for _raiz, dirs, _files, rootfd in os.fwalk(qarch, topdown=False):
            for d in dirs:
                try:
                    os.rmdir(d, dir_fd=rootfd)
                except OSError:
                    pass
    except OSError:
        return
