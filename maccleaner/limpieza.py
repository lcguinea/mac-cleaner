"""F5B: limpieza real desde la app (autorización F5B-app-1, docs/F5.md).

Dos pasos, cada uno en su propio proceso del motor:
  1. `vista_previa`: escaneo + sombra (solo lectura; no necesita la clave). La app enseña al usuario qué entraría por
     categoría y cuánto, y qué categorías se omiten y por qué.
  2. `ejecutar`: el usuario confirma un tope de bytes (lo que vio). Escaneo y sombra NUEVOS (los topes salen de esta
     sombra), plan real firmado con la clave del Llavero y apply, todo en el MISMO proceso: macOS pide permiso para la
     clave una sola vez. El plan se rechaza entero si supera el tope confirmado, el de la sombra o MAX_BYTES.
Los informes, la sombra, el plan y la cuarentena quedan en ~/.mac-cleaner (la guardia solo permite escribir ahí).
"""
from __future__ import annotations

import datetime as dt
import json
import os

from . import autorizacion, sombra, zona as zona_mod
from .sistema import FicherosAbiertos

DIR_INFORMES = "informes"


def directorio_informes(raiz: str | None = None) -> str:
    return os.path.join(raiz or zona_mod.raiz_real(), zona_mod.DIR_REAL, DIR_INFORMES)


def _guardar(salida: str, nombre: str, datos) -> str:
    os.makedirs(salida, mode=0o700, exist_ok=True)
    ruta = os.path.join(salida, nombre)
    with open(ruta, "w", encoding="utf-8") as fh:
        json.dump(datos, fh, ensure_ascii=False, indent=1)
    return ruta


def _escanear_y_sombrear(cfg, abiertos, ahora, salida):
    from .cli import ejecutar_scan          # cli importa este módulo de forma diferida: sin ciclo
    escaneo = ejecutar_scan(cfg, abiertos=abiertos, ahora=ahora)
    sello = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    r_esc = _guardar(salida, f"scan-{sello}.json", escaneo)
    doc, lista = sombra.evaluar(escaneo, cfg, abiertos=abiertos, ahora=ahora)
    r_som = _guardar(salida, f"sombra-{sello}.json", doc)
    sombra.guardar_candidatos(r_som[:-5] + "-candidatos.jsonl", lista)
    return escaneo, r_esc, doc, lista, r_som


def _por_regla(doc: dict) -> dict:
    out = {}
    for g in doc["candidatos"]["grupos"]:
        if g["lista_blanca"]["si"]:
            r = out.setdefault(g["regla"], {"ficheros": 0, "bytes": 0, "grupos": []})
            r["ficheros"] += g["lista_blanca"]["si"]
            r["bytes"] += g["lista_blanca"]["bytes_si"]
            r["grupos"].append({"grupo": g["grupo"], "ficheros": g["lista_blanca"]["si"],
                                "bytes": g["lista_blanca"]["bytes_si"], "riesgo": g["riesgo"]})
    for r in out.values():
        r["grupos"].sort(key=lambda x: -x["bytes"])
        r["grupos"] = r["grupos"][:15]
    return out


def vista_previa(cfg, *, abiertos: FicherosAbiertos, ahora: float, salida: str) -> dict:
    escaneo, r_esc, doc, _lista, r_som = _escanear_y_sombrear(cfg, abiertos, ahora, salida)
    bloqueada, habilitadas, omitidas = None, [], {}
    try:
        habilitadas, _h, omitidas = autorizacion.preparar(zona_mod.raiz_real(), abiertos, ahora)
    except autorizacion.ErrorAutorizacion as exc:
        bloqueada = str(exc)
    por_regla = {k: v for k, v in _por_regla(doc).items() if k in habilitadas}
    total = sum(v["bytes"] for v in por_regla.values())
    bloq = doc["verificaciones"]["bloqueantes"]
    if bloq and not bloqueada:
        bloqueada = f"la sombra tiene {bloq} verificaciones bloqueantes: revisa {r_som[:-5]}.md"
    return {"tipo": "mac-cleaner-vista-previa", "autorizacion": autorizacion.ID, "generado": doc["generado"],
            "escaneo": r_esc, "sombra": r_som, "reglas": por_regla, "omitidas": omitidas,
            "total_bytes": total, "total_ficheros": sum(v["ficheros"] for v in por_regla.values()),
            "max_bytes": autorizacion.MAX_BYTES, "supera_tope": total > autorizacion.MAX_BYTES,
            "bloqueada": bloqueada, "disco": escaneo.get("disco"),
            "dias_cuarentena": autorizacion.DIAS_CUARENTENA}


def ejecutar(cfg, *, hasta_bytes: int, reglas: list[str] | None, ahora: float, salida: str,
             abiertos: FicherosAbiertos | None = None, abiertos_apply: FicherosAbiertos | None = None) -> dict:
    """Escaneo + sombra + plan real firmado + apply. `abiertos_apply=None` toma un lsof nuevo justo antes de mover."""
    from .aplicar import Aplicador
    from .plan import crear_plan, guardar
    abiertos = abiertos if abiertos is not None else FicherosAbiertos.capturar()
    escaneo, r_esc, doc, lista, r_som = _escanear_y_sombrear(cfg, abiertos, ahora, salida)
    plan = crear_plan(escaneo, cfg, ruta_escaneo=r_esc, ahora=ahora, abiertos=abiertos,
                      hash_max_bytes=cfg.hash_max_bytes, calcular_hash=True,
                      real={"sombra": doc, "candidatos": lista, "ruta": r_som, "hasta_bytes": hasta_bytes,
                            "reglas": reglas})
    r_plan = guardar(plan, salida)
    res = Aplicador(plan, ahora=ahora, abiertos=abiertos_apply).aplicar()
    return {"tipo": "mac-cleaner-limpieza", "autorizacion": autorizacion.ID, "plan": r_plan,
            "reglas": plan["real"]["reglas"], "omitidas": plan.get("omitidas", {}),
            "planificado": plan["totales"], "topes": plan["real"]["topes"], **res}
