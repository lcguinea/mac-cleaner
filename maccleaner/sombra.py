"""F3: ejecución en sombra. Evalúa qué se limpiaría, sin mover ni borrar nada.

Parte de un escaneo reciente (≤ 24 h), vuelve a recorrer los grupos candidatos AHORA con las protecciones de F1
(lo mismo que `plan`, pero sin firmar ni calcular SHA-256) y clasifica cada fichero con la lista blanca.
El resultado distingue:
  * candidatos (por regla y grupo, con una muestra de rutas);
  * exclusiones y motivos (del escaneo y de la revalidación);
  * espacio potencialmente recuperable (físico, sin garantías: clones, snapshots y regeneración);
  * riesgos;
  * cambios respecto a la ejecución en sombra anterior;
  * operaciones que requerirían autorización (y qué falta para cada una).
Nunca produce un plan aplicable: no hay MAC y la limpieza real sigue deshabilitada en el código.
"""
from __future__ import annotations

import datetime as dt
import os
import time

from . import listablanca, zona as zona_mod
from .config import Config
from .plan import crear_plan
from .sistema import FicherosAbiertos

VERSION_SOMBRA = 1
MUESTRA = 5


def evaluar(escaneo: dict, cfg: Config, *, abiertos: FicherosAbiertos, ahora: float | None = None,
            anterior: dict | None = None) -> dict:
    ahora = ahora or time.time()
    plan = crear_plan(escaneo, cfg, abiertos=abiertos, ahora=ahora, calcular_hash=False, firmar=False)
    subs, rechazos_raiz = listablanca.subarboles(escaneo["escaneo"]["reglas"], cfg.home)

    grupos: dict[str, dict] = {}
    for e in plan["elementos"]:
        ok, motivo = listablanca.clasificar(e["regla"], e["ruta"], subs)
        clave = f"{e['regla']}:{e['grupo']}"
        g = grupos.setdefault(clave, {"regla": e["regla"], "grupo": e["grupo"], "riesgo": e["riesgo"],
                                      "ficheros": 0, "bytes_fisicos": 0, "bytes_logicos": 0,
                                      "lista_blanca": {"si": 0, "no": 0, "bytes_si": 0, "bytes_no": 0},
                                      "motivos_no": {}, "muestra": []})
        b = e["bloques"] * 512
        g["ficheros"] += 1
        g["bytes_fisicos"] += b
        g["bytes_logicos"] += e["tam"]
        lb = g["lista_blanca"]
        if ok:
            lb["si"] += 1
            lb["bytes_si"] += b
        else:
            lb["no"] += 1
            lb["bytes_no"] += b
            g["motivos_no"][motivo] = g["motivos_no"].get(motivo, 0) + 1
        if len(g["muestra"]) < MUESTRA:
            g["muestra"].append(e["ruta"])

    lista = sorted(grupos.values(), key=lambda g: g["bytes_fisicos"], reverse=True)
    tot = {
        "ficheros": sum(g["ficheros"] for g in lista),
        "bytes_fisicos": sum(g["bytes_fisicos"] for g in lista),
        "lista_blanca_ficheros": sum(g["lista_blanca"]["si"] for g in lista),
        "lista_blanca_bytes": sum(g["lista_blanca"]["bytes_si"] for g in lista),
        "fuera_lista_ficheros": sum(g["lista_blanca"]["no"] for g in lista),
        "fuera_lista_bytes": sum(g["lista_blanca"]["bytes_no"] for g in lista),
    }

    excl_reval: dict[str, int] = {}
    for x in plan["excluidos"]:
        excl_reval[x["motivo"]] = excl_reval.get(x["motivo"], 0) + 1

    riesgos = [
        "La limpieza real está DESHABILITADA en el código (zona.LIMPIEZA_REAL_HABILITADA = False): nada de esto se ejecuta.",
        "Ocupado ≠ recuperable: clones de APFS y snapshots locales pueden impedir liberar espacio; las cachés se regeneran.",
        "Instantánea única de lsof: un fichero abierto después de la evaluación no se detecta.",
    ]
    if escaneo.get("snapshots", {}).get("snapshots"):
        riesgos.append(f"Hay {len(escaneo['snapshots']['snapshots'])} snapshots locales: el espacio no se liberaría hasta que caduquen.")
    altos = [g for g in lista if g["riesgo"] != "bajo"]
    if altos:
        riesgos.append(f"{len(altos)} grupos candidatos tienen riesgo medio (el riesgo alto ya está excluido).")
    for r in rechazos_raiz:
        riesgos.append(f"Raíz de {r['regla']} rechazada para la lista blanca: {r['motivo']} ({r['raiz']}).")

    operaciones = []
    for rid, lb in listablanca.LISTA_BLANCA.items():
        gs = [g for g in lista if g["regla"] == rid and g["lista_blanca"]["si"]]
        operaciones.append({
            "regla": rid, "operacion": lb["operacion"], "en_lista_blanca": True,
            "ficheros": sum(g["lista_blanca"]["si"] for g in gs),
            "bytes_fisicos": sum(g["lista_blanca"]["bytes_si"] for g in gs),
            "requiere": ["autorización escrita del usuario para esta regla",
                         "clave HMAC en el Llavero (`mac-cleaner clave crear`)",
                         "cambio de código revisado que sustituya LIMPIEZA_REAL_HABILITADA por esta lista blanca",
                         "una semana de ejecuciones en sombra sin sorpresas"],
        })
    fuera = {}
    for g in lista:
        if g["lista_blanca"]["no"]:
            f = fuera.setdefault(g["regla"], {"ficheros": 0, "bytes_fisicos": 0, "grupos": []})
            f["ficheros"] += g["lista_blanca"]["no"]
            f["bytes_fisicos"] += g["lista_blanca"]["bytes_no"]
            f["grupos"].append(g["grupo"])
    for rid, f in fuera.items():
        operaciones.append({
            "regla": rid, "operacion": "mover a cuarentena (reversible)", "en_lista_blanca": False,
            "ficheros": f["ficheros"], "bytes_fisicos": f["bytes_fisicos"], "grupos": f["grupos"][:20],
            "requiere": ["ampliar la lista blanca con una decisión escrita (fuera del alcance inicial: solo npm y pip)"],
        })

    doc = {
        "tipo": "mac-cleaner-sombra", "version": VERSION_SOMBRA,
        "generado": dt.datetime.fromtimestamp(ahora).isoformat(timespec="seconds"), "ahora": ahora,
        "limpieza_real_habilitada": zona_mod.LIMPIEZA_REAL_HABILITADA,
        "escaneo": {"generado": escaneo.get("generado"), "ahora": escaneo.get("ahora"), "zona": escaneo.get("zona")},
        "config_sha256": plan["config_sha256"],
        "lista_blanca": {"subarboles": subs, "rechazos": rechazos_raiz},
        "candidatos": {"totales": tot, "grupos": lista},
        "exclusiones": {"escaneo": escaneo["escaneo"].get("exclusiones", {}).get("por_motivo", {}),
                        "revalidacion": excl_reval, "n_revalidacion": plan["n_excluidos"],
                        "muestra_revalidacion": plan["excluidos"][:50]},
        "recuperable": {"lista_blanca_bytes": tot["lista_blanca_bytes"], "total_candidatos_bytes": tot["bytes_fisicos"],
                        "nota": "estimación física; no garantizada (clones, snapshots, regeneración)"},
        "riesgos": riesgos,
        "operaciones_que_requieren_autorizacion": operaciones,
    }
    doc["cambios"] = comparar(anterior, doc) if anterior else {"disponible": False,
                                                                "motivo": "no hay ejecución en sombra anterior"}
    return doc


def comparar(anterior: dict, actual: dict) -> dict:
    """Cambios por grupo y en totales respecto a una ejecución en sombra anterior."""
    if anterior.get("tipo") != "mac-cleaner-sombra":
        return {"disponible": False, "motivo": "el fichero anterior no es una ejecución en sombra"}
    a = {f"{g['regla']}:{g['grupo']}": g for g in anterior["candidatos"]["grupos"]}
    b = {f"{g['regla']}:{g['grupo']}": g for g in actual["candidatos"]["grupos"]}
    nuevos = sorted(set(b) - set(a))
    desaparecidos = sorted(set(a) - set(b))
    cambiados = []
    for k in sorted(set(a) & set(b)):
        da = b[k]["bytes_fisicos"] - a[k]["bytes_fisicos"]
        df = b[k]["ficheros"] - a[k]["ficheros"]
        lb = b[k]["lista_blanca"]["si"] - a[k]["lista_blanca"]["si"]
        if da or df or lb:
            cambiados.append({"grupo": k, "delta_bytes": da, "delta_ficheros": df, "delta_lista_blanca": lb})
    ta, tb = anterior["candidatos"]["totales"], actual["candidatos"]["totales"]
    return {
        "disponible": True, "anterior": anterior.get("generado"),
        "config_cambiada": anterior.get("config_sha256") != actual.get("config_sha256"),
        "nuevos": [{"grupo": k, "bytes": b[k]["bytes_fisicos"], "ficheros": b[k]["ficheros"]} for k in nuevos],
        "desaparecidos": [{"grupo": k, "bytes": a[k]["bytes_fisicos"], "ficheros": a[k]["ficheros"]} for k in desaparecidos],
        "cambiados": cambiados,
        "delta_totales": {k: tb.get(k, 0) - ta.get(k, 0) for k in tb},
    }


def _h(n: int) -> str:
    from .informe import humano
    return humano(n)


def markdown(d: dict) -> str:
    L = []
    w = L.append
    t = d["candidatos"]["totales"]
    w("# mac-cleaner · ejecución en sombra (F3: no se mueve ni se borra nada)\n")
    w(f"- Generado: {d['generado']} · escaneo de {d['escaneo']['generado']}" + (f" · zona sintética `{d['escaneo']['zona']}`" if d['escaneo']['zona'] else ""))
    w(f"- Limpieza real habilitada: **{'sí' if d['limpieza_real_habilitada'] else 'no'}**\n")
    w("## Resumen\n")
    w(f"- Candidatos: {t['ficheros']:,} ficheros, {_h(t['bytes_fisicos'])} físicos")
    w(f"- Cubiertos por la lista blanca (npm/pip): {t['lista_blanca_ficheros']:,} ficheros, **{_h(t['lista_blanca_bytes'])}**")
    w(f"- Fuera de la lista blanca: {t['fuera_lista_ficheros']:,} ficheros, {_h(t['fuera_lista_bytes'])}")
    w(f"- Recuperable estimado (solo lista blanca): {_h(d['recuperable']['lista_blanca_bytes'])} — {d['recuperable']['nota']}\n")
    w("## Candidatos por grupo\n")
    w("| Regla | Grupo | Riesgo | Ficheros | Físico | En lista blanca | Fuera (motivo) |")
    w("|---|---|---|---:|---:|---:|---|")
    for g in d["candidatos"]["grupos"][:60]:
        mot = "; ".join(f"{m} ({n})" for m, n in g["motivos_no"].items()) or "—"
        w(f"| `{g['regla']}` | `{g['grupo']}` | {g['riesgo']} | {g['ficheros']:,} | {_h(g['bytes_fisicos'])} | "
          f"{_h(g['lista_blanca']['bytes_si'])} | {mot} |")
    w("\n## Operaciones que requerirían autorización\n")
    for o in d["operaciones_que_requieren_autorizacion"]:
        w(f"- **{o['regla']}** ({'lista blanca' if o['en_lista_blanca'] else 'fuera de la lista blanca'}): {o['operacion']} — "
          f"{o['ficheros']:,} ficheros, {_h(o['bytes_fisicos'])}. Requiere: {'; '.join(o['requiere'])}.")
    w("\n## Exclusiones\n")
    for m, n in sorted(d["exclusiones"]["revalidacion"].items(), key=lambda x: -x[1]):
        w(f"- (revalidación) {m}: {n}")
    for m, n in sorted(d["exclusiones"]["escaneo"].items(), key=lambda x: -x[1])[:30]:
        w(f"- (escaneo) {m}: {n}")
    w("\n## Riesgos\n")
    for r in d["riesgos"]:
        w(f"- {r}")
    w("\n## Cambios respecto a la ejecución anterior\n")
    c = d["cambios"]
    if not c.get("disponible"):
        w(f"- {c.get('motivo')}")
    else:
        w(f"- Anterior: {c['anterior']} · configuración cambiada: {'sí' if c['config_cambiada'] else 'no'}")
        w(f"- Totales: " + ", ".join(f"{k} {v:+,}" for k, v in c["delta_totales"].items()))
        for x in c["nuevos"][:20]:
            w(f"- Nuevo: `{x['grupo']}` ({_h(x['bytes'])})")
        for x in c["desaparecidos"][:20]:
            w(f"- Desaparecido: `{x['grupo']}` ({_h(x['bytes'])})")
        for x in c["cambiados"][:30]:
            w(f"- Cambiado: `{x['grupo']}` {x['delta_bytes']:+,} B, {x['delta_ficheros']:+,} ficheros")
    return "\n".join(L) + "\n"


def ultimo(directorio: str) -> str | None:
    import glob
    c = sorted(glob.glob(os.path.join(directorio, "sombra-*.json")))
    return c[-1] if c else None
