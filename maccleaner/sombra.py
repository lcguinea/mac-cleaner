"""Ejecución en sombra (F3; criterios del motor real en F4A). Evalúa qué se limpiaría, sin mover ni borrar nada.

Usa EXACTAMENTE los criterios que aplicaría el futuro motor: escaneo reciente (≤ 24 h), revalidación de los grupos
con las protecciones de F1 y lsof, antigüedad, riesgo (`[[ajuste_riesgo]]`) y la lista blanca OFICIAL (no se
puede sustituir desde la CLI). El informe incluye:
  * rutas candidatas (lista completa de lo admitido por la lista blanca en un fichero aparte, y muestras);
  * riesgo y justificación por grupo;
  * espacio potencialmente recuperable;
  * exclusiones y motivos;
  * cambios respecto a la sombra anterior (por grupo y por fichero candidato);
  * estado de ficheros abiertos o modificados;
  * autorizaciones que serían necesarias;
  * operaciones que no podrían restaurarse con seguridad;
  * verificaciones automáticas (detectores de falsos positivos) y una huella reproducible del informe.
Nunca produce un plan aplicable: sin MAC y con la limpieza real deshabilitada en el código.
"""
from __future__ import annotations

import datetime as dt
import glob
import hashlib
import json
import os
import re
import time

from . import listablanca, zona as zona_mod
from .config import Config
from .escaner import DIA, riesgo_de
from .plan import crear_plan
from .sistema import FicherosAbiertos

VERSION_SOMBRA = 2
MUESTRA = 5
GRUPOS_ESPERADOS = {"npm:_cacache", "pip:http-v2", "pip:http", "homebrew:downloads"}
# F5B: en estas reglas cualquier grupo puede entrar (raíz entera), salvo los excluidos por la lista blanca.
REGLAS_RAIZ_ENTERA = {r for r, e in listablanca.LISTA_BLANCA.items() if e["subdirectorios"] == (".",)}
_VOLATILES = ("generado", "ahora", "cambios", "guardia", "huella_informe", "observacion")


def _canon(d) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def huella_informe(doc: dict) -> str:
    """SHA-256 del informe sin los campos que dependen del momento: dos sombras del mismo estado coinciden."""
    return hashlib.sha256(_canon({k: v for k, v in doc.items() if k not in _VOLATILES})).hexdigest()


def evaluar(escaneo: dict, cfg: Config, *, abiertos: FicherosAbiertos, ahora: float | None = None,
            anterior: dict | None = None, candidatos_anteriores: list | None = None) -> tuple[dict, list]:
    """Devuelve (informe, lista ordenada de candidatos de la lista blanca: [ruta, tam, bloques, mtime_ns])."""
    ahora = ahora or time.time()
    lb = listablanca.OFICIAL
    zona = escaneo.get("zona")
    plan = crear_plan(escaneo, cfg, abiertos=abiertos, ahora=ahora, calcular_hash=False, firmar=False,
                      lista_blanca=lb, filtrar=False)
    subs = plan["lista_blanca"]["subarboles"]
    reglas = {r.id: r for r in cfg.reglas}
    dev_cuarentena = os.stat(zona if zona else cfg.home).st_dev   # la cuarentena real iría en ~/.mac-cleaner

    grupos: dict[str, dict] = {}
    lista: list[list] = []
    abiertos_mod = {"modificados_24h": 0, "modificados_desde_escaneo": 0}
    no_rest = {"sin_sha256": {"ficheros": 0, "bytes_fisicos": 0}, "otro_volumen": 0}
    for e in sorted(plan["elementos"], key=lambda x: x["ruta"]):
        ok = e.get("lista_blanca") is not None
        motivo = e["lista_blanca"] if ok else lb.clasificar(e["regla"], e["ruta"], subs)[1]
        clave = f"{e['regla']}:{e['grupo']}"
        if clave not in grupos:
            r = reglas.get(e["regla"])
            riesgo, motivo_riesgo = riesgo_de(cfg, r, e["grupo"]) if r else (e["riesgo"], "")
            grupos[clave] = {"regla": e["regla"], "grupo": e["grupo"], "riesgo": riesgo, "motivo_riesgo": motivo_riesgo,
                             "ficheros": 0, "bytes_fisicos": 0, "bytes_logicos": 0,
                             "lista_blanca": {"si": 0, "no": 0, "bytes_si": 0, "bytes_no": 0},
                             "justificacion": None, "motivos_no": {}, "muestra": []}
        g = grupos[clave]
        b = e["bloques"] * 512
        g["ficheros"] += 1
        g["bytes_fisicos"] += b
        g["bytes_logicos"] += e["tam"]
        if ok:
            g["lista_blanca"]["si"] += 1
            g["lista_blanca"]["bytes_si"] += b
            g["justificacion"] = f"lista blanca oficial ({motivo}); caché regenerable por su herramienta"
            lista.append([e["ruta"], e["tam"], e["bloques"], e["mtime_ns"]])
            ref = max(e["mtime_ns"] / 1e9, e.get("birthtime") or 0)
            if ref > ahora - DIA:
                abiertos_mod["modificados_24h"] += 1
            if e["mtime_ns"] / 1e9 > float(escaneo.get("ahora", 0)):
                abiertos_mod["modificados_desde_escaneo"] += 1
            if e["tam"] > cfg.hash_max_bytes:
                no_rest["sin_sha256"]["ficheros"] += 1
                no_rest["sin_sha256"]["bytes_fisicos"] += b
            if e["dev"] != dev_cuarentena:
                no_rest["otro_volumen"] += 1
        else:
            g["lista_blanca"]["no"] += 1
            g["lista_blanca"]["bytes_no"] += b
            g["motivos_no"][motivo] = g["motivos_no"].get(motivo, 0) + 1
        if len(g["muestra"]) < MUESTRA:
            g["muestra"].append(e["ruta"])

    orden = sorted(grupos.values(), key=lambda g: (-g["bytes_fisicos"], g["regla"], g["grupo"]))
    for g in orden:
        if g["justificacion"] is None:
            g["justificacion"] = "no admitido por la lista blanca oficial: " + "; ".join(sorted(g["motivos_no"]))
    tot = {
        "ficheros": sum(g["ficheros"] for g in orden),
        "bytes_fisicos": sum(g["bytes_fisicos"] for g in orden),
        "lista_blanca_ficheros": sum(g["lista_blanca"]["si"] for g in orden),
        "lista_blanca_bytes": sum(g["lista_blanca"]["bytes_si"] for g in orden),
        "fuera_lista_ficheros": sum(g["lista_blanca"]["no"] for g in orden),
        "fuera_lista_bytes": sum(g["lista_blanca"]["bytes_no"] for g in orden),
    }

    excl_reval: dict[str, int] = {}
    for x in plan["excluidos"]:
        excl_reval[x["motivo"]] = excl_reval.get(x["motivo"], 0) + 1
    abiertos_mod.update({
        "lsof_disponible": abiertos.disponible,
        "abiertos_bajo_lista_blanca": sum(abiertos.contar_bajo(s) for ss in subs.values() for s in ss),
        "grupos_excluidos_en_uso": sorted({x["ruta"] for x in plan["excluidos"] if x["motivo"].startswith("en uso")}),
        "grupos_excluidos_activos": sorted({x["ruta"] for x in plan["excluidos"] if x["motivo"].startswith("activo")}),
        "nota": "apply volvería a comprobar lsof, tamaño, mtime, ctime e inodo de cada fichero justo antes de moverlo",
    })
    no_rest.update({
        "enlaces_duros": sum(1 for x in plan["excluidos"] if "enlace duro" in x["motivo"]),
        "umbral_sha256_bytes": cfg.hash_max_bytes,
        "notas": [
            "sin_sha256: ficheros mayores que hash_max_mb; restore los verificaría solo por inodo, metadatos y ctime.",
            "otro_volumen: apply los omitiría (la cuarentena debe estar en el mismo volumen; nunca se copia).",
            "npm y pip pueden borrar o recrear directorios de su caché: restaurar a un directorio desaparecido da un "
            "conflicto explícito y el fichero sigue en cuarentena (recuperable a mano).",
        ],
    })

    riesgos = [
        "La limpieza real está DESHABILITADA en el código (zona.LIMPIEZA_REAL_HABILITADA = False): nada de esto se ejecuta.",
        "Ocupado ≠ recuperable: clones de APFS y snapshots locales pueden impedir liberar espacio; las cachés se regeneran.",
        "Instantánea única de lsof: un fichero abierto después de la evaluación no se detecta (apply volvería a mirar).",
    ]
    if escaneo.get("snapshots", {}).get("snapshots"):
        riesgos.append(f"Hay {len(escaneo['snapshots']['snapshots'])} snapshots locales: el espacio no se liberaría hasta que caduquen.")
    for r in plan["lista_blanca"]["rechazos"]:
        riesgos.append(f"Lista blanca no aplicable a «{r['regla']}»: {r['motivo']}.")

    lb_grupos = [f"{g['regla']}:{g['grupo']}" for g in orden if g["lista_blanca"]["si"]]
    prot = cfg.proteccion
    excluidos_lb = {}
    for g in orden:
        patron = listablanca.LISTA_BLANCA.get(g["regla"], {}).get("excluir_grupos")
        if g["lista_blanca"]["si"] and patron and re.search(patron, g["grupo"], re.IGNORECASE):
            excluidos_lb[f"{g['regla']}:{g['grupo']}"] = g["lista_blanca"]["si"]
    verificaciones = {
        "grupos_lista_blanca_inesperados": sorted(k for k in set(lb_grupos) - GRUPOS_ESPERADOS
                                                  if k.split(":", 1)[0] not in REGLAS_RAIZ_ENTERA),
        "grupos_excluidos_admitidos": sorted(excluidos_lb),
        "candidatos_con_proteccion": [r for r, *_ in lista if prot.motivo_ruta(r) or prot.motivo_nombre(os.path.basename(r), False)][:20],
        "candidatos_con_componente_prohibido": [r for r, *_ in lista if any(
            listablanca.COMPONENTES_PROHIBIDOS.match(c) for c in r.split("/"))][:20],
        "rechazos_raiz": plan["lista_blanca"]["rechazos"],
        "limpieza_real_habilitada": zona_mod.LIMPIEZA_REAL_HABILITADA,
    }
    verificaciones["bloqueantes"] = sum(len(verificaciones[k]) for k in (
        "grupos_lista_blanca_inesperados", "grupos_excluidos_admitidos", "candidatos_con_proteccion", "candidatos_con_componente_prohibido",
        "rechazos_raiz")) + int(verificaciones["limpieza_real_habilitada"])

    operaciones = []
    for rid, ent in listablanca.LISTA_BLANCA.items():
        gs = [g for g in orden if g["regla"] == rid and g["lista_blanca"]["si"]]
        operaciones.append({
            "regla": rid, "operacion": ent["operacion"], "en_lista_blanca": True,
            "ficheros": sum(g["lista_blanca"]["si"] for g in gs),
            "bytes_fisicos": sum(g["lista_blanca"]["bytes_si"] for g in gs),
            "requiere": ["regla en autorizacion.REGLAS (autorización escrita vigente)",
                         "clave HMAC en el Llavero y confirmación en el diálogo de macOS",
                         "confirmación del usuario en la app (tope de bytes que vio)"],
        })
    fuera: dict[str, dict] = {}
    for g in orden:
        if g["lista_blanca"]["no"]:
            f = fuera.setdefault(g["regla"], {"ficheros": 0, "bytes_fisicos": 0, "grupos": []})
            f["ficheros"] += g["lista_blanca"]["no"]
            f["bytes_fisicos"] += g["lista_blanca"]["bytes_no"]
            f["grupos"].append(g["grupo"])
    for rid in sorted(fuera):
        f = fuera[rid]
        operaciones.append({"regla": rid, "operacion": "ninguna: fuera de la lista blanca", "en_lista_blanca": False,
                            "ficheros": f["ficheros"], "bytes_fisicos": f["bytes_fisicos"], "grupos": f["grupos"][:20],
                            "requiere": ["ampliar la lista blanca con un cambio de código y una decisión escrita"]})

    doc = {
        "tipo": "mac-cleaner-sombra", "version": VERSION_SOMBRA,
        "generado": dt.datetime.fromtimestamp(ahora).isoformat(timespec="seconds"), "ahora": ahora,
        "limpieza_real_habilitada": zona_mod.LIMPIEZA_REAL_HABILITADA,
        "escaneo": {"generado": escaneo.get("generado"), "ahora": escaneo.get("ahora"), "zona": zona},
        "config_sha256": plan["config_sha256"],
        "lista_blanca": {"nombre": lb.nombre, "subarboles": subs, "rechazos": plan["lista_blanca"]["rechazos"]},
        "candidatos": {"totales": tot, "grupos": orden, "n_lista": len(lista),
                       "lista_sha256": hashlib.sha256(_canon(lista)).hexdigest()},
        "exclusiones": {"escaneo": dict(sorted(escaneo["escaneo"].get("exclusiones", {}).get("por_motivo", {}).items())),
                        "revalidacion": dict(sorted(excl_reval.items())), "n_revalidacion": plan["n_excluidos"],
                        "muestra_revalidacion": plan["excluidos"][:50]},
        "recuperable": {"lista_blanca_bytes": tot["lista_blanca_bytes"], "total_candidatos_bytes": tot["bytes_fisicos"],
                        "nota": "estimación física; no garantizada (clones, snapshots, regeneración)"},
        "abiertos_y_modificados": abiertos_mod,
        "no_restaurables_con_seguridad": no_rest,
        "riesgos": riesgos,
        "verificaciones": verificaciones,
        "operaciones_que_requieren_autorizacion": operaciones,
    }
    doc["huella_informe"] = huella_informe(doc)
    cambios = comparar(anterior, doc) if anterior else {"disponible": False, "motivo": "no hay ejecución en sombra anterior"}
    if anterior and candidatos_anteriores is not None:
        cambios["candidatos"] = comparar_candidatos(candidatos_anteriores, lista)
    doc["cambios"] = cambios
    return doc, lista


def comparar(anterior: dict, actual: dict) -> dict:
    """Cambios por grupo y en totales respecto a una ejecución en sombra anterior."""
    if anterior.get("tipo") != "mac-cleaner-sombra":
        return {"disponible": False, "motivo": "el fichero anterior no es una ejecución en sombra"}
    a = {f"{g['regla']}:{g['grupo']}": g for g in anterior["candidatos"]["grupos"]}
    b = {f"{g['regla']}:{g['grupo']}": g for g in actual["candidatos"]["grupos"]}
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
        "nuevos": [{"grupo": k, "bytes": b[k]["bytes_fisicos"], "ficheros": b[k]["ficheros"]} for k in sorted(set(b) - set(a))],
        "desaparecidos": [{"grupo": k, "bytes": a[k]["bytes_fisicos"], "ficheros": a[k]["ficheros"]} for k in sorted(set(a) - set(b))],
        "cambiados": cambiados,
        "delta_totales": {k: tb.get(k, 0) - ta.get(k, 0) for k in tb},
    }


def comparar_candidatos(anteriores: list, actuales: list) -> dict:
    """Diferencias fichero a fichero entre dos listas de candidatos de la lista blanca."""
    a = {x[0]: tuple(x[1:]) for x in anteriores}
    b = {x[0]: tuple(x[1:]) for x in actuales}
    anadidos = sorted(set(b) - set(a))
    retirados = sorted(set(a) - set(b))
    modificados = sorted(k for k in set(a) & set(b) if a[k] != b[k])
    return {"anadidos": len(anadidos), "retirados": len(retirados), "modificados": len(modificados),
            "sin_cambios": len(set(a) & set(b)) - len(modificados),
            "muestra_anadidos": anadidos[:10], "muestra_retirados": retirados[:10], "muestra_modificados": modificados[:10]}


def guardar_candidatos(ruta: str, lista: list) -> None:
    with open(ruta, "w", encoding="utf-8") as fh:
        for x in lista:
            fh.write(json.dumps(x, ensure_ascii=False) + "\n")


def cargar_candidatos(ruta_sombra: str) -> list | None:
    ruta = ruta_sombra[:-5] + "-candidatos.jsonl"
    try:
        with open(ruta, encoding="utf-8") as fh:
            return [json.loads(x) for x in fh if x.strip()]
    except OSError:
        return None


def _h(n: int) -> str:
    from .informe import humano
    return humano(n)


def markdown(d: dict) -> str:
    L = []
    w = L.append
    t = d["candidatos"]["totales"]
    w("# mac-cleaner · ejecución en sombra (no se mueve ni se borra nada)\n")
    w(f"- Generado: {d['generado']} · escaneo de {d['escaneo']['generado']}" + (f" · zona sintética `{d['escaneo']['zona']}`" if d['escaneo']['zona'] else ""))
    w(f"- Limpieza real habilitada: **{'sí' if d['limpieza_real_habilitada'] else 'no'}** · lista blanca: {d['lista_blanca']['nombre']}")
    w(f"- Huella del informe: `{d['huella_informe'][:16]}` · candidatos: `{d['candidatos']['lista_sha256'][:16]}`")
    v = d["verificaciones"]
    w(f"- Verificaciones bloqueantes: **{v['bloqueantes']}**" + (" (revisar antes de seguir)" if v["bloqueantes"] else "") + "\n")
    w("## Resumen\n")
    w(f"- Candidatos revalidados: {t['ficheros']:,} ficheros, {_h(t['bytes_fisicos'])} físicos")
    w(f"- Admitidos por la lista blanca (npm/pip): {t['lista_blanca_ficheros']:,} ficheros, **{_h(t['lista_blanca_bytes'])}**")
    w(f"- No admitidos: {t['fuera_lista_ficheros']:,} ficheros, {_h(t['fuera_lista_bytes'])}")
    w(f"- Recuperable estimado (solo lista blanca): {_h(d['recuperable']['lista_blanca_bytes'])} — {d['recuperable']['nota']}\n")
    w("## Candidatos, riesgo y justificación\n")
    w("| Regla | Grupo | Riesgo | Motivo del riesgo | Ficheros | Físico | Lista blanca | Justificación |")
    w("|---|---|---|---|---:|---:|---:|---|")
    for g in d["candidatos"]["grupos"][:60]:
        w(f"| `{g['regla']}` | `{g['grupo']}` | {g['riesgo']} | {g['motivo_riesgo']} | {g['ficheros']:,} | "
          f"{_h(g['bytes_fisicos'])} | {_h(g['lista_blanca']['bytes_si'])} | {g['justificacion']} |")
    w(f"\nLista completa de rutas admitidas: fichero `*-candidatos.jsonl` junto a este informe ({d['candidatos']['n_lista']:,} rutas).")
    am = d["abiertos_y_modificados"]
    w("\n## Ficheros abiertos o modificados\n")
    w(f"- lsof disponible: {'sí' if am['lsof_disponible'] else 'no'}; abiertos bajo la lista blanca: {am['abiertos_bajo_lista_blanca']}")
    w(f"- Admitidos modificados en las últimas 24 h: {am['modificados_24h']}; después del escaneo: {am['modificados_desde_escaneo']}")
    for k, titulo in (("grupos_excluidos_en_uso", "Grupos excluidos por estar en uso"), ("grupos_excluidos_activos", "Grupos excluidos por actividad reciente")):
        for x in am[k][:20]:
            w(f"- {titulo}: `{x}`")
    w(f"- {am['nota']}")
    nr = d["no_restaurables_con_seguridad"]
    w("\n## Operaciones que no podrían restaurarse con seguridad\n")
    w(f"- Sin SHA-256 (> {_h(nr['umbral_sha256_bytes'])}): {nr['sin_sha256']['ficheros']} ficheros, {_h(nr['sin_sha256']['bytes_fisicos'])}")
    w(f"- En otro volumen que la cuarentena: {nr['otro_volumen']} · enlaces duros excluidos: {nr['enlaces_duros']}")
    for n in nr["notas"]:
        w(f"- {n}")
    w("\n## Autorizaciones que serían necesarias\n")
    for o in d["operaciones_que_requieren_autorizacion"]:
        w(f"- **{o['regla']}** ({'lista blanca' if o['en_lista_blanca'] else 'fuera de la lista blanca'}): {o['operacion']} — "
          f"{o['ficheros']:,} ficheros, {_h(o['bytes_fisicos'])}. Requiere: {'; '.join(o['requiere'])}.")
    w("\n## Exclusiones\n")
    for m, n in sorted(d["exclusiones"]["revalidacion"].items(), key=lambda x: (-x[1], x[0]))[:40]:
        w(f"- (revalidación) {m}: {n}")
    for m, n in sorted(d["exclusiones"]["escaneo"].items(), key=lambda x: (-x[1], x[0]))[:30]:
        w(f"- (escaneo) {m}: {n}")
    w("\n## Verificaciones automáticas (falsos positivos)\n")
    for k in ("grupos_lista_blanca_inesperados", "grupos_excluidos_admitidos", "candidatos_con_proteccion",
              "candidatos_con_componente_prohibido", "rechazos_raiz"):
        w(f"- {k}: {len(v[k])}" + (f" → {v[k][:5]}" if v[k] else ""))
    w("\n## Riesgos\n")
    for r in d["riesgos"]:
        w(f"- {r}")
    w("\n## Cambios respecto a la ejecución anterior\n")
    c = d["cambios"]
    if not c.get("disponible"):
        w(f"- {c.get('motivo')}")
    else:
        w(f"- Anterior: {c['anterior']} · configuración cambiada: {'sí' if c['config_cambiada'] else 'no'}")
        w("- Totales: " + ", ".join(f"{k} {v:+,}" for k, v in c["delta_totales"].items()))
        if "candidatos" in c:
            cc = c["candidatos"]
            w(f"- Candidatos: +{cc['anadidos']:,} añadidos, −{cc['retirados']:,} retirados, {cc['modificados']:,} modificados, {cc['sin_cambios']:,} iguales")
        for x in c["nuevos"][:20]:
            w(f"- Grupo nuevo: `{x['grupo']}` ({_h(x['bytes'])})")
        for x in c["desaparecidos"][:20]:
            w(f"- Grupo desaparecido: `{x['grupo']}` ({_h(x['bytes'])})")
        for x in c["cambiados"][:30]:
            w(f"- Cambiado: `{x['grupo']}` {x['delta_bytes']:+,} B, {x['delta_ficheros']:+,} ficheros")
    return "\n".join(L) + "\n"


def ultimo(directorio: str) -> str | None:
    c = sorted(x for x in glob.glob(os.path.join(directorio, "sombra-*.json")))
    return c[-1] if c else None
