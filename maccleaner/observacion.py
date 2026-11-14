"""F4A: observación de 7 días del modo sombra (procedimiento manual, sin tareas programadas).

* `mac-cleaner sombra --observacion` ejecuta una sombra REAL y la anota en `<salida>/observacion/registro.jsonl`
  (fecha local, huellas, totales, verificaciones). Nada se programa ni queda residente: el usuario la lanza a mano
  una vez al día.
* `mac-cleaner observacion` resume lo registrado: una fila por día (la última ejecución del día), diferencias entre
  días, verificaciones bloqueantes y avisos, y si se cumplen las condiciones objetivas para proponer F4B.
Solo cuenta ejecuciones registradas de verdad: no extrapola ni simula días futuros.
"""
from __future__ import annotations

import datetime as dt
import json
import os

DIAS_REQUERIDOS = 7
VARIACION_AVISO = 0.5          # ±50 % de bytes admitidos entre dos días consecutivos → revisar


def _registro(salida: str) -> str:
    return os.path.join(salida, "observacion", "registro.jsonl")


def registrar(salida: str, doc: dict, ruta_sombra: str) -> dict:
    os.makedirs(os.path.join(salida, "observacion"), exist_ok=True)
    t = doc["candidatos"]["totales"]
    reg = {
        "fecha": dt.datetime.fromtimestamp(doc["ahora"]).date().isoformat(), "t": doc["ahora"],
        "sombra": ruta_sombra, "huella_informe": doc["huella_informe"], "lista_sha256": doc["candidatos"]["lista_sha256"],
        "config_sha256": doc["config_sha256"], "zona": doc["escaneo"]["zona"],
        "lista_blanca_ficheros": t["lista_blanca_ficheros"], "lista_blanca_bytes": t["lista_blanca_bytes"],
        "candidatos_ficheros": t["ficheros"], "bloqueantes": doc["verificaciones"]["bloqueantes"],
        "modificados_24h": doc["abiertos_y_modificados"]["modificados_24h"],
        "abiertos_bajo_lista_blanca": doc["abiertos_y_modificados"]["abiertos_bajo_lista_blanca"],
        "guardia_bloqueos": len(doc.get("guardia", {}).get("bloqueos", [])),
        "limpieza_real_habilitada": doc["limpieza_real_habilitada"],
        "cambios_candidatos": doc.get("cambios", {}).get("candidatos"),
    }
    with open(_registro(salida), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(reg, ensure_ascii=False, sort_keys=True) + "\n")
    return reg


def cargar(salida: str) -> list[dict]:
    try:
        with open(_registro(salida), encoding="utf-8") as fh:
            return [json.loads(x) for x in fh if x.strip()]
    except OSError:
        return []


def resumen(salida: str, incluir_sinteticas: bool = False) -> dict:
    """incluir_sinteticas=True solo para pruebas: una observación válida es siempre sobre el Mac real."""
    regs = cargar(salida)
    reales = [r for r in regs if incluir_sinteticas or not r.get("zona")]
    por_dia: dict[str, dict] = {}
    for r in sorted(reales, key=lambda r: r["t"]):
        por_dia[r["fecha"]] = r                         # la última ejecución de cada día
    dias = [por_dia[k] for k in sorted(por_dia)]
    filas, avisos, bloqueos = [], [], []
    for i, r in enumerate(dias):
        prev = dias[i - 1] if i else None
        delta = r["lista_blanca_bytes"] - prev["lista_blanca_bytes"] if prev else None
        filas.append({"dia": i + 1, "fecha": r["fecha"], "lista_blanca_ficheros": r["lista_blanca_ficheros"],
                      "lista_blanca_bytes": r["lista_blanca_bytes"], "delta_bytes": delta,
                      "bloqueantes": r["bloqueantes"], "modificados_24h": r["modificados_24h"],
                      "abiertos": r["abiertos_bajo_lista_blanca"], "huella": r["huella_informe"][:12],
                      "cambios_candidatos": r.get("cambios_candidatos")})
        if r["bloqueantes"]:
            bloqueos.append(f"{r['fecha']}: {r['bloqueantes']} verificaciones bloqueantes (ver su informe de sombra)")
        if r["guardia_bloqueos"]:
            bloqueos.append(f"{r['fecha']}: la guardia bloqueó {r['guardia_bloqueos']} operaciones")
        if r["limpieza_real_habilitada"]:
            bloqueos.append(f"{r['fecha']}: la limpieza real figuraba habilitada")
        if prev and prev["config_sha256"] != r["config_sha256"]:
            bloqueos.append(f"{r['fecha']}: la configuración cambió respecto al día anterior (reinicia o justifica)")
        if prev and prev["lista_blanca_bytes"] and abs(delta) > VARIACION_AVISO * prev["lista_blanca_bytes"]:
            avisos.append(f"{r['fecha']}: los bytes admitidos variaron {delta:+,} B (> {VARIACION_AVISO:.0%}): revisar")
        if r["modificados_24h"]:
            avisos.append(f"{r['fecha']}: {r['modificados_24h']} ficheros admitidos modificados en las últimas 24 h "
                          "(caché en uso: apply los volvería a comprobar)")
        if r["abiertos_bajo_lista_blanca"]:
            avisos.append(f"{r['fecha']}: {r['abiertos_bajo_lista_blanca']} ficheros abiertos bajo la lista blanca")
    motivos = []
    if len(dias) < DIAS_REQUERIDOS:
        motivos.append(f"faltan observaciones: {len(dias)} de {DIAS_REQUERIDOS} días distintos")
    elif (dt.date.fromisoformat(dias[-1]["fecha"]) - dt.date.fromisoformat(dias[0]["fecha"])).days < DIAS_REQUERIDOS - 1:
        motivos.append("las observaciones no abarcan 7 días naturales")
    motivos += bloqueos
    return {"tipo": "mac-cleaner-observacion", "dias_observados": len(dias), "dias_requeridos": DIAS_REQUERIDOS,
            "ejecuciones_registradas": len(reales), "ejecuciones_sinteticas_ignoradas": len(regs) - len(reales),
            "filas": filas, "avisos": avisos, "bloqueos": bloqueos,
            "criterios_objetivos_cumplidos": not motivos, "motivos": motivos,
            "nota": "Cumplir los criterios objetivos NO autoriza F4B: hace falta además la revisión humana de los 7 "
                    "informes y la autorización escrita (docs/F4.md)."}


def markdown(r: dict) -> str:
    from .informe import humano
    L = ["# mac-cleaner · observación en sombra\n",
         f"- Días observados: **{r['dias_observados']} de {r['dias_requeridos']}** "
         f"({r['ejecuciones_registradas']} ejecuciones reales; {r['ejecuciones_sinteticas_ignoradas']} sintéticas ignoradas)",
         f"- Criterios objetivos para proponer F4B: **{'cumplidos' if r['criterios_objetivos_cumplidos'] else 'no cumplidos'}**",
         f"- {r['nota']}\n", "| Día | Fecha | Admitidos | Bytes | Δ bytes | Bloqueantes | Mod. 24 h | Abiertos | Huella |",
         "|---:|---|---:|---:|---:|---:|---:|---:|---|"]
    for f in r["filas"]:
        d = "—" if f["delta_bytes"] is None else f"{f['delta_bytes']:+,}"
        L.append(f"| {f['dia']} | {f['fecha']} | {f['lista_blanca_ficheros']:,} | {humano(f['lista_blanca_bytes'])} | {d} | "
                 f"{f['bloqueantes']} | {f['modificados_24h']} | {f['abiertos']} | `{f['huella']}` |")
    for titulo, xs in (("Motivos", r["motivos"]), ("Avisos", r["avisos"])):
        L.append(f"\n## {titulo}\n")
        L += [f"- {x}" for x in xs] or ["- ninguno"]
    return "\n".join(L) + "\n"
