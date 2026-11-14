"""Convierte el JSON de `scan` en un informe Markdown legible."""
from __future__ import annotations

import datetime as dt
import time


def humano(n: float | int | None) -> str:
    if n is None:
        return "—"
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1000 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1000
    return f"{n:.1f} TB"


def fecha(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d") if ts else "—"


def dias(ahora: float, ts: float) -> str:
    return f"{max(0.0, (ahora - ts) / 86400):.0f} d" if ts else "—"


def generar(d: dict) -> str:
    ahora = d.get("ahora", time.time())
    L = []
    w = L.append
    w(f"# mac-cleaner · informe de escaneo (F1, solo lectura)\n")
    w(f"- Generado: {d['generado']} · duración {d['escaneo']['duracion_s']} s · macOS {d.get('macos', '?')}")
    w(f"- Configuración: `{d['config']}` · prioridad: {', '.join(d.get('prioridad') or ['normal'])}")
    lsof = d.get("lsof", {})
    w(f"- Ficheros abiertos (lsof): {'%d rutas' % lsof.get('n', 0) if lsof.get('disponible') else 'no disponible — ' + str(lsof.get('error'))}")
    di = d.get("disco", {})
    if di:
        w(f"- Disco `{di['volumen']}`: {humano(di['usado'])} usados de {humano(di['total'])}; libres {humano(di['libre'])} ({100 * di['libre'] / di['total']:.0f} %)")
    sn = d.get("snapshots", {})
    if sn.get("disponible"):
        w(f"- Snapshots locales de APFS: {len(sn['snapshots'])}" + (" → **el espacio de lo que se borre no se libera hasta que caduquen**" if sn["snapshots"] else ""))
    w("")
    w("> **Ocupado ≠ recuperable.** *Ocupado* es el espacio físico asignado hoy (bloques en disco). "
      "*Candidato* = ficheros con una antigüedad mayor o igual al umbral de la regla y que no están abiertos. "
      "*Recuperable conservador* = solo grupos enteros inactivos (sin ficheros recientes ni abiertos) y de riesgo bajo o medio. "
      "Ninguna cifra está garantizada: los clones de APFS, los snapshots y la regeneración de cachés reducen lo que se libera de verdad.\n")

    reglas = d["escaneo"]["reglas"]
    w("## Resumen por regla\n")
    w("| Regla | Riesgo | Umbral | Ficheros | Lógico | Ocupado (físico) | Candidato | Recuperable conservador | Abierto |")
    w("|---|---|---:|---:|---:|---:|---:|---:|---:|")
    T = {"logico": 0, "fisico": 0, "cand": 0, "cons": 0}
    for r in reglas:
        t = r["totales"]
        T["logico"] += t["logico"]; T["fisico"] += t["fisico"]; T["cand"] += t["candidatos_fisico_sin_alto"]; T["cons"] += t["recuperable_conservador"]
        w(f"| `{r['id']}` | {r['riesgo']} | {r['edad_minima_dias']} d | {t['ficheros']:,} | {humano(t['logico'])} | {humano(t['fisico'])} | "
          f"{humano(t['candidatos_fisico'])} | {humano(t['recuperable_conservador'])} | {humano(t['abiertos_fisico'])} |")
    w(f"| **Total** | | | | {humano(T['logico'])} | **{humano(T['fisico'])}** | {humano(T['cand'])} (sin riesgo alto) | **{humano(T['cons'])}** | |\n")

    w("## Raíces\n")
    for r in reglas:
        for x in r["raices"]:
            estado = "escaneada" if x.get("escaneada") else f"**no escaneada**: {x.get('motivo')}"
            w(f"- `{r['id']}` · `{x['ruta']}` → {estado}")
    w("")

    herrs = [r for r in reglas if r.get("herramienta")]
    if herrs:
        w("## Herramientas (consultas no destructivas)\n")
        for r in herrs:
            h = r["herramienta"]
            w(f"### {h.get('herramienta')}\n")
            w(f"- Consultas: {', '.join('`%s`' % c for c in h.get('consultas', []))}")
            if not h.get("disponible"):
                w(f"- No disponible: {h.get('motivo')}")
            else:
                w(f"- Caché: `{h.get('ruta')}`" + (f" (origen: {h['origen']})" if h.get("origen") else ""))
            if r.get("limpieza_oficial"):
                w(f"- Limpieza oficial recomendada (F2, no ejecutada): `{r['limpieza_oficial']}`")
                if h.get("version"):
                    w(f"- Ejecutable: `{h.get('ejecutable')}` · {h['version']}")
                if h.get("info"):
                    w("- Lo que informa la herramienta (puede diferir del recorrido, que es la cifra de referencia):")
            for k, v in (h.get("info") or {}).items():
                w(f"  - {k}: {v}")
            dr = h.get("dry_run")
            if dr:
                w(f"- `brew cleanup -n`: {dr.get('n_elementos', 0)} elementos; liberaría ≈ {humano(dr.get('bytes_estimados'))}")
            w("")

    w(f"## Grupos más grandes\n")
    filas = []
    for r in reglas:
        for g in r["grupos"]:
            filas.append((r["id"], g))
    filas.sort(key=lambda x: x[1]["fisico"], reverse=True)
    w("| Regla | Grupo | Ocupado | Candidato | Ficheros | Última mod. | Más reciente | Más antiguo | Estado | Riesgo |")
    w("|---|---|---:|---:|---:|---|---:|---:|---|---|")
    for rid, g in filas[: d.get("top_grupos", 25)]:
        w(f"| `{rid}` | `{g['nombre'][:48]}` | {humano(g['fisico'])} | {humano(g['candidatos_fisico'])} | {g['ficheros']:,} | "
          f"{fecha(g['mtime_max'])} | {dias(ahora, g['ref_max'])} | {dias(ahora, g['ref_min'])} | {g['estado']} | {g['riesgo']}"
          + (f" ({g['motivo_riesgo']})" if g['riesgo'] != r_base(reglas, rid) else "") + " |")
    w("")

    w("## Antigüedad del espacio ocupado (por regla, físico)\n")
    tramos = ["<7d", "7-30d", "30-90d", "90d-1a", ">1a"]
    w("| Regla | " + " | ".join(tramos) + " |")
    w("|---|" + "---:|" * len(tramos))
    for r in reglas:
        acc = {t: 0 for t in tramos}
        for g in r["grupos"]:
            for t, b in g["por_tramo"].items():
                acc[t] = acc.get(t, 0) + b
        w(f"| `{r['id']}` | " + " | ".join(humano(acc[t]) for t in tramos) + " |")
    w("\n_(La tabla suma solo los 200 grupos mayores de cada regla.)_\n")

    ex = d["escaneo"]["exclusiones"]
    w("## Exclusiones (no inspeccionadas)\n")
    w(ex["nota"] + "\n")
    for m, n in sorted(ex["por_motivo"].items(), key=lambda x: -x[1]):
        w(f"- {m}: {n}")
    if ex["muestra"]:
        w("\n<details><summary>Muestra de rutas excluidas</summary>\n")
        for x in ex["muestra"][:80]:
            w(f"- `{x['ruta']}` — {x['motivo']}")
        w("\n</details>\n")

    c = d["escaneo"]["contadores"]
    w("## Contadores de seguridad\n")
    w(f"- Ficheros contados: {c['ficheros']:,} · directorios: {c['directorios']:,}")
    w(f"- Enlaces simbólicos omitidos (no se siguen): {c['enlaces_omitidos']:,}")
    w(f"- Enlaces duros ya contados (deduplicados): {c['duplicados_enlace_duro']:,} ({humano(c['duplicados_fisico'])})")
    w(f"- Otros volúmenes o puntos de montaje: {c['otro_volumen']:,} · especiales (sockets, FIFO): {c['especiales_omitidos']:,} · de otro propietario: {c['ajenos_omitidos']:,}")
    er = d["escaneo"]["errores"]
    w(f"- Errores de acceso (se continúa): {er['n']:,}")
    if er["muestra"]:
        w("\n<details><summary>Muestra de errores</summary>\n")
        for x in er["muestra"][:40]:
            w(f"- `{x['ruta']}` — {x['error']}")
        w("\n</details>\n")
    gu = d.get("guardia")
    if gu:
        w("\n## Guardia de solo lectura\n")
        w(f"- Activa durante todo el escaneo; escritura permitida solo en `{gu['permitido']}`.")
        w(f"- Intentos bloqueados: {len(gu['bloqueos'])}" + ("" if not gu["bloqueos"] else " → " + "; ".join(gu["bloqueos"][:10])))
        w(f"- Subprocesos ejecutados (lista blanca): {', '.join('`%s`' % s.replace('subprocess ', '') for s in gu['subprocesos']) or 'ninguno'}")
    w("\n---\nF1 no borra, mueve ni modifica nada. Las acciones quedan para F2 (plan + cuarentena + restauración).")
    return "\n".join(L) + "\n"


def r_base(reglas: list, rid: str) -> str:
    return next((r["riesgo"] for r in reglas if r["id"] == rid), "")
