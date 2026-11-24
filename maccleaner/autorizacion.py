"""Autorización escrita de la limpieza REAL (F4B: solo pip; F5B: app de macOS, docs/F5.md).

La autorización es CÓDIGO a propósito: habilitar o ampliar la limpieza real exige cambiar este fichero (y dejarlo en
el historial de git), no una opción de la CLI, una variable de entorno, el TOML ni el plan. Lo que fija la vigente:

  * reglas: REGLAS, cada una limitada por la lista blanca OFICIAL (listablanca.py). Las cachés de las herramientas se
    vuelven a localizar en cada plan y en cada apply y deben estar EXACTAMENTE donde dice CACHES_ESPERADAS (si una
    herramienta declara otra ruta, se rechaza todo; si no está instalada, su categoría se omite).
  * antigüedad mínima autorizada por regla (EDAD_MINIMA_DIAS): se aplica aunque el TOML diga menos.
  * topes por operación: nº de ficheros = los de las reglas habilitadas en la ÚLTIMA SOMBRA (real, de menos de
    SOMBRA_MAX_EDAD_S, sin verificaciones bloqueantes, con la misma configuración e íntegra); bytes físicos = el menor
    entre los de esa sombra, MAX_BYTES y lo que el usuario confirmó en la app (`hasta_bytes`). Si el plan los supera,
    se rechaza ENTERO (no se recorta).
  * cuarentena: `~/.mac-cleaner/cuarentena` (protegida en guards.PROTECCION_FIJA_RUTAS), mismo volumen,
    DIAS_CUARENTENA días. PURGA_REAL: si se puede purgar lo que lleve al menos DIAS_CUARENTENA días.
  * ventana: si REQUIERE_VENTANA, solo dentro de VENTANA (hora local). F5B no tiene ventana: cada limpieza la inicia el
    usuario en la app, la confirma y macOS le pide permiso para usar la clave HMAC del Llavero (un diálogo por proceso;
    la clave se creó sin apps de confianza, SEGURIDAD-F3 §2.2). `restore` de una operación real funciona siempre.
  * condiciones previas: lsof disponible. Si pip, npm/npx o brew están en ejecución, SU categoría se omite (si no
    queda ninguna, se rechaza). Si ps falla, se omiten todas las de herramientas.

Las pruebas sustituyen `zona.raiz_real`, `localizar_*` y `procesos_en_conflicto` desde Python (mock); nada de eso se
puede cambiar desde la CLI ni el entorno.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re

from . import herramientas, sistema
from . import zona as zona_mod
from .guards import bajo

ID = "F5B-app-1"
FECHA = "2026-11-24"
TEXTO = ("I authorize real cleaning from the Mac Cleaner app (F5B) of: the pip cache (http, http-v2), the npm cache "
         "(_cacache), Homebrew downloads 30 days old or older, logs in ~/Library/Logs 30 days old or older, and app "
         "caches in ~/Library/Caches unchanged for 30 days (whole groups, no open files, no high risk, and no "
         "com.apple.*). Limit per cleaning: 5 GB and the number of files in the shadow scan made just before. "
         "Everything goes to the quarantine ~/.mac-cleaner/cuarentena for 14 days. No fixed time window: I start each "
         "cleaning myself from the app and confirm it. I also authorize purging from the app, with me pressing the "
         "button, anything that has been in quarantine for 14 days or more.")
REGLAS: tuple[str, ...] = ("pip", "npm", "homebrew", "logs-usuario", "caches-usuario")
EDAD_MINIMA_DIAS = {"homebrew": 30, "logs-usuario": 30, "caches-usuario": 30}
MAX_BYTES = 5_000_000_000
DIAS_CUARENTENA = 14
PURGA_REAL = True
REQUIERE_VENTANA = False
# Ventana (inicio, fin) en hora local ISO; solo cuenta si REQUIERE_VENTANA.
VENTANA: tuple[str, str] | None = None
SOMBRA_MAX_EDAD_S = 2 * 3600

# Regla → herramienta y caché esperada (relativa al HOME real).
HERRAMIENTA_DE_REGLA = {"pip": "pip", "npm": "npm", "homebrew": "brew"}
CACHES_ESPERADAS = {"pip": "Library/Caches/pip", "npm": ".npm", "brew": "Library/Caches/Homebrew"}

# Autorizaciones anteriores (historial; sus operaciones se pueden restaurar y, con PURGA_REAL, purgar).
ANTERIORES = {
    "F4B-pip-1": {"fecha": "2026-11-23", "reglas": ["pip"], "max_bytes": 1_500_000_000,
                  "ventana": ["2026-11-23T15:00", "2026-11-23T16:00"],
                  "texto": ("Autorizo la primera limpieza real de mac-cleaner: solo la caché de pip, con un tope de 1,5 GB "
                            "y del número de ficheros que dé la última sombra. Los ficheros van a la cuarentena "
                            "~/.mac-cleaner/cuarentena y se guardan 14 días. Ventana: [fecha y hora], conmigo presente.")},
}

_PROCESOS = {
    "pip": re.compile(r"(^|[\s/])pip3?(\.\d+)?(\s|$)|\s-m\s+pip(\s|$)"),
    "npm": re.compile(r"(^|[\s/])(npm|npx)(\s|$)"),
    "homebrew": re.compile(r"(^|[\s/])brew(\s|$)"),
}


class ErrorAutorizacion(PermissionError):
    pass


def ids_conocidos() -> set[str]:
    return {ID, *ANTERIORES}


def edad_minima(regla: str, configurada: int) -> int:
    """Antigüedad mínima efectiva: la del TOML, nunca menos que la autorizada."""
    return max(int(configurada), EDAD_MINIMA_DIAS.get(regla, 0))


def ventana() -> tuple[float, float] | None:
    if VENTANA is None:
        return None
    ini, fin = (dt.datetime.fromisoformat(x).timestamp() for x in VENTANA)
    return ini, fin


def vigente(ahora: float) -> bool:
    if not REGLAS:
        return False
    if not REQUIERE_VENTANA:
        return True
    v = ventana()
    return bool(v and v[0] <= ahora <= v[1])


def exigir_ventana(ahora: float) -> None:
    if not REQUIERE_VENTANA:
        return
    v = ventana()
    if v is None:
        raise ErrorAutorizacion(f"{ID}: la ventana de la limpieza real no está fijada (autorizacion.VENTANA)")
    if not (v[0] <= ahora <= v[1]):
        raise ErrorAutorizacion(f"{ID}: fuera de la ventana autorizada ({VENTANA[0]} – {VENTANA[1]}, hora local)")


def cache_esperada(raiz: str, herramienta: str = "pip") -> str:
    return os.path.join(raiz, CACHES_ESPERADAS[herramienta])


# Puntos de sustitución de las pruebas.
def localizar_pip(home: str) -> dict:
    return herramientas.pip(home)


def localizar_npm(home: str) -> dict:
    return herramientas.npm(home)


def localizar_brew(home: str) -> dict:
    return herramientas.brew(home)


def herramientas_reales(raiz: str, reglas=None) -> tuple[dict, dict]:
    """({herramienta: info}, {regla: motivo de omisión}) con las cachés que declaran AHORA las herramientas de las reglas
    autorizadas. Una caché en un sitio distinto del esperado rechaza todo (ErrorAutorizacion)."""
    localizar = {"pip": localizar_pip, "npm": localizar_npm, "brew": localizar_brew}
    out, omitidas = {}, {}
    for regla in (REGLAS if reglas is None else reglas):
        h = HERRAMIENTA_DE_REGLA.get(regla)
        if h is None:
            continue
        info = localizar[h](raiz)
        if not info.get("disponible") or not info.get("ruta"):
            omitidas[regla] = f"{h} no disponible: {info.get('motivo', 'sin ruta de caché')}"
            continue
        if os.path.realpath(info["ruta"]) != os.path.realpath(cache_esperada(raiz, h)):
            raise ErrorAutorizacion(f"la caché de {h} ({info['ruta']}) no es la autorizada (~/{CACHES_ESPERADAS[h]})")
        out[h] = info
    return out, omitidas


def procesos_en_conflicto() -> list[str]:
    """Procesos de pip, npm/npx o brew en ejecución (ps). Si ps falla, devuelve un aviso que bloquea las herramientas."""
    rc, out, err = sistema.ejecutar(["/bin/ps", "-axo", "pid=,command="])
    if rc != 0:
        return [f"no se puede comprobar con ps: {(err or 'error').strip()[:100]}"]
    propio = os.getpid()
    hallados = []
    for linea in out.splitlines():
        pid, _, cmd = linea.strip().partition(" ")
        if pid.isdigit() and int(pid) != propio and any(p.search(cmd) for p in _PROCESOS.values()):
            hallados.append(f"{pid} {cmd[:120]}")
    return hallados


def reglas_en_conflicto(procesos: list[str]) -> dict[str, str]:
    """{regla: motivo} de las categorías cuya herramienta está en ejecución."""
    out = {}
    for p in procesos:
        if p.startswith("no se puede comprobar"):
            return {r: p for r in _PROCESOS}
        cmd = p.partition(" ")[2]
        for regla, patron in _PROCESOS.items():
            if patron.search(cmd):
                out.setdefault(regla, f"en ejecución: {p[:100]}")
    return out


def preparar(raiz: str, abiertos, ahora: float, reglas=None) -> tuple[list[str], dict, dict]:
    """Condiciones de un plan o apply real. Devuelve (reglas habilitadas, herramientas, {regla: motivo de omisión}).
    Lanza ErrorAutorizacion si no hay autorización vigente, falta lsof, una caché no es la esperada o no queda nada."""
    exigir_ventana(ahora)
    pedidas = [r for r in (REGLAS if reglas is None else reglas) if r in REGLAS]
    if not pedidas:
        raise ErrorAutorizacion(f"ninguna regla autorizada en {ID}")
    if not abiertos.disponible:
        raise ErrorAutorizacion("lsof no disponible: no se puede comprobar qué ficheros están abiertos")
    # Se localizan las herramientas de TODAS las reglas autorizadas (aunque no se pidan): así cada candidato se atribuye
    # a su regla (topes_desde_sombra) y una caché fuera de su sitio se detecta siempre.
    herrs, omitidas = herramientas_reales(raiz, REGLAS)
    omitidas = {r: m for r, m in omitidas.items() if r in pedidas}
    conflicto = reglas_en_conflicto(procesos_en_conflicto())
    for r in pedidas:
        if r in conflicto and r not in omitidas:
            omitidas[r] = conflicto[r]
    habilitadas = [r for r in pedidas if r not in omitidas]
    if not habilitadas:
        raise ErrorAutorizacion("no queda ninguna categoría autorizada utilizable: " +
                                "; ".join(f"{r}: {m}" for r, m in omitidas.items()))
    return habilitadas, herrs, omitidas


def _canon(d) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def topes_desde_sombra(doc: dict, candidatos: list | None, subarboles, *, ahora: float,
                       config_sha256: str, ruta: str = "", hasta_bytes: int | None = None,
                       reglas: list[str] | None = None) -> dict:
    """Topes del plan a partir de la última sombra. Lanza ErrorAutorizacion si la sombra no sirve.
    `subarboles`: lista de subárboles autorizados, o {regla: [subárboles]} de TODAS las reglas de la lista blanca junto
    con `reglas` (las elegidas): cada candidato cuenta para la regla de su subárbol MÁS específico (los de pip y
    Homebrew cuelgan también de ~/Library/Caches, pero no son de caches-usuario)."""
    from .sombra import huella_informe            # sombra importa plan: import diferido
    if not isinstance(doc, dict) or doc.get("tipo") != "mac-cleaner-sombra":
        raise ErrorAutorizacion("no es una sombra de mac-cleaner")
    if (doc.get("escaneo") or {}).get("zona"):
        raise ErrorAutorizacion("la sombra es de una zona sintética")
    t = doc.get("ahora")
    if not isinstance(t, (int, float)) or t > ahora + 300 or ahora - t > SOMBRA_MAX_EDAD_S:
        raise ErrorAutorizacion(f"la sombra debe tener menos de {SOMBRA_MAX_EDAD_S // 3600} h: ejecuta `sombra` otra vez")
    if doc.get("config_sha256") != config_sha256:
        raise ErrorAutorizacion("la sombra se hizo con otra configuración")
    if doc.get("huella_informe") != huella_informe(doc):
        raise ErrorAutorizacion("la huella de la sombra no coincide: informe modificado o dañado")
    bloq = (doc.get("verificaciones") or {}).get("bloqueantes")
    if bloq != 0:
        raise ErrorAutorizacion(f"la sombra tiene verificaciones bloqueantes ({bloq})")
    c = doc.get("candidatos") or {}
    if candidatos is None or len(candidatos) != c.get("n_lista") or \
            hashlib.sha256(_canon(candidatos)).hexdigest() != c.get("lista_sha256"):
        raise ErrorAutorizacion("la lista de candidatos de la sombra falta o no coincide con su informe")
    if hasta_bytes is not None and (not isinstance(hasta_bytes, int) or isinstance(hasta_bytes, bool) or hasta_bytes <= 0):
        raise ErrorAutorizacion("el tope confirmado por el usuario no es válido")
    if isinstance(subarboles, dict):
        pares = sorted(((s, r) for r, ss in subarboles.items() for s in ss), key=lambda p: -len(p[0]))
        elegidas = set(reglas if reglas is not None else subarboles)
    else:
        pares, elegidas = [(s, None) for s in subarboles], {None}
    n = b = 0
    for x in candidatos:
        duena = next((r for s, r in pares if bajo(x[0], s) and x[0] != s), "")
        if duena != "" and duena in elegidas:
            n += 1
            b += int(x[2]) * 512
    limite = min(b, MAX_BYTES, hasta_bytes if hasta_bytes is not None else MAX_BYTES)
    return {"ficheros": n, "bytes_fisicos": limite,
            "sombra": {"ruta": ruta, "generado": doc.get("generado"), "ahora": t,
                       "huella_informe": doc["huella_informe"], "ficheros_autorizados": n, "bytes_autorizados": b,
                       "hasta_bytes": hasta_bytes}}


CLAVES_REAL = {"raiz", "autorizacion", "reglas", "topes", "sombra", "ventana"}


def validar_plan_real(plan: dict, ahora: float) -> str:
    """Comprobaciones del bloque `real` de un plan. Devuelve la raíz real (HOME canónico)."""
    r = plan.get("real")
    if plan.get("zona") is not None:
        raise ErrorAutorizacion("un plan real no puede declarar zona sintética")
    if not isinstance(r, dict) or set(r) != CLAVES_REAL:
        raise ErrorAutorizacion("bloque «real» del plan no válido")
    raiz = zona_mod.raiz_real()
    if r["raiz"] != raiz or os.path.realpath(plan.get("home", "")) != raiz:
        raise ErrorAutorizacion("el plan real es de otro HOME")
    reglas = r["reglas"]
    if r["autorizacion"] != ID or not isinstance(reglas, list) or not reglas or \
            not all(isinstance(x, str) and x in REGLAS for x in reglas) or len(set(reglas)) != len(reglas):
        raise ErrorAutorizacion(f"el plan no corresponde a la autorización vigente ({ID}, reglas {', '.join(REGLAS)})")
    topes = r["topes"]
    if not isinstance(topes, dict) or set(topes) != {"ficheros", "bytes_fisicos"} or \
            not all(isinstance(topes[k], int) and not isinstance(topes[k], bool) and topes[k] > 0 for k in topes):
        raise ErrorAutorizacion("topes del plan no válidos")
    if topes["bytes_fisicos"] > MAX_BYTES:
        raise ErrorAutorizacion(f"el tope de bytes del plan supera el autorizado ({MAX_BYTES})")
    if r["ventana"] != (list(VENTANA) if REQUIERE_VENTANA and VENTANA else None):
        raise ErrorAutorizacion("la ventana del plan no es la autorizada")
    exigir_ventana(ahora)
    return raiz


def comprobar_totales(elementos: list[dict], topes: dict) -> None:
    n = len(elementos)
    b = sum(int(e["bloques"]) * 512 for e in elementos)
    if n > topes["ficheros"] or b > topes["bytes_fisicos"]:
        raise ErrorAutorizacion(f"el plan supera los topes ({n} ficheros / {b} bytes frente a {topes['ficheros']} / "
                                f"{topes['bytes_fisicos']}): se rechaza entero, no se recorta")


def estado(ahora: float) -> dict:
    """Lo que la app necesita saber (solo lectura)."""
    return {"id": ID, "fecha": FECHA, "texto": TEXTO, "reglas": list(REGLAS), "max_bytes": MAX_BYTES,
            "dias_cuarentena": DIAS_CUARENTENA, "ventana": list(VENTANA) if REQUIERE_VENTANA and VENTANA else None,
            "requiere_ventana": REQUIERE_VENTANA, "vigente": vigente(ahora), "purga_real": PURGA_REAL,
            "edad_minima_dias": EDAD_MINIMA_DIAS}
