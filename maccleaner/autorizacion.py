"""F4B: autorización escrita de la primera limpieza REAL (docs/F4.md §4).

La autorización es CÓDIGO a propósito: habilitar la limpieza real exige cambiar este fichero (y dejarlo en el
historial de git), no una opción de la CLI, una variable de entorno, el TOML ni el plan. Lo que fija:

  * regla: SOLO `pip`, y solo su caché HTTP (`http-v2`, `http`) según la lista blanca OFICIAL. La caché que declara
    `pip cache dir` debe ser exactamente `~/Library/Caches/pip`; si no, se rechaza.
  * topes por operación: nº de ficheros = los de pip en la lista blanca de la ÚLTIMA SOMBRA (real, de menos de
    SOMBRA_MAX_EDAD_S, sin verificaciones bloqueantes, con la misma configuración e íntegra); bytes físicos = el menor
    entre los de esa sombra y MAX_BYTES. Si el plan los supera, se rechaza ENTERO (no se recorta).
  * cuarentena: `~/.mac-cleaner/cuarentena` (protegida en guards.PROTECCION_FIJA_RUTAS), mismo volumen, 14 días.
    La purga real NO está autorizada (purge sigue solo en zonas sintéticas).
  * ventana: VENTANA (hora local). Fuera de ella `plan --real` y `apply` de un plan real se rechazan. `restore` de
    una operación real funciona siempre.
  * condiciones previas (F4.md §4.5): lsof disponible y ningún proceso de pip o npm en ejecución.

Las pruebas sustituyen `zona.raiz_real`, `localizar_pip` y `procesos_en_conflicto` desde Python (mock); nada de
eso se puede cambiar desde la CLI ni el entorno.
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

ID = "F4B-pip-1"
FECHA = "2026-11-23"
TEXTO = ("Autorizo la primera limpieza real de mac-cleaner: solo la caché de pip, con un tope de 1,5 GB y del número "
         "de ficheros que dé la última sombra. Los ficheros van a la cuarentena ~/.mac-cleaner/cuarentena y se guardan "
         "14 días. Ventana: [fecha y hora], conmigo presente.")
REGLA = "pip"
CACHE_REL = "Library/Caches/pip"           # relativa al HOME real
MAX_BYTES = 1_500_000_000
DIAS_CUARENTENA = 14
# Ventana (inicio, fin) en hora local ISO, p. ej. ("2026-11-24T10:00", "2026-11-24T12:00"). None = sin ventana.
VENTANA: tuple[str, str] | None = ("2026-11-23T15:00", "2026-11-23T16:00")   # dada por el usuario el 23-11 a las 15:01: «ahora, durante la próxima hora»
SOMBRA_MAX_EDAD_S = 2 * 3600

_PROCESO = re.compile(r"(^|[\s/])(pip3?(\.\d+)?|npm|npx)(\s|$)|\s-m\s+pip(\s|$)")


class ErrorAutorizacion(PermissionError):
    pass


def ventana() -> tuple[float, float] | None:
    if VENTANA is None:
        return None
    ini, fin = (dt.datetime.fromisoformat(x).timestamp() for x in VENTANA)
    return ini, fin


def exigir_ventana(ahora: float) -> None:
    v = ventana()
    if v is None:
        raise ErrorAutorizacion(f"{ID}: la ventana de la limpieza real no está fijada (autorizacion.VENTANA)")
    if not (v[0] <= ahora <= v[1]):
        raise ErrorAutorizacion(f"{ID}: fuera de la ventana autorizada ({VENTANA[0]} – {VENTANA[1]}, hora local)")


def cache_esperada(raiz: str) -> str:
    return os.path.join(raiz, CACHE_REL)


def localizar_pip(home: str) -> dict:          # punto de sustitución de las pruebas
    return herramientas.pip(home)


def herramientas_reales(raiz: str) -> dict:
    """{"pip": info} con la caché que declara pip AHORA; debe ser exactamente ~/Library/Caches/pip."""
    info = localizar_pip(raiz)
    if not info.get("disponible") or not info.get("ruta"):
        raise ErrorAutorizacion(f"pip no disponible: {info.get('motivo', 'sin ruta de caché')}")
    if os.path.realpath(info["ruta"]) != os.path.realpath(cache_esperada(raiz)):
        raise ErrorAutorizacion(f"la caché de pip ({info['ruta']}) no es la autorizada (~/{CACHE_REL})")
    return {"pip": info}


def procesos_en_conflicto() -> list[str]:
    """Procesos de pip o npm en ejecución (ps). Si ps falla, se trata como conflicto: no se puede comprobar."""
    rc, out, err = sistema.ejecutar(["/bin/ps", "-axo", "pid=,command="])
    if rc != 0:
        return [f"no se puede comprobar con ps: {(err or 'error').strip()[:100]}"]
    propio = os.getpid()
    hallados = []
    for linea in out.splitlines():
        pid, _, cmd = linea.strip().partition(" ")
        if pid.isdigit() and int(pid) != propio and _PROCESO.search(cmd):
            hallados.append(f"{pid} {cmd[:120]}")
    return hallados


def exigir_condiciones(abiertos) -> None:
    """F4.md §4.5, antes de mover: lsof disponible y ni pip ni npm en ejecución."""
    if not abiertos.disponible:
        raise ErrorAutorizacion("lsof no disponible: no se puede comprobar qué ficheros están abiertos")
    conflicto = procesos_en_conflicto()
    if conflicto:
        raise ErrorAutorizacion("pip o npm en ejecución: " + "; ".join(conflicto[:3]))


def _canon(d) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def topes_desde_sombra(doc: dict, candidatos: list | None, subarboles: list[str], *, ahora: float,
                       config_sha256: str, ruta: str = "") -> dict:
    """Topes del plan a partir de la última sombra. Lanza ErrorAutorizacion si la sombra no sirve."""
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
    n = b = 0
    for x in candidatos:
        if any(bajo(x[0], s) and x[0] != s for s in subarboles):
            n += 1
            b += int(x[2]) * 512
    return {"ficheros": n, "bytes_fisicos": min(b, MAX_BYTES),
            "sombra": {"ruta": ruta, "generado": doc.get("generado"), "ahora": t,
                       "huella_informe": doc["huella_informe"], "ficheros_pip": n, "bytes_pip": b}}


CLAVES_REAL = {"raiz", "autorizacion", "regla", "topes", "sombra", "ventana"}


def validar_plan_real(plan: dict, ahora: float) -> str:
    """Comprobaciones del bloque `real` de un plan F4B. Devuelve la raíz real (HOME canónico)."""
    r = plan.get("real")
    if plan.get("zona") is not None:
        raise ErrorAutorizacion("un plan real no puede declarar zona sintética")
    if not isinstance(r, dict) or set(r) != CLAVES_REAL:
        raise ErrorAutorizacion("bloque «real» del plan no válido")
    raiz = zona_mod.raiz_real()
    if r["raiz"] != raiz or os.path.realpath(plan.get("home", "")) != raiz:
        raise ErrorAutorizacion("el plan real es de otro HOME")
    if r["autorizacion"] != ID or r["regla"] != REGLA:
        raise ErrorAutorizacion(f"el plan no corresponde a la autorización vigente ({ID}, regla {REGLA})")
    topes = r["topes"]
    if not isinstance(topes, dict) or set(topes) != {"ficheros", "bytes_fisicos"} or \
            not all(isinstance(topes[k], int) and not isinstance(topes[k], bool) and topes[k] > 0 for k in topes):
        raise ErrorAutorizacion("topes del plan no válidos")
    if topes["bytes_fisicos"] > MAX_BYTES:
        raise ErrorAutorizacion(f"el tope de bytes del plan supera el autorizado ({MAX_BYTES})")
    if r["ventana"] != (list(VENTANA) if VENTANA else None):
        raise ErrorAutorizacion("la ventana del plan no es la autorizada")
    exigir_ventana(ahora)
    return raiz


def comprobar_totales(elementos: list[dict], topes: dict) -> None:
    n = len(elementos)
    b = sum(int(e["bloques"]) * 512 for e in elementos)
    if n > topes["ficheros"] or b > topes["bytes_fisicos"]:
        raise ErrorAutorizacion(f"el plan supera los topes ({n} ficheros / {b} bytes frente a {topes['ficheros']} / "
                                f"{topes['bytes_fisicos']}): se rechaza entero, no se recorta")
