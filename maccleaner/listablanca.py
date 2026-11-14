"""F3: lista blanca inicial para una futura limpieza real. NO habilita nada.

La limpieza de datos reales sigue bloqueada por `zona.LIMPIEZA_REAL_HABILITADA = False` y por la puerta de zona
de `plan.validar_plan`. Este módulo define QUÉ podría limpiarse cuando el usuario lo autorice, y hoy solo lo
usa el modo sombra para clasificar candidatos.

Alcance: exclusivamente las cachés de contenido regenerables de npm y pip.
  * npm  → `<caché de npm>/_cacache` (blobs direccionados por contenido e índice; npm los vuelve a descargar).
           Fuera: `_npx` (paquetes ejecutables, p. ej. herramientas MCP; además protegido en guards/TOML),
           `_logs`, `_prebuilds`, `_tuf`, `_update-notifier-*` y cualquier otro subdirectorio.
  * pip  → `<pip cache dir>/http-v2` y `<pip cache dir>/http` (caché HTTP de descargas).
           Fuera: `wheels` (ruedas compiladas localmente: regenerables, pero recompilarlas puede requerir
           herramientas de compilación), `selfcheck` y cualquier otro subdirectorio.
Nunca: instalaciones (node_modules, site-packages, dist-packages), entornos virtuales, prefijos de Homebrew,
ni nada bajo un directorio con marcadores de proyecto o entorno. Tampoco órdenes oficiales que borren.
"""
from __future__ import annotations

import os
import re

from .guards import bajo

LISTA_BLANCA = {
    "npm": {"herramienta": "npm", "subdirectorios": ("_cacache",),
            "operacion": "mover a cuarentena (reversible) el contenido de _cacache; npm lo vuelve a descargar"},
    "pip": {"herramienta": "pip", "subdirectorios": ("http-v2", "http"),
            "operacion": "mover a cuarentena (reversible) la caché HTTP de pip; pip la vuelve a descargar"},
}

# Componentes que nunca pueden aparecer en la ruta de un elemento autorizable ni en la raíz de la caché.
COMPONENTES_PROHIBIDOS = re.compile(
    r"^(node_modules|site-packages|dist-packages|_npx|\.?venv|virtualenvs?|envs|conda-meta|Cellar|"
    r"lib|bin|include|Scripts|wheels|\.git)$", re.IGNORECASE)
PREFIJOS_PROHIBIDOS = ("/opt/homebrew", "/usr/local", "/usr", "/Library", "/System", "/Applications")
MARCADORES_ENTORNO = ("pyvenv.cfg", "package.json", "conda-meta", "pyproject.toml", ".git")


def motivo_raiz(raiz: str, home: str) -> str | None:
    """¿Es aceptable esta raíz de caché? Debe estar en el HOME, fuera de prefijos de instalación, sin componentes
    de instalación o entorno y sin marcadores de proyecto/entorno en ella ni en sus antepasados (hasta el HOME)."""
    raiz = os.path.realpath(raiz)
    home = os.path.realpath(home)
    if not bajo(raiz, home) or raiz == home:
        return "la caché no está dentro del HOME"
    if any(bajo(raiz, p) for p in PREFIJOS_PROHIBIDOS):
        return "la caché está bajo un prefijo de instalación"
    rel = raiz[len(home):].strip("/").split("/")
    if any(COMPONENTES_PROHIBIDOS.match(c) for c in rel):
        return "la ruta de la caché contiene un componente de instalación o entorno"
    d = raiz
    while bajo(d, home) and d != home:
        try:
            nombres = set(os.listdir(d))
        except OSError:
            return f"no se puede comprobar {d}"
        hit = nombres.intersection(MARCADORES_ENTORNO)
        if hit:
            return f"la caché está dentro de un proyecto o entorno ({', '.join(sorted(hit))})"
        d = os.path.dirname(d)
    return None


def subarboles(reglas_escaneo: list[dict], home: str) -> tuple[dict[str, list[str]], list[dict]]:
    """A partir de las reglas de un escaneo, devuelve {regla: [subárboles autorizables]} y los rechazos."""
    out, rechazos = {}, []
    for r in reglas_escaneo:
        lb = LISTA_BLANCA.get(r.get("id"))
        info = r.get("herramienta") or {}
        if not lb or info.get("herramienta") != lb["herramienta"] or not info.get("disponible") or not info.get("ruta"):
            continue
        raiz = os.path.realpath(info["ruta"])
        motivo = motivo_raiz(raiz, home)
        if motivo:
            rechazos.append({"regla": r["id"], "raiz": raiz, "motivo": motivo})
            continue
        out[r["id"]] = [os.path.join(raiz, s) for s in lb["subdirectorios"]]
    return out, rechazos


def clasificar(regla: str, ruta: str, subs: dict[str, list[str]]) -> tuple[bool, str]:
    """(True, motivo) si el fichero quedaría cubierto por la lista blanca; (False, motivo) si no."""
    if regla not in LISTA_BLANCA:
        return False, f"la regla «{regla}» no está en la lista blanca inicial (solo npm y pip)"
    if regla not in subs:
        return False, f"la caché de «{regla}» no está disponible o su raíz no es aceptable"
    sub = next((s for s in subs[regla] if bajo(ruta, s) and ruta != s), None)
    if sub is None:
        return False, f"fuera de los subdirectorios permitidos de {regla} ({', '.join(LISTA_BLANCA[regla]['subdirectorios'])})"
    rel = ruta[len(sub):].strip("/").split("/")
    if any(COMPONENTES_PROHIBIDOS.match(c) for c in rel):
        return False, "la ruta contiene un componente de instalación o entorno"
    return True, f"{regla}: {os.path.basename(sub)}"
