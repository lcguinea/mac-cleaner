"""Lista blanca de limpieza (F3; integrada en plan y apply en F4A). NO habilita la limpieza real.

La limpieza de datos reales sigue bloqueada por `zona.LIMPIEZA_REAL_HABILITADA = False` y por la puerta de zona
de `plan.validar_plan`. Desde F4A la lista blanca es OBLIGATORIA en `plan` (solo entran elementos permitidos),
en `apply` (se recalcula al empezar y se vuelve a comprobar cada elemento inmediatamente antes de moverlo) y en
`sombra` (los mismos criterios). No se puede ampliar desde el TOML (la regla debe ser de tipo herramienta y con la
herramienta esperada), ni desde argumentos, ni desde el plan (el campo `lista_blanca` del plan es informativo).
`ListaBlanca` admite otras definiciones solo desde código Python: las pruebas de mecánica genérica de F2 usan una
lista «de laboratorio» en zonas sintéticas; la CLI y `demo` usan siempre `OFICIAL`.

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

from .guards import bajo, expandir

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
    """(compatibilidad F3) Clasificación con la lista blanca oficial."""
    return OFICIAL.clasificar(regla, ruta, subs)


class ListaBlanca:
    """Definición de lo limpiable. Cada entrada: regla → {"herramienta": nombre} (raíz = la caché que declara la
    herramienta) o {"rutas": True} (raíces = las rutas de la regla; SOLO laboratorio), más "subdirectorios"
    ("." = la raíz entera)."""

    def __init__(self, entradas: dict, nombre: str):
        self.entradas = entradas
        self.nombre = nombre

    @property
    def oficial(self) -> bool:
        return self is OFICIAL

    def subarboles(self, cfg, herramientas: dict) -> tuple[dict[str, list[str]], list[dict]]:
        """{regla: [subárboles]} según la configuración y las cachés de las herramientas; y los rechazos."""
        reglas = {r.id: r for r in cfg.reglas}
        out, rechazos = {}, []
        for rid, ent in self.entradas.items():
            r = reglas.get(rid)
            if r is None:
                continue
            raices = []
            if ent.get("herramienta"):
                info = herramientas.get(ent["herramienta"]) or {}
                if r.tipo != "herramienta" or r.herramienta != ent["herramienta"]:
                    rechazos.append({"regla": rid, "motivo": f"la regla «{rid}» del TOML no es la herramienta "
                                                             f"{ent['herramienta']}: la lista blanca no se aplica"})
                    continue
                if not info.get("disponible") or not info.get("ruta"):
                    continue
                raices = [os.path.realpath(info["ruta"])]
            elif ent.get("rutas"):
                if r.tipo != "ruta":
                    continue
                raices = [os.path.realpath(expandir(x, cfg.home, cfg.tmpdir)) for x in r.rutas]
            for raiz in raices:
                motivo = motivo_raiz(raiz, cfg.home) if self.oficial else None
                if motivo:
                    rechazos.append({"regla": rid, "raiz": raiz, "motivo": motivo})
                    continue
                out.setdefault(rid, []).extend(raiz if s == "." else os.path.join(raiz, s) for s in ent["subdirectorios"])
        return out, rechazos

    def clasificar(self, regla: str, ruta: str, subs: dict[str, list[str]]) -> tuple[bool, str]:
        if regla not in self.entradas:
            return False, f"la regla «{regla}» no está en la lista blanca ({self.nombre})"
        if regla not in subs:
            return False, f"la caché de «{regla}» no está disponible o su raíz no es aceptable"
        sub = next((x for x in subs[regla] if bajo(ruta, x) and ruta != x), None)
        if sub is None:
            return False, f"fuera de los subdirectorios permitidos de {regla} ({', '.join(self.entradas[regla]['subdirectorios'])})"
        rel = ruta[len(sub):].strip("/").split("/")
        if any(COMPONENTES_PROHIBIDOS.match(c) for c in rel):
            return False, "la ruta contiene un componente de instalación o entorno"
        return True, f"{regla}: {os.path.basename(sub)}"

    def raiz_sigue_aceptable(self, ruta: str, subs: dict[str, list[str]], regla: str, home: str) -> str | None:
        """Revalidación inmediatamente anterior al movimiento: la raíz de la caché sigue sin marcadores de proyecto
        o entorno (en ella o en sus antepasados) y el subárbol sigue siendo un directorio real."""
        sub = next((x for x in subs.get(regla, []) if bajo(ruta, x) and ruta != x), None)
        if sub is None:
            return "fuera de la lista blanca"
        if not self.oficial:
            return None
        try:
            if os.path.islink(sub) or not os.path.isdir(sub):
                return "el subárbol de la lista blanca ya no es un directorio real"
        except OSError as exc:
            return f"no se puede comprobar el subárbol: {exc}"
        return motivo_raiz(os.path.dirname(sub), home)


OFICIAL = ListaBlanca(LISTA_BLANCA, "oficial")


def herramientas_de_escaneo(reglas_escaneo: list[dict]) -> dict:
    """Información de herramientas registrada en un escaneo ({"npm": {...}, "pip": {...}})."""
    return {r["herramienta"]["herramienta"]: r["herramienta"] for r in reglas_escaneo
            if isinstance(r.get("herramienta"), dict) and r["herramienta"].get("herramienta")}
