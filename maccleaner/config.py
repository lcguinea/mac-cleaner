"""Carga y valida config/reglas.toml (biblioteca estándar: tomllib, Python >= 3.11)."""
from __future__ import annotations

import os
import re
import sys
import tempfile
from dataclasses import dataclass, field

if sys.version_info < (3, 11):  # pragma: no cover
    raise SystemExit("mac-cleaner necesita Python 3.11 o superior (tomllib). Usa el lanzador ./mac-cleaner.")
import tomllib

from .guards import Proteccion

RIESGOS = ("bajo", "medio", "alto")
TIPOS = ("ruta", "herramienta")
HERRAMIENTAS = ("brew", "pip", "npm")


class ErrorConfig(ValueError):
    pass


@dataclass
class Regla:
    id: str
    tipo: str
    descripcion: str
    riesgo: str
    edad_minima_dias: int
    rutas: list[str] = field(default_factory=list)
    herramienta: str | None = None
    solo_propietario: bool = False
    limpieza_oficial: str | None = None


@dataclass
class AjusteRiesgo:
    patron: re.Pattern
    riesgo: str
    motivo: str


@dataclass
class Config:
    reglas: list[Regla]
    proteccion: Proteccion
    ajustes: list[AjusteRiesgo]
    edad_minima_dias: int = 30
    top_grupos: int = 25
    usar_lsof: bool = True
    baja_prioridad: bool = True
    home: str = ""
    tmpdir: str = ""
    origen: str = ""
    dias_cuarentena: float = 14
    hash_max_bytes: int = 64 << 20


def tmpdir_usuario() -> str:
    return os.environ.get("TMPDIR") or tempfile.gettempdir()


def cargar(ruta: str, home: str | None = None, tmpdir: str | None = None, bases: list[str] | None = None) -> Config:
    home = home or os.path.expanduser("~")
    tmpdir = tmpdir or tmpdir_usuario()
    try:
        with open(ruta, "rb") as fh:
            datos = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ErrorConfig(f"No se puede leer {ruta}: {exc}") from exc

    g = datos.get("general", {})
    q = datos.get("cuarentena", {})
    if float(q.get("dias", 14)) < 1:
        raise ErrorConfig("[cuarentena].dias debe ser al menos 1")
    edad_def = int(g.get("edad_minima_dias", 30))
    p = datos.get("proteccion", {})
    for clave in ("rutas", "nombres", "extensiones", "marcadores_proyecto", "marcadores_venv"):
        if not isinstance(p.get(clave, []), list):
            raise ErrorConfig(f"[proteccion].{clave} debe ser una lista")
    for patron in p.get("nombres", []):
        try:
            re.compile(patron)
        except re.error as exc:
            raise ErrorConfig(f"Expresión regular no válida en [proteccion].nombres: {patron!r}: {exc}") from exc
    prot = Proteccion(
        home=home, tmpdir=tmpdir,
        rutas=p.get("rutas", []), nombres=p.get("nombres", []), extensiones=p.get("extensiones", []),
        marcadores=p.get("marcadores_proyecto", []) + p.get("marcadores_venv", []),
        bases=bases or [],
    )

    ajustes = []
    for a in datos.get("ajuste_riesgo", []):
        if a.get("riesgo") not in RIESGOS:
            raise ErrorConfig(f"ajuste_riesgo con riesgo no válido: {a!r}")
        ajustes.append(AjusteRiesgo(re.compile(a["patron"], re.IGNORECASE), a["riesgo"], a.get("motivo", "")))

    reglas, vistos = [], set()
    for r in datos.get("regla", []):
        rid = r.get("id")
        if not rid or rid in vistos:
            raise ErrorConfig(f"Regla sin id o duplicada: {rid!r}")
        vistos.add(rid)
        tipo = r.get("tipo")
        if tipo not in TIPOS:
            raise ErrorConfig(f"Regla {rid}: tipo debe ser uno de {TIPOS}")
        riesgo = r.get("riesgo", "medio")
        if riesgo not in RIESGOS:
            raise ErrorConfig(f"Regla {rid}: riesgo debe ser uno de {RIESGOS}")
        if tipo == "herramienta" and r.get("herramienta") not in HERRAMIENTAS:
            raise ErrorConfig(f"Regla {rid}: herramienta debe ser una de {HERRAMIENTAS}")
        if tipo == "ruta" and not r.get("rutas"):
            raise ErrorConfig(f"Regla {rid}: falta 'rutas'")
        reglas.append(Regla(
            id=rid, tipo=tipo, descripcion=r.get("descripcion", ""), riesgo=riesgo,
            edad_minima_dias=int(r.get("edad_minima_dias", edad_def)), rutas=list(r.get("rutas", [])),
            herramienta=r.get("herramienta"), solo_propietario=bool(r.get("solo_propietario", False)),
            limpieza_oficial=r.get("limpieza_oficial"),
        ))

    return Config(
        reglas=reglas, proteccion=prot, ajustes=ajustes, edad_minima_dias=edad_def,
        top_grupos=int(g.get("top_grupos", 25)), usar_lsof=bool(g.get("usar_lsof", True)),
        baja_prioridad=bool(g.get("baja_prioridad", True)), home=home, tmpdir=tmpdir, origen=ruta,
        dias_cuarentena=float(q.get("dias", 14)), hash_max_bytes=int(float(q.get("hash_max_mb", 64)) * (1 << 20)),
    )
