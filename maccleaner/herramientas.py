"""Localización NO destructiva de las cachés de Homebrew, pip y npm.

Solo se ejecutan los argv de esta lista blanca. Comprobaciones hechas el 14-11-2026:
  - `pip cache dir` / `pip cache info` con --disable-pip-version-check: sin cambios en la caché.
  - `brew --cache`: solo imprime la ruta.
  - `brew cleanup -n`: es un dry-run, pero en la primera ejecución cambió el listado de metadatos
    de ~/Library/Caches/Homebrew (causa no determinada). Por eso es OPCIONAL (--brew-dry-run).
  - npm: NO se ejecuta (npm puede escribir logs en _logs en cada orden); la ruta se resuelve
    leyendo $npm_config_cache y ~/.npmrc, igual que npm.
"""
from __future__ import annotations

import os
import re
import shutil

from .sistema import ejecutar

RUTAS_EXTRA = ("/opt/homebrew/bin", "/usr/local/bin")
ENV_BREW = {"HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ANALYTICS": "1", "HOMEBREW_NO_ENV_HINTS": "1",
            "HOMEBREW_NO_INSTALL_CLEANUP": "1"}


def _which(nombre: str) -> str | None:
    """Prefiere Homebrew (la cadena de herramientas del usuario) al pip antiguo de /usr/bin."""
    for d in RUTAS_EXTRA:
        cand = os.path.join(d, nombre)
        if os.access(cand, os.X_OK):
            return cand
    return shutil.which(nombre)


def brew(home: str, dry_run: bool = False) -> dict:
    info: dict = {"herramienta": "brew", "consultas": []}
    exe = _which("brew")
    if not exe:
        info.update(disponible=False, motivo="brew no encontrado")
        return info
    rc, out, err = ejecutar([exe, "--cache"], env_extra=ENV_BREW)
    info["consultas"].append("brew --cache")
    if rc != 0 or not out.strip():
        info.update(disponible=False, motivo=(err or "brew --cache falló").strip()[:200])
        return info
    info.update(disponible=True, ruta=out.strip())
    if dry_run:
        rc, out, err = ejecutar([exe, "cleanup", "-n", "--prune=30"], timeout=120, env_extra=ENV_BREW)
        info["consultas"].append("brew cleanup -n --prune=30")
        info["dry_run"] = _parse_brew_dry_run(out) if rc == 0 else {"error": (err or out).strip()[:300]}
    return info


_UNIDADES = {"B": 1, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}


def _a_bytes(txt: str) -> int | None:
    m = re.match(r"([\d.,]+)\s*([KMGT]?B)", txt.strip())
    if not m:
        return None
    return int(float(m.group(1).replace(",", "")) * _UNIDADES[m.group(2)])


def _parse_brew_dry_run(out: str) -> dict:
    elementos = []
    for l in out.splitlines():
        m = re.match(r"Would remove: (.+?) \((?:[\d,]+ files, )?([\d.,]+\s*[KMGT]?B)\)", l)
        if m:
            elementos.append({"ruta": m.group(1), "bytes": _a_bytes(m.group(2))})
    total = None
    m = re.search(r"would free approximately ([\d.,]+\s*[KMGT]?B)", out)
    if m:
        total = _a_bytes(m.group(1))
    return {"elementos": elementos[:50], "n_elementos": len(elementos), "bytes_estimados": total}


def pip(home: str) -> dict:
    info: dict = {"herramienta": "pip", "consultas": []}
    exe = _which("pip3") or _which("pip")
    if not exe:
        info.update(disponible=False, motivo="pip no encontrado")
        return info
    base = [exe, "--disable-pip-version-check", "--no-input", "--no-color"]
    rc, out, err = ejecutar(base + ["cache", "dir"])
    info["consultas"].append("pip cache dir")
    if rc != 0 or not out.strip():
        info.update(disponible=False, motivo=(err or "pip cache dir falló").strip()[:200])
        return info
    info.update(disponible=True, ruta=out.strip().splitlines()[-1], ejecutable=exe)
    rc, out, _ = ejecutar(base + ["--version"])
    if rc == 0:
        info["version"] = out.strip()[:160]
    rc, out, _ = ejecutar(base + ["cache", "info"])
    info["consultas"].append("pip cache info")
    if rc == 0:
        info["info"] = {k.strip(): v.strip() for k, v in (l.split(":", 1) for l in out.splitlines() if ":" in l)}
    return info


def npm(home: str) -> dict:
    info: dict = {"herramienta": "npm", "consultas": ["$npm_config_cache", "~/.npmrc (cache=)"]}
    ruta = os.environ.get("npm_config_cache") or os.environ.get("NPM_CONFIG_CACHE")
    origen = "entorno"
    if not ruta:
        try:
            with open(os.path.join(home, ".npmrc"), encoding="utf-8", errors="replace") as fh:
                for l in fh:
                    m = re.match(r"\s*cache\s*=\s*(.+?)\s*$", l)
                    if m:
                        ruta, origen = m.group(1), "~/.npmrc"
        except OSError:
            pass
    if not ruta:
        ruta, origen = os.path.join(home, ".npm"), "valor por defecto de npm"
    ruta = os.path.expanduser(ruta)
    info.update(disponible=os.path.isdir(ruta), ruta=ruta, origen=origen)
    if not info["disponible"]:
        info["motivo"] = "la caché de npm no existe"
    return info


def localizar(nombre: str, home: str, brew_dry_run: bool = False) -> dict:
    if nombre == "brew":
        return brew(home, brew_dry_run)
    if nombre == "pip":
        return pip(home)
    if nombre == "npm":
        return npm(home)
    raise ValueError(f"herramienta no permitida: {nombre}")
