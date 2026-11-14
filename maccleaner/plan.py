"""`plan`: convierte un escaneo reciente (≤ 24 h) en una lista de ficheros candidatos, revalidada AHORA.

El escaneo solo sirve para elegir grupos (recuperable conservador > 0). Cada grupo se vuelve a recorrer
en el momento de planificar, con las protecciones de F1, una instantánea nueva de lsof y la antigüedad
recalculada. De cada fichero se guardan los metadatos necesarios para detectar cualquier cambio antes de
aplicar: st_dev, st_ino, propietario, modo, tamaño, mtime_ns, ctime_ns, birthtime y (opcional) SHA-256.

`huella` es un SHA-256 del contenido canónico del plan: detecta modificaciones accidentales o ingenuas.
NO es una firma autenticada: quien edite el plan puede recalcularla. Por eso `apply` vuelve a comprobar
todas las protecciones y la zona sin fiarse del plan.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets
import time

from . import zona as zona_mod
from .config import Config
from .escaner import DIA, Escaner, ref_antiguedad
from .fsseguro import sha256_ruta
from .sistema import FicherosAbiertos

VERSION_PLAN = 1
CADUCIDAD_ESCANEO_H = 24
CADUCIDAD_PLAN_H = 24
TOLERANCIA_FUTURO_S = 300
MAX_ELEMENTOS = 200_000


class PlanNoValido(ValueError):
    pass


def _canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def calcular_huella(plan: dict) -> str:
    return hashlib.sha256(_canon({k: v for k, v in plan.items() if k != "huella"})).hexdigest()


def sha256_fichero(ruta: str) -> str:
    with open(ruta, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def crear_plan(escaneo: dict, cfg: Config, *, ruta_escaneo: str = "", ahora: float | None = None,
               abiertos: FicherosAbiertos | None = None, hash_max_bytes: int = 64 << 20,
               calcular_hash: bool = True, caducidad_h: float = CADUCIDAD_PLAN_H) -> dict:
    ahora = ahora or time.time()
    t_esc = float(escaneo.get("ahora", 0))
    if not t_esc:
        raise PlanNoValido("el escaneo no tiene marca de tiempo")
    if t_esc > ahora + TOLERANCIA_FUTURO_S:
        raise PlanNoValido("el escaneo tiene fecha futura")
    if ahora - t_esc > CADUCIDAD_ESCANEO_H * 3600:
        raise PlanNoValido(f"el escaneo tiene más de {CADUCIDAD_ESCANEO_H} h: vuelve a ejecutar `scan`")
    if escaneo.get("config_sha256") and escaneo["config_sha256"] != sha256_fichero(cfg.origen):
        raise PlanNoValido("la configuración cambió desde el escaneo: vuelve a ejecutar `scan`")

    zona = escaneo.get("zona")
    if zona:
        zona = zona_mod.validar_zona(zona)
    esc = Escaner(cfg, abiertos=abiertos or FicherosAbiertos(), ahora=ahora, limite=zona)
    reglas = {r.id: r for r in cfg.reglas}
    elementos, excluidos = [], []

    for r_esc in escaneo["escaneo"]["reglas"]:
        regla = reglas.get(r_esc["id"])
        for g in r_esc.get("grupos", []):
            if g.get("recuperable_conservador", 0) <= 0:
                continue
            base = {"regla": r_esc["id"], "grupo": g["nombre"], "ruta": g["ruta"]}
            if regla is None:
                excluidos.append({**base, "motivo": "la regla ya no existe en la configuración"})
                continue
            riesgo, _ = esc._riesgo(regla, g["nombre"])
            if riesgo == "alto":
                excluidos.append({**base, "motivo": "riesgo alto"})
                continue
            raiz = os.path.dirname(g["ruta"])
            try:
                ficheros = list(esc.iterar_grupo(regla, raiz, g["ruta"]))
            except ValueError as exc:
                excluidos.append({**base, "motivo": f"no admisible ahora: {exc}"})
                continue
            if not ficheros:
                excluidos.append({**base, "motivo": "vacío ahora"})
                continue
            edad_min = regla.edad_minima_dias * DIA
            if esc.abiertos.alguno_bajo(g["ruta"]) or any(esc.abiertos.abierto(p) for p, _ in ficheros):
                excluidos.append({**base, "motivo": "en uso ahora (ficheros abiertos)"})
                continue
            if edad_min and max(ref_antiguedad(st) for _, st in ficheros) > ahora - edad_min:
                excluidos.append({**base, "motivo": "activo ahora (modificado después del umbral)"})
                continue
            for ruta, st in ficheros:
                if st.st_nlink > 1:
                    excluidos.append({**base, "ruta": ruta, "motivo": "enlace duro: moverlo no libera espacio"})
                    continue
                if len(elementos) >= MAX_ELEMENTOS:
                    raise PlanNoValido(f"el plan superaría {MAX_ELEMENTOS} elementos: limita con --regla")
                sha = None
                if calcular_hash and st.st_size <= hash_max_bytes:
                    try:
                        sha = sha256_ruta(ruta, st.st_ino)
                    except OSError as exc:
                        excluidos.append({**base, "ruta": ruta, "motivo": f"no legible: {exc.strerror or exc}"})
                        continue
                elementos.append({
                    "id": f"e{len(elementos) + 1:06d}", "regla": regla.id, "grupo": g["nombre"], "riesgo": riesgo,
                    "ruta": ruta, "dev": st.st_dev, "ino": st.st_ino, "uid": st.st_uid, "modo": st.st_mode,
                    "tam": st.st_size, "bloques": st.st_blocks, "mtime_ns": st.st_mtime_ns,
                    "ctime_ns": st.st_ctime_ns, "birthtime": getattr(st, "st_birthtime", None),
                    "sha256": sha, "edad_minima_dias": regla.edad_minima_dias,
                })

    plan = {
        "tipo": "mac-cleaner-plan", "version": VERSION_PLAN, "id": dt.datetime.fromtimestamp(ahora).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3),
        "creado": ahora, "caduca": ahora + caducidad_h * 3600,
        "zona": zona, "modo": "sintetico" if zona else "real (solo vista previa: apply lo rechaza en F2)",
        "home": cfg.home, "tmpdir": cfg.tmpdir,
        "config": cfg.origen, "config_sha256": sha256_fichero(cfg.origen),
        "escaneo": {"ruta": ruta_escaneo, "generado": escaneo.get("generado"), "ahora": t_esc},
        "lsof": {"disponible": esc.abiertos.disponible, "n": len(esc.abiertos)},
        "hash": {"calculado": calcular_hash, "max_bytes": hash_max_bytes},
        "totales": {"elementos": len(elementos), "bytes_fisicos": sum(e["bloques"] * 512 for e in elementos),
                    "bytes_logicos": sum(e["tam"] for e in elementos)},
        "elementos": elementos, "excluidos": excluidos[:2000], "n_excluidos": len(excluidos),
        "nota_huella": "SHA-256 de integridad del contenido; no es una firma autenticada.",
    }
    plan["huella"] = calcular_huella(plan)
    return plan


CAMPOS_ELEMENTO = ("id", "regla", "grupo", "riesgo", "ruta", "dev", "ino", "uid", "modo", "tam", "bloques",
                   "mtime_ns", "ctime_ns", "sha256", "edad_minima_dias")


def validar_plan(plan: dict, ahora: float | None = None) -> str:
    """Comprobaciones estructurales previas a cualquier operación. Devuelve la zona canónica."""
    ahora = ahora or time.time()
    if not isinstance(plan, dict) or plan.get("tipo") != "mac-cleaner-plan":
        raise PlanNoValido("no es un plan de mac-cleaner")
    if plan.get("version") != VERSION_PLAN:
        raise PlanNoValido(f"versión de plan no admitida: {plan.get('version')}")
    if plan.get("huella") != calcular_huella(plan):
        raise PlanNoValido("la huella no coincide: el plan fue modificado o está dañado")
    creado, caduca = float(plan.get("creado", 0)), float(plan.get("caduca", 0))
    if creado > ahora + TOLERANCIA_FUTURO_S:
        raise PlanNoValido("el plan tiene fecha de creación futura")
    if ahora > caduca or caduca - creado > CADUCIDAD_PLAN_H * 3600 + 1:
        raise PlanNoValido("el plan ha caducado: vuelve a ejecutar `scan` y `plan`")
    zona = zona_mod.validar_zona(plan.get("zona"))   # sin zona → limpieza real deshabilitada
    vistos_ruta, vistos_id, vistos_ino = set(), set(), set()
    for e in plan.get("elementos", []):
        faltan = [c for c in CAMPOS_ELEMENTO if c not in e]
        if faltan:
            raise PlanNoValido(f"elemento sin campos {faltan}")
        if e["riesgo"] == "alto":
            raise PlanNoValido(f"{e['id']}: un plan no puede contener elementos de riesgo alto")
        zona_mod.exigir_dentro(e["ruta"], zona)
        for conjunto, clave in ((vistos_ruta, e["ruta"]), (vistos_id, e["id"]), (vistos_ino, (e["dev"], e["ino"]))):
            if clave in conjunto:
                raise PlanNoValido(f"elemento duplicado: {clave}")
            conjunto.add(clave)
    return zona


def guardar(plan: dict, directorio: str) -> str:
    os.makedirs(directorio, exist_ok=True)
    ruta = os.path.join(directorio, f"plan-{plan['id']}.json")
    fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(plan, fh, ensure_ascii=False, indent=1)
    return ruta


def cargar(ruta: str) -> dict:
    try:
        with open(ruta, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise PlanNoValido(f"no se puede leer el plan: {exc}") from exc
