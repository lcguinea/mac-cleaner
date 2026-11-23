"""`plan`: convierte un escaneo reciente (≤ 24 h) en una lista de ficheros candidatos, revalidada AHORA.

El escaneo solo sirve para elegir grupos (recuperable conservador > 0). Cada grupo se vuelve a recorrer
en el momento de planificar, con las protecciones de F1, una instantánea nueva de lsof y la antigüedad
recalculada. De cada fichero se guardan los metadatos necesarios para detectar cualquier cambio antes de
aplicar: st_dev, st_ino, propietario, modo, tamaño, mtime_ns, ctime_ns, birthtime y (opcional) SHA-256.

`huella` es un SHA-256 del contenido canónico del plan: detecta modificaciones accidentales o ingenuas.
F3: los planes de zona sintética (y, en el futuro, los reales) llevan además `autenticacion`, un HMAC-SHA256
con clave del Llavero (autenticacion.py) que liga versión, id, zona, fechas, configuración y elementos.
`apply` exige un MAC válido Y además vuelve a comprobar todas las protecciones sin fiarse del plan. Los planes
sin zona (vista previa o sombra) no se autentican: nunca son aplicables.

F4B (`real=`): plan sobre datos reales SOLO dentro de la autorización de autorizacion.py: escaneo real, ventana,
lsof disponible, sin pip/npm en ejecución, caché de pip = ~/Library/Caches/pip, lista blanca OFICIAL restringida a
la regla autorizada, clave NO sintética del Llavero y totales dentro de los topes (que salen de la última sombra);
si los supera se rechaza entero. Lleva `zona: null` y un bloque `real` firmado con el resto del plan.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
import re
import secrets
import time

from . import autenticacion as aut
from . import autorizacion
from . import listablanca
from . import zona as zona_mod
from .config import Config
from .escaner import DIA, Escaner, ref_antiguedad
from .fsseguro import sha256_ruta
from .sistema import FicherosAbiertos

VERSION_PLAN = 2          # F3: v2 = con autenticación HMAC; los planes v1 (F2) se rechazan
_ID_PLAN = re.compile(r"\d{8}-\d{6}-[0-9a-f]{6}")
CADUCIDAD_ESCANEO_H = 24
CADUCIDAD_PLAN_H = 24
TOLERANCIA_FUTURO_S = 300
MAX_ELEMENTOS = 200_000


class PlanNoValido(ValueError):
    pass


def _canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def calcular_huella(plan: dict) -> str:
    return hashlib.sha256(_canon({k: v for k, v in plan.items() if k not in ("huella", "autenticacion")})).hexdigest()


def sha256_fichero(ruta: str) -> str:
    with open(ruta, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def crear_plan(escaneo: dict, cfg: Config, *, ruta_escaneo: str = "", ahora: float | None = None,
               abiertos: FicherosAbiertos | None = None, hash_max_bytes: int = 64 << 20,
               calcular_hash: bool = True, caducidad_h: float = CADUCIDAD_PLAN_H,
               clave: aut.Clave | None = None, firmar: bool = True,
               lista_blanca: "listablanca.ListaBlanca | None" = None, filtrar: bool = True,
               real: dict | None = None) -> dict:
    """Con zona sintética el plan se firma con `clave` (por defecto, la activa del almacén actual).
    F4A: solo entran elementos de la lista blanca (por defecto la OFICIAL); el resto va a `excluidos` con su motivo.
    `filtrar=False` solo lo usa la sombra, que clasifica todo para informar (su plan nunca es aplicable).
    F4B: `real={"sombra": doc, "candidatos": lista, "ruta": ruta}` crea un plan real autorizado (ver el docstring)."""
    lb = lista_blanca or listablanca.OFICIAL
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
    raiz_real = None
    if real is not None:
        if zona:
            raise PlanNoValido("un plan real necesita un escaneo real, no de una zona sintética")
        if lista_blanca not in (None, listablanca.OFICIAL) or not filtrar or not firmar:
            raise PlanNoValido("un plan real solo admite la lista blanca OFICIAL, filtrada y firmada")
        raiz_real = zona_mod.raiz_real()
        if os.path.realpath(cfg.home) != raiz_real:
            raise PlanNoValido("la configuración no es la del HOME real")
        try:
            autorizacion.exigir_ventana(ahora)
            autorizacion.exigir_condiciones(abiertos if abiertos is not None else FicherosAbiertos())
            herramientas_reales = autorizacion.herramientas_reales(raiz_real)
        except autorizacion.ErrorAutorizacion as exc:
            raise PlanNoValido(str(exc)) from exc
        if clave is None:
            try:
                clave = aut.almacen_actual().activa()
            except aut.ClaveNoDisponible as exc:
                raise PlanNoValido(f"no se puede firmar el plan: {exc}") from exc
        if clave.sintetica:
            raise PlanNoValido("una clave sintética no puede firmar un plan real")
    if zona:
        zona = zona_mod.validar_zona(zona)
        if firmar and clave is None:
            try:
                clave = aut.almacen_actual().activa()
            except aut.ClaveNoDisponible as exc:
                raise PlanNoValido(f"no se puede firmar el plan: {exc}") from exc
    esc = Escaner(cfg, abiertos=abiertos if abiertos is not None else FicherosAbiertos(), ahora=ahora, limite=zona)
    if raiz_real:
        herramientas = herramientas_reales
    else:
        herramientas = zona_mod.herramientas_de_zona(zona) if zona else listablanca.herramientas_de_escaneo(escaneo["escaneo"]["reglas"])
    subs, rechazos_lb = lb.subarboles(cfg, herramientas)
    if raiz_real:
        subs = {k: v for k, v in subs.items() if k == autorizacion.REGLA}   # solo la regla autorizada
    reglas = {r.id: r for r in cfg.reglas}
    elementos, excluidos = [], []

    for r_esc in escaneo["escaneo"]["reglas"]:
        regla = reglas.get(r_esc["id"])
        for g in r_esc.get("grupos", []):
            if g.get("recuperable_conservador", 0) <= 0:
                continue
            base = {"regla": r_esc["id"], "grupo": g["nombre"], "ruta": g["ruta"]}
            if raiz_real and r_esc["id"] != autorizacion.REGLA:
                excluidos.append({**base, "motivo": f"regla no autorizada en {autorizacion.ID}"})
                continue
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
                ok_lb, motivo_lb = lb.clasificar(regla.id, ruta, subs)
                if filtrar and not ok_lb:
                    excluidos.append({**base, "ruta": ruta, "motivo": f"fuera de la lista blanca: {motivo_lb}"})
                    continue
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
                    "lista_blanca": motivo_lb if ok_lb else None,
                })

    plan = {
        "tipo": "mac-cleaner-plan", "version": VERSION_PLAN, "id": dt.datetime.fromtimestamp(ahora).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3),
        "creado": ahora, "caduca": ahora + caducidad_h * 3600,
        "zona": zona, "modo": "sintetico" if zona else "real (vista previa sin autenticar: apply la rechaza)",
        "home": cfg.home, "tmpdir": cfg.tmpdir,
        "config": cfg.origen, "config_sha256": sha256_fichero(cfg.origen),
        "escaneo": {"ruta": ruta_escaneo, "generado": escaneo.get("generado"), "ahora": t_esc},
        "lsof": {"disponible": esc.abiertos.disponible, "n": len(esc.abiertos)},
        "hash": {"calculado": calcular_hash, "max_bytes": hash_max_bytes},
        "totales": {"elementos": len(elementos), "bytes_fisicos": sum(e["bloques"] * 512 for e in elementos),
                    "bytes_logicos": sum(e["tam"] for e in elementos)},
        "lista_blanca": {"nombre": lb.nombre, "subarboles": subs, "rechazos": rechazos_lb, "filtrada": filtrar},
        "elementos": elementos, "excluidos": excluidos[:2000], "n_excluidos": len(excluidos),
        "nota_huella": "SHA-256 de integridad del contenido; no es una firma autenticada.",
    }
    if raiz_real:
        try:
            t = autorizacion.topes_desde_sombra(real.get("sombra"), real.get("candidatos"), subs.get(autorizacion.REGLA, []),
                                                ahora=ahora, config_sha256=plan["config_sha256"], ruta=real.get("ruta", ""))
            if not elementos:
                raise autorizacion.ErrorAutorizacion("no hay nada que limpiar en la caché autorizada")
            topes = {"ficheros": t["ficheros"], "bytes_fisicos": t["bytes_fisicos"]}
            if min(topes.values()) <= 0:
                raise autorizacion.ErrorAutorizacion("la última sombra no tiene nada de pip en la lista blanca: tope 0")
            autorizacion.comprobar_totales(elementos, topes)
        except autorizacion.ErrorAutorizacion as exc:
            raise PlanNoValido(str(exc)) from exc
        plan["modo"] = f"real ({autorizacion.ID}: solo {autorizacion.REGLA})"
        plan["real"] = {"raiz": raiz_real, "autorizacion": autorizacion.ID, "regla": autorizacion.REGLA,
                        "topes": topes, "sombra": t["sombra"],
                        "ventana": list(autorizacion.VENTANA) if autorizacion.VENTANA else None}
    plan["huella"] = calcular_huella(plan)
    if (zona or raiz_real) and firmar:
        aut.firmar_plan(plan, clave)
    elif not firmar:
        plan["modo"] = "sombra (sin autenticar: no aplicable)"
    return plan


CAMPOS_ELEMENTO = ("id", "regla", "grupo", "riesgo", "ruta", "dev", "ino", "uid", "modo", "tam", "bloques",
                   "mtime_ns", "ctime_ns", "sha256", "edad_minima_dias")


_CAMPOS_TEXTO = ("id", "regla", "grupo", "ruta")
_CAMPOS_ENTEROS = ("dev", "ino", "uid", "modo", "tam", "bloques", "mtime_ns", "ctime_ns", "edad_minima_dias")
_HEX64 = re.compile(r"[0-9a-f]{64}")


def _es_numero(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _validar_tipos(e: dict) -> None:
    """Tipos exactos de cada campo: un plan forjado no debe poder provocar TypeError/ValueError internos."""
    for c in _CAMPOS_TEXTO:
        if not isinstance(e[c], str) or not e[c]:
            raise PlanNoValido(f"{e.get('id')!r}: «{c}» debe ser texto no vacío")
    for c in _CAMPOS_ENTEROS:
        if not isinstance(e[c], int) or isinstance(e[c], bool) or e[c] < 0:
            raise PlanNoValido(f"{e['id']}: «{c}» debe ser un entero no negativo")
    if e["riesgo"] not in ("bajo", "medio"):
        raise PlanNoValido(f"{e['id']}: riesgo no válido {e['riesgo']!r}")
    if e["sha256"] is not None and not (isinstance(e["sha256"], str) and _HEX64.fullmatch(e["sha256"])):
        raise PlanNoValido(f"{e['id']}: «sha256» debe ser null o 64 dígitos hexadecimales")


def validar_plan(plan: dict, ahora: float | None = None) -> str:
    """Comprobaciones estructurales previas a cualquier operación. Devuelve la zona canónica."""
    ahora = ahora or time.time()
    if not isinstance(plan, dict) or plan.get("tipo") != "mac-cleaner-plan":
        raise PlanNoValido("no es un plan de mac-cleaner")
    if plan.get("version") != VERSION_PLAN:
        raise PlanNoValido(f"versión de plan no admitida: {plan.get('version')}")
    if plan.get("huella") != calcular_huella(plan):
        raise PlanNoValido("la huella no coincide: el plan fue modificado o está dañado")
    for clave in ("creado", "caduca"):
        if not _es_numero(plan.get(clave)):
            raise PlanNoValido(f"campo «{clave}» ausente o no numérico")
    for clave in ("id", "home", "tmpdir", "config", "config_sha256"):
        if not isinstance(plan.get(clave), str) or not plan[clave]:
            raise PlanNoValido(f"campo «{clave}» ausente o no es texto")
    if not isinstance(plan.get("elementos"), list):
        raise PlanNoValido("«elementos» debe ser una lista")
    creado, caduca = float(plan["creado"]), float(plan["caduca"])
    if creado > ahora + TOLERANCIA_FUTURO_S:
        raise PlanNoValido("el plan tiene fecha de creación futura")
    if ahora > caduca or caduca - creado > CADUCIDAD_PLAN_H * 3600 + 1:
        raise PlanNoValido("el plan ha caducado: vuelve a ejecutar `scan` y `plan`")
    if plan.get("zona") is not None and not isinstance(plan["zona"], str):
        raise PlanNoValido("«zona» debe ser texto")
    if not _ID_PLAN.fullmatch(plan["id"]):
        raise PlanNoValido("identificador de plan no válido")
    if "real" in plan:                               # F4B: solo dentro de la autorización vigente
        try:
            zona = autorizacion.validar_plan_real(plan, ahora)
        except autorizacion.ErrorAutorizacion as exc:
            raise PlanNoValido(str(exc)) from exc
    else:
        zona = zona_mod.validar_zona(plan.get("zona"))   # sin zona → limpieza real deshabilitada (primera barrera)
    try:
        aut.verificar_plan(plan)                     # F3: MAC HMAC-SHA256 con la clave declarada
    except aut.ErrorAutenticacion as exc:
        raise PlanNoValido(f"autenticación: {exc}") from exc
    vistos_ruta, vistos_id, vistos_ino = set(), set(), set()
    for e in plan["elementos"]:
        if not isinstance(e, dict):
            raise PlanNoValido("elemento que no es un objeto")
        faltan = [c for c in CAMPOS_ELEMENTO if c not in e]
        if faltan:
            raise PlanNoValido(f"elemento sin campos {faltan}")
        if e["riesgo"] == "alto":
            raise PlanNoValido(f"{e['id']}: un plan no puede contener elementos de riesgo alto")
        _validar_tipos(e)
        zona_mod.exigir_dentro(e["ruta"], zona)
        if "real" in plan and e["regla"] != autorizacion.REGLA:
            raise PlanNoValido(f"{e['id']}: regla «{e['regla']}» no autorizada en {autorizacion.ID}")
        for conjunto, clave in ((vistos_ruta, e["ruta"]), (vistos_id, e["id"]), (vistos_ino, (e["dev"], e["ino"]))):
            if clave in conjunto:
                raise PlanNoValido(f"elemento duplicado: {clave}")
            conjunto.add(clave)
    if "real" in plan:
        try:
            autorizacion.comprobar_totales(plan["elementos"], plan["real"]["topes"])
        except autorizacion.ErrorAutorizacion as exc:
            raise PlanNoValido(str(exc)) from exc
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
