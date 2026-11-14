"""CLI de mac-cleaner.

F1 (solo lectura, datos reales): scan, report.
F2 (reversible, SOLO en zonas sintéticas): plan, apply, restore, purge; además oficiales y demo.
F3: sombra (evaluación sin mover nada) y clave (HMAC en el Llavero); planes y manifiestos autenticados.
`plan` también funciona sobre escaneos reales como vista previa, pero `apply` lo rechaza (zona.LIMPIEZA_REAL_HABILITADA = False).
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import platform
import sys

from . import __version__, guardia, sistema
from . import zona as zona_mod
from .config import ErrorConfig, cargar
from .escaner import Escaner
from .informe import generar
from .plan import sha256_fichero

RAIZ_PROYECTO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DEF = os.path.join(RAIZ_PROYECTO, "config", "reglas.toml")
SALIDA_DEF = os.path.join(RAIZ_PROYECTO, "informes")


def _salida(a: argparse.Namespace, zona: str | None) -> str:
    """Directorio de resultados: --salida, o <zona>/informes en modo sintético, o informes/."""
    if getattr(a, "salida", None):
        return os.path.realpath(a.salida)
    return os.path.join(zona, "informes") if zona else SALIDA_DEF


def herramientas_de_zona(zona: str) -> dict:
    """En una zona sintética las herramientas no se consultan: sus cachés son las ficticias de la zona."""
    home = os.path.join(zona, "home")
    return {"npm": {"herramienta": "npm", "disponible": True, "ruta": os.path.join(home, ".npm"), "origen": "zona sintética"},
            "pip": {"herramienta": "pip", "disponible": True, "ruta": os.path.join(home, "Library", "Caches", "pip"),
                    "origen": "zona sintética"},
            "brew": {"herramienta": "brew", "disponible": False, "motivo": "zona sintética"}}


def ejecutar_scan(cfg, *, abiertos, brew_dry_run=False, solo_reglas=None, zona=None, ahora=None,
                  herramientas_fijas=None) -> dict:
    """Escaneo completo. Devuelve el documento JSON (lo usan la CLI, demo y las pruebas)."""
    prioridad = sistema.bajar_prioridad() if cfg.baja_prioridad else []
    esc = Escaner(cfg, abiertos=abiertos, brew_dry_run=brew_dry_run, solo_reglas=solo_reglas, limite=zona, ahora=ahora,
                  herramientas_fijas=herramientas_fijas)
    res = esc.escanear()
    return {
        "herramienta": "mac-cleaner", "version": __version__, "fase": "F2" if zona else "F1",
        "generado": dt.datetime.fromtimestamp(esc.ahora).isoformat(timespec="seconds"), "ahora": esc.ahora,
        "macos": platform.mac_ver()[0], "config": cfg.origen, "config_sha256": sha256_fichero(cfg.origen),
        "zona": zona, "prioridad": prioridad,
        "lsof": {"disponible": abiertos.disponible, "n": len(abiertos), "error": abiertos.error},
        "disco": sistema.disco(), "snapshots": sistema.snapshots_locales(),
        "top_grupos": cfg.top_grupos, "escaneo": res,
    }


def _cargar_cfg_zona(config: str, zona: str | None):
    if zona:
        return cargar(config, home=os.path.join(zona, "home"), tmpdir=os.path.join(zona, "tmp"))
    return cargar(config)


def cmd_scan(a: argparse.Namespace) -> int:
    zona = zona_mod.validar_zona(a.zona_sintetica) if a.zona_sintetica else None
    a.salida = _salida(a, zona)
    # La guardia se activa antes de leer nada: a partir de aquí solo se puede escribir en la salida.
    os.makedirs(a.salida, exist_ok=True)
    guardia.activar(a.salida)
    try:
        cfg = _cargar_cfg_zona(a.config, zona)
    except ErrorConfig as exc:
        print(f"Error de configuración: {exc}", file=sys.stderr)
        return 2
    abiertos = sistema.FicherosAbiertos.capturar() if (cfg.usar_lsof and not a.sin_lsof) else sistema.FicherosAbiertos()
    datos = ejecutar_scan(cfg, abiertos=abiertos, brew_dry_run=a.brew_dry_run, solo_reglas=a.regla, zona=zona)
    datos["guardia"] = {"activa": True, "permitido": a.salida,
                        "bloqueos": [x for x in guardia.registro if x.startswith("BLOQUEADO")],
                        "subprocesos": [x for x in guardia.registro if x.startswith("subprocess")]}
    sello = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    ruta = os.path.join(a.salida, f"scan-{sello}.json")
    with open(ruta, "w", encoding="utf-8") as fh:
        json.dump(datos, fh, ensure_ascii=False, indent=1)
    res = datos["escaneo"]
    t = res["contadores"]
    print(f"Escaneo completado en {res['duracion_s']} s: {t['ficheros']:,} ficheros, "
          f"{len(res['exclusiones']['muestra'])}+ exclusiones, {res['errores']['n']} errores de acceso.")
    print(f"JSON: {ruta}")
    if a.informe:
        md = ruta[:-5] + ".md"
        with open(md, "w", encoding="utf-8") as fh:
            fh.write(generar(datos))
        print(f"Informe: {md}")
    return 0


def _ultimo(salida: str, patron: str = "scan-*.json") -> str | None:
    cands = sorted(glob.glob(os.path.join(salida, patron)))
    return cands[-1] if cands else None


def cmd_report(a: argparse.Namespace) -> int:
    ruta = a.entrada or _ultimo(a.salida or SALIDA_DEF)
    if not ruta or not os.path.exists(ruta):
        print("No hay ningún escaneo. Ejecuta primero: mac-cleaner scan", file=sys.stderr)
        return 2
    with open(ruta, encoding="utf-8") as fh:
        datos = json.load(fh)
    md = generar(datos)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"Informe: {a.out}")
    else:
        sys.stdout.write(md)
    return 0


# ── F2 ──────────────────────────────────────────────────────────────────────────

def cmd_plan(a: argparse.Namespace) -> int:
    from .plan import PlanNoValido, crear_plan, guardar
    entrada = a.entrada or _ultimo(SALIDA_DEF)
    if not entrada:
        print("Falta --entrada (JSON de scan).", file=sys.stderr)
        return 2
    with open(entrada, encoding="utf-8") as fh:
        escaneo = json.load(fh)
    zona = escaneo.get("zona")
    salida = _salida(a, zona)
    os.makedirs(salida, exist_ok=True)
    guardia.activar(salida)
    try:
        cfg = _cargar_cfg_zona(escaneo["config"], zona_mod.validar_zona(zona) if zona else None)
        abiertos = sistema.FicherosAbiertos.capturar() if not a.sin_lsof else sistema.FicherosAbiertos()
        calcular = a.hash if a.hash is not None else bool(zona)   # real: sin hash por defecto (evita leer GB)
        plan = crear_plan(escaneo, cfg, ruta_escaneo=entrada, abiertos=abiertos,
                          hash_max_bytes=cfg.hash_max_bytes, calcular_hash=calcular)
    except (PlanNoValido, ErrorConfig, zona_mod.ZonaNoValida) as exc:
        print(f"Plan rechazado: {exc}", file=sys.stderr)
        return 2
    ruta = guardar(plan, salida)
    t = plan["totales"]
    print(f"Plan {plan['id']} ({plan['modo']}): {t['elementos']} elementos, {t['bytes_fisicos'] / 1e6:.1f} MB físicos; "
          f"{plan['n_excluidos']} exclusiones. Caduca en 24 h.")
    print(f"Plan: {ruta}")
    return 0


def cmd_apply(a: argparse.Namespace) -> int:
    from .aplicar import Aplicador
    from .fsseguro import DirectorioInseguro
    from .plan import PlanNoValido, cargar as cargar_plan
    try:
        plan = cargar_plan(a.plan)
        zona = zona_mod.validar_zona(plan.get("zona"))
        guardia.activar(zona)                      # solo se puede escribir dentro de la zona
        res = Aplicador(plan).aplicar()
    except (PlanNoValido, zona_mod.ZonaNoValida, ErrorConfig, DirectorioInseguro) as exc:
        print(f"apply rechazado: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(res, ensure_ascii=False, indent=1))
    return 0 if not res["abortado"] and not res["errores"] else 1


def cmd_restore(a: argparse.Namespace) -> int:
    from .manifiesto import ManifiestoCorrupto, ManifiestoOcupado
    from .restaurar import ErrorRestauracion, restaurar
    try:
        zona = zona_mod.validar_zona(a.zona)
        guardia.activar(zona)
        res = restaurar(zona, a.operacion, elemento=a.elemento, ruta=a.ruta, sin_clave=a.recuperacion_sin_clave)
    except (zona_mod.ZonaNoValida, ManifiestoCorrupto, ManifiestoOcupado, ErrorRestauracion) as exc:
        print(f"restore rechazado: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(res, ensure_ascii=False, indent=1))
    return 0 if not res["errores"] and not res["conflictos"] else 1


def cmd_purge(a: argparse.Namespace) -> int:
    from .purgar import purgar
    try:
        zona = zona_mod.validar_zona(a.zona)
        guardia.activar(zona)
        cfg_dias = a.dias if a.dias is not None else cargar(a.config).dias_cuarentena
        res = purgar(zona, dias=cfg_dias, ejecutar=a.ejecutar)
    except (zona_mod.ZonaNoValida, ErrorConfig, ValueError) as exc:
        print(f"purge rechazado: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(res, ensure_ascii=False, indent=1))
    return 0


def cmd_oficiales(a: argparse.Namespace) -> int:
    from .oficiales import OPERACIONES
    for o in OPERACIONES:
        tipo = "REVERSIBLE " if o["reversible"] else "DESTRUCTIVA"
        print(f"[{tipo}] {o['herramienta']:5} {o['orden']}\n              {o['efecto']} — {o['uso']}")
    print("\nF2 no ejecuta ninguna orden de limpieza de estas herramientas.")
    return 0


def cmd_demo(a: argparse.Namespace) -> int:
    """Ciclo completo scan → plan → apply → restore sobre una zona sintética nueva con ficheros ficticios."""
    from .aplicar import Aplicador
    from .plan import crear_plan, guardar
    from .restaurar import restaurar
    from . import autenticacion as aut
    zona = zona_mod.crear_zona("mac-cleaner-demo-")
    if not os.environ.get(aut.ENV_SINTETICA):
        aut.establecer_almacen(aut.AlmacenSintetico.nuevo())   # demo: clave sintética efímera, nunca el Llavero
    guardia.activar(zona)
    caches = os.path.join(zona, "home", "Library", "Caches")
    for i in range(12):
        d = os.path.join(caches, f"app{i % 3}")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, f"f{i}.cache"), "wb") as fh:
            fh.write(os.urandom(4096 * (i + 1)))
    os.makedirs(os.path.join(caches, "proyecto", ".git"))
    with open(os.path.join(caches, "proyecto", "codigo.py"), "w") as fh:
        fh.write("print('protegido')\n")
    cfg_ruta = os.path.join(zona, "reglas.toml")
    with open(cfg_ruta, "w") as fh:
        fh.write('[general]\nusar_lsof = false\nbaja_prioridad = false\n[[regla]]\nid = "caches"\ntipo = "ruta"\n'
                 'rutas = ["~/Library/Caches"]\nriesgo = "medio"\nedad_minima_dias = 0\n')
    cfg = _cargar_cfg_zona(cfg_ruta, zona)
    vacio = sistema.FicherosAbiertos([], disponible=True)
    escaneo = ejecutar_scan(cfg, abiertos=vacio, zona=zona)
    plan = crear_plan(escaneo, cfg, abiertos=vacio)
    ruta_plan = guardar(plan, os.path.join(zona, "informes"))
    r_apply = Aplicador(plan, abiertos=vacio).aplicar()
    r_rest = restaurar(zona, r_apply["op"])
    print(json.dumps({"zona": zona, "plan": ruta_plan, "elementos": plan["totales"]["elementos"],
                      "excluidos": plan["n_excluidos"], "apply": {k: r_apply[k] for k in ("op", "movidos", "omitidos", "errores")},
                      "restore": {k: r_rest[k] for k in ("restaurados", "conflictos", "errores")},
                      "guardia_bloqueos": [x for x in guardia.registro if x.startswith("BLOQUEADO")]},
                     ensure_ascii=False, indent=1))
    print(f"\nLa zona queda para inspección: {zona} (bórrala cuando quieras; es un directorio temporal).")
    return 0


def cmd_sombra(a: argparse.Namespace) -> int:
    """F3: evalúa qué se limpiaría (lista blanca npm/pip), sin mover ni borrar nada. Guardia de solo lectura."""
    from . import sombra
    from .plan import PlanNoValido
    zona = zona_mod.validar_zona(a.zona_sintetica) if a.zona_sintetica else None
    salida = _salida(a, zona)
    os.makedirs(salida, exist_ok=True)
    guardia.activar(salida)
    try:
        if a.entrada:
            with open(a.entrada, encoding="utf-8") as fh:
                escaneo = json.load(fh)
            if (escaneo.get("zona") or None) != zona:
                print("El escaneo no corresponde a la zona indicada.", file=sys.stderr)
                return 2
        cfg = _cargar_cfg_zona(a.entrada and escaneo["config"] or a.config, zona)
        abiertos = sistema.FicherosAbiertos.capturar() if (cfg.usar_lsof and not a.sin_lsof) else sistema.FicherosAbiertos()
        if not a.entrada:
            escaneo = ejecutar_scan(cfg, abiertos=abiertos, zona=zona,
                                    herramientas_fijas=herramientas_de_zona(zona) if zona else None)
        ruta_ant = a.anterior or sombra.ultimo(salida)
        anterior = None
        if ruta_ant:
            with open(ruta_ant, encoding="utf-8") as fh:
                anterior = json.load(fh)
        doc = sombra.evaluar(escaneo, cfg, abiertos=abiertos, anterior=anterior)
    except (PlanNoValido, ErrorConfig, zona_mod.ZonaNoValida, OSError, ValueError) as exc:
        print(f"Sombra rechazada: {exc}", file=sys.stderr)
        return 2
    doc["guardia"] = {"activa": True, "permitido": salida,
                      "bloqueos": [x for x in guardia.registro if x.startswith("BLOQUEADO")]}
    sello = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    ruta = os.path.join(salida, f"sombra-{sello}.json")
    with open(ruta, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)
    with open(ruta[:-5] + ".md", "w", encoding="utf-8") as fh:
        fh.write(sombra.markdown(doc))
    t = doc["candidatos"]["totales"]
    print(f"Sombra: {t['ficheros']:,} candidatos; lista blanca {t['lista_blanca_ficheros']:,} ficheros "
          f"({t['lista_blanca_bytes'] / 1e6:.1f} MB). Nada se ha movido ni borrado.")
    print(f"JSON: {ruta}")
    print(f"Informe: {ruta[:-5]}.md")
    return 0


def cmd_clave(a: argparse.Namespace) -> int:
    """Gestión de la clave HMAC. crear/rotar escriben SOLO en el Llavero y solo con orden expresa del usuario."""
    from . import autenticacion as aut
    try:
        if a.accion == "estado":
            print(json.dumps(aut.almacen_actual().estado(), ensure_ascii=False, indent=1))
            return 0
        almacen = aut.AlmacenLlavero()
        c = almacen.crear() if a.accion == "crear" else almacen.rotar()
    except aut.ClaveNoDisponible as exc:
        print(f"clave: {exc}", file=sys.stderr)
        return 2
    print(f"Clave {c.id} guardada en el Llavero (servicio {aut.SERVICIO_LLAVERO}). El secreto no se muestra.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mac-cleaner", description="Diagnóstico de espacio en macOS. F1: solo lectura. "
                                "F2: limpieza reversible SOLO en zonas sintéticas.")
    p.add_argument("--version", action="version", version=f"mac-cleaner {__version__}")
    sub = p.add_subparsers(dest="orden", required=True)

    s = sub.add_parser("scan", help="Escanea las rutas autorizadas y guarda un JSON")
    s.add_argument("--config", default=CONFIG_DEF)
    s.add_argument("--salida", default=None, help="Directorio de resultados (por defecto: informes/ o <zona>/informes)")
    s.add_argument("--regla", action="append", help="Escanear solo esta regla (repetible)")
    s.add_argument("--sin-lsof", action="store_true", help="No tomar la instantánea de ficheros abiertos")
    s.add_argument("--brew-dry-run", action="store_true",
                   help="Ejecutar también `brew cleanup -n` (dry-run; ver README: puede refrescar metadatos de Homebrew)")
    s.add_argument("--informe", action="store_true", help="Generar además el informe .md junto al JSON")
    s.add_argument("--zona-sintetica", help="F2: escanear una zona sintética (HOME y TMPDIR ficticios dentro de ella)")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("report", help="Genera un informe Markdown a partir de un escaneo")
    r.add_argument("--entrada", help="JSON de scan (por defecto: el más reciente de informes/)")
    r.add_argument("--salida", default=None)
    r.add_argument("--out", help="Escribir el informe en este fichero en vez de en la salida estándar")
    r.set_defaults(func=cmd_report)

    pl = sub.add_parser("plan", help="Crea un plan (≤ 24 h) revalidando ahora los grupos recuperables de un escaneo")
    pl.add_argument("--entrada", help="JSON de scan (por defecto: el más reciente de informes/)")
    pl.add_argument("--salida", default=None)
    pl.add_argument("--sin-lsof", action="store_true")
    g = pl.add_mutually_exclusive_group()
    g.add_argument("--hash", dest="hash", action="store_true", default=None, help="Calcular SHA-256 (por defecto solo en zona)")
    g.add_argument("--sin-hash", dest="hash", action="store_false")
    pl.set_defaults(func=cmd_plan)

    ap = sub.add_parser("apply", help="Mueve a cuarentena los elementos de un plan (SOLO zonas sintéticas)")
    ap.add_argument("--plan", required=True)
    ap.set_defaults(func=cmd_apply)

    rs = sub.add_parser("restore", help="Restaura una operación completa o un elemento (SOLO zonas sintéticas)")
    rs.add_argument("--zona", required=True)
    rs.add_argument("--operacion", required=True)
    rs.add_argument("--elemento", help="Id del elemento (p. ej. e000003)")
    rs.add_argument("--ruta", help="Ruta original del elemento")
    rs.add_argument("--recuperacion-sin-clave", action="store_true",
                    help="Clave perdida: restaurar sin verificar los MAC (cadena, inodo y SHA-256 sí se comprueban)")
    rs.set_defaults(func=cmd_restore)

    pu = sub.add_parser("purge", help="Lista (o, con --ejecutar, borra en zona sintética) lo caducado en cuarentena")
    pu.add_argument("--zona", required=True)
    pu.add_argument("--dias", type=float, default=None, help="Retención en días (por defecto [cuarentena].dias = 14)")
    pu.add_argument("--config", default=CONFIG_DEF)
    pu.add_argument("--ejecutar", action="store_true", help="Borrar de verdad (solo zonas sintéticas)")
    pu.set_defaults(func=cmd_purge)

    of = sub.add_parser("oficiales", help="Operaciones de brew, npm y pip: reversibles frente a destructivas")
    of.set_defaults(func=cmd_oficiales)

    de = sub.add_parser("demo", help="Ciclo completo en una zona sintética nueva con ficheros ficticios")
    de.set_defaults(func=cmd_demo)

    so = sub.add_parser("sombra", help="F3: evalúa qué se limpiaría (lista blanca npm/pip) sin mover ni borrar nada")
    so.add_argument("--entrada", help="JSON de scan (≤ 24 h); si se omite, se escanea ahora")
    so.add_argument("--anterior", help="Sombra anterior para comparar (por defecto, la más reciente de la salida)")
    so.add_argument("--config", default=CONFIG_DEF)
    so.add_argument("--salida", default=None)
    so.add_argument("--sin-lsof", action="store_true")
    so.add_argument("--zona-sintetica", help="Evaluar una zona sintética (cachés de npm y pip ficticias)")
    so.set_defaults(func=cmd_sombra)

    cl = sub.add_parser("clave", help="F3: clave HMAC en el Llavero (estado | crear | rotar)")
    cl.add_argument("accion", choices=("estado", "crear", "rotar"))
    cl.set_defaults(func=cmd_clave)

    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
