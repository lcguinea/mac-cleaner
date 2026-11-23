"""Pruebas de F4B: modo real limitado por autorizacion.py (solo pip, topes de la última sombra, ventana).

NINGUNA prueba toca el HOME real: `zona.raiz_real` se sustituye por un HOME ficticio temporal, `localizar_pip` y
`procesos_en_conflicto` por dobles, y la clave «real» (no sintética) vive en memoria, nunca en el Llavero.
"""
from __future__ import annotations

import copy
import datetime as dt
import json
import os
import shutil
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from maccleaner import autenticacion as aut, autorizacion, sombra, zona as zona_mod  # noqa: E402
from maccleaner.aplicar import Aplicador  # noqa: E402
from maccleaner.cli import ejecutar_scan, main  # noqa: E402
from maccleaner.config import cargar  # noqa: E402
from maccleaner.manifiesto import Manifiesto  # noqa: E402
from maccleaner.plan import PlanNoValido, calcular_huella, crear_plan, validar_plan  # noqa: E402
from maccleaner.purgar import purgar  # noqa: E402
from maccleaner.restaurar import restaurar  # noqa: E402
from maccleaner.sistema import FicherosAbiertos  # noqa: E402

from test_f2 import LAB, VACIO, escribir, huella_fichero  # noqa: E402
from test_f25 import elemento_forjado  # noqa: E402

TOML = """
[general]
usar_lsof = true
baja_prioridad = false
[proteccion]
rutas = ["~/.npm/_npx"]
marcadores_proyecto = [".git", "package.json"]
marcadores_venv = ["pyvenv.cfg"]
[[regla]]
id = "pip"
tipo = "herramienta"
herramienta = "pip"
riesgo = "bajo"
edad_minima_dias = 0
[[regla]]
id = "npm"
tipo = "herramienta"
herramienta = "npm"
riesgo = "bajo"
edad_minima_dias = 0
"""


def _iso(t: float) -> str:
    return dt.datetime.fromtimestamp(t).isoformat(timespec="seconds")


class Real(unittest.TestCase):
    """HOME ficticio tratado como «real» con caché de pip y npm, ventana abierta y clave no sintética en memoria."""

    def setUp(self) -> None:
        self.T0 = time.time()
        self.home = os.path.realpath(tempfile.mkdtemp(prefix="mc-f4b-home-"))
        self.addCleanup(self._limpiar)
        otro = os.path.realpath(tempfile.mkdtemp(prefix="mc-f4b-cfg-"))
        self.addCleanup(shutil.rmtree, otro, True)
        self.cfg_ruta = os.path.join(otro, "reglas.toml")
        with open(self.cfg_ruta, "w") as fh:
            fh.write(textwrap.dedent(TOML))
        self.pip = os.path.join(self.home, "Library", "Caches", "pip")
        npm = os.path.join(self.home, ".npm")
        self.permitidos = [escribir(os.path.join(self.pip, "http-v2", "a", "b", "resp"), 4000),
                           escribir(os.path.join(self.pip, "http", "x", "y", "resp"), 9000)]
        self.intocables = [escribir(os.path.join(self.pip, "wheels", "aa", "pkg.whl"), 900),
                           escribir(os.path.join(self.pip, "selfcheck", "state.json"), 50),
                           escribir(os.path.join(npm, "_cacache", "content-v2", "sha512", "ab", "blob"), 3000),
                           escribir(os.path.join(npm, "_npx", "1", "node_modules", "mcp", "index.js"), 700)]
        self.real_clave = aut.Clave("k-" + "1" * 16, b"\x07" * 32, False)
        self.sint = aut.AlmacenSintetico.nuevo()
        aut.establecer_almacen(_Almacen(self.real_clave, self.sint.activa()))
        self.addCleanup(aut.establecer_almacen, None)
        self.info_pip = {"herramienta": "pip", "disponible": True, "ruta": self.pip}
        self.info_npm = {"herramienta": "npm", "disponible": True, "ruta": npm}
        for p in (mock.patch.object(zona_mod, "raiz_real", lambda: self.home),
                  mock.patch.object(autorizacion, "localizar_pip", lambda home: dict(self.info_pip)),
                  mock.patch.object(autorizacion, "procesos_en_conflicto", lambda: []),
                  mock.patch.object(autorizacion, "VENTANA", (_iso(self.T0 - 3600), _iso(self.T0 + 3600)))):
            p.start()
            self.addCleanup(p.stop)

    def _limpiar(self):
        for base, dirs, _ in os.walk(self.home):
            for d in dirs:
                os.chmod(os.path.join(base, d), 0o700)
        shutil.rmtree(self.home, True)

    def cfg(self):
        return cargar(self.cfg_ruta, home=self.home, tmpdir=os.path.join(self.home, "tmp"))

    def escanear(self, ahora=None):
        return ejecutar_scan(self.cfg(), abiertos=VACIO, ahora=ahora or self.T0,
                             herramientas_fijas={"pip": self.info_pip, "npm": self.info_npm})

    def sombrear(self, escaneo=None, ahora=None):
        doc, lista = sombra.evaluar(escaneo or self.escanear(), self.cfg(), abiertos=VACIO, ahora=ahora or self.T0 + 30)
        return {"sombra": doc, "candidatos": lista, "ruta": "sombra-prueba.json"}

    def planificar(self, real=None, ahora=None, escaneo=None, **kw):
        escaneo = escaneo or self.escanear()
        return crear_plan(escaneo, self.cfg(), abiertos=VACIO, ahora=ahora or self.T0 + 60,
                          real=real if real is not None else self.sombrear(escaneo), **kw)

    def refirmar(self, plan, clave=None):
        plan["huella"] = calcular_huella(plan)
        aut.firmar_plan(plan, clave or self.real_clave)
        return plan

    def cuarentena(self):
        return os.path.join(self.home, ".mac-cleaner", "cuarentena")


class _Almacen:
    """Clave «real» (no sintética) y una sintética, en memoria. Nunca el Llavero."""

    def __init__(self, real, sint):
        self.claves = {real.id: real, sint.id: sint}
        self.real = real

    def activa(self):
        return self.real

    def obtener(self, cid):
        if cid not in self.claves:
            raise aut.ClaveNoDisponible(cid)
        return self.claves[cid]


# ── 1. ciclo completo ──────────────────────────────────────────────────────────

class TestCicloReal(Real):
    def test_plan_real_solo_pip_http_con_topes_de_la_sombra(self):
        plan = self.planificar()
        self.assertIsNone(plan["zona"])
        self.assertEqual({e["ruta"] for e in plan["elementos"]}, set(self.permitidos))
        self.assertEqual(plan["real"]["regla"], "pip")
        self.assertEqual(plan["real"]["topes"]["ficheros"], 2)
        self.assertEqual(plan["real"]["topes"]["bytes_fisicos"], plan["totales"]["bytes_fisicos"])
        self.assertTrue(all(e["sha256"] for e in plan["elementos"]))
        self.assertFalse(plan["autenticacion"]["sintetica"])
        motivos = {x.get("ruta"): x["motivo"] for x in plan["excluidos"]}
        self.assertTrue(any("no autorizada" in m for m in motivos.values()))   # npm
        self.assertIn("fuera de la lista blanca", motivos[self.intocables[0]])  # wheels

    def test_apply_mueve_a_la_cuarentena_real_y_restore_lo_devuelve_identico(self):
        antes = {p: huella_fichero(p) for p in self.permitidos}
        intactos = {p: huella_fichero(p) for p in self.intocables}
        res = Aplicador(self.planificar(), ahora=self.T0 + 120, abiertos=VACIO).aplicar()
        self.assertEqual((res["movidos"], res["omitidos"], res["errores"], res["abortado"]), (2, 0, 0, None))
        self.assertTrue(res["cuarentena"].startswith(self.cuarentena() + "/"))
        self.assertTrue(all(not os.path.exists(p) for p in self.permitidos))
        self.assertEqual({p: huella_fichero(p) for p in self.intocables}, intactos)
        ini = Manifiesto.cargar(res["manifiesto"]).inicio
        self.assertEqual((ini["modo"], ini["autorizacion"], ini["zona"]), ("real", autorizacion.ID, self.home))
        self.assertEqual(os.stat(os.path.join(self.home, ".mac-cleaner")).st_mode & 0o077, 0)
        r = restaurar(self.home, res["op"])
        self.assertEqual((r["restaurados"], r["conflictos"], r["errores"]), (2, 0, 0))
        self.assertEqual({p: huella_fichero(p) for p in self.permitidos}, antes)

    def test_restore_real_funciona_fuera_de_la_ventana(self):
        res = Aplicador(self.planificar(), ahora=self.T0 + 120, abiertos=VACIO).aplicar()
        with mock.patch.object(autorizacion, "VENTANA", None):
            self.assertEqual(restaurar(self.home, res["op"])["restaurados"], 2)

    def test_un_plan_real_solo_se_aplica_una_vez(self):
        plan = self.planificar()
        Aplicador(plan, ahora=self.T0 + 120, abiertos=VACIO).aplicar()
        with self.assertRaisesRegex(PlanNoValido, "ya se aplicó"):
            Aplicador(plan, ahora=self.T0 + 130, abiertos=VACIO).aplicar()

    def test_purge_real_sigue_sin_autorizar(self):
        Aplicador(self.planificar(), ahora=self.T0 + 120, abiertos=VACIO).aplicar()
        with self.assertRaises(zona_mod.ZonaNoValida):
            purgar(self.home, dias=14, ejecutar=True)


# ── 2. autorización: ventana, clave, regla ─────────────────────────────────────

class TestAutorizacion(Real):
    def test_sin_ventana_no_hay_plan_ni_apply(self):
        plan = self.planificar()
        with mock.patch.object(autorizacion, "VENTANA", None):
            with self.assertRaisesRegex(PlanNoValido, "ventana"):
                self.planificar()
            with self.assertRaisesRegex(PlanNoValido, "ventana"):
                Aplicador(plan, ahora=self.T0 + 120, abiertos=VACIO)

    def test_fuera_de_la_ventana(self):
        plan = self.planificar()
        with self.assertRaisesRegex(PlanNoValido, "fuera de la ventana"):
            Aplicador(plan, ahora=self.T0 + 3700, abiertos=VACIO)

    def test_ventana_cambiada_invalida_el_plan(self):
        plan = self.planificar()
        with mock.patch.object(autorizacion, "VENTANA", (_iso(self.T0 - 60), _iso(self.T0 + 7200))):
            with self.assertRaisesRegex(PlanNoValido, "ventana del plan"):
                Aplicador(plan, ahora=self.T0 + 120, abiertos=VACIO)

    def test_clave_sintetica_no_firma_ni_autoriza_un_plan_real(self):
        with self.assertRaisesRegex(PlanNoValido, "sintética"):
            self.planificar(clave=self.sint.activa())
        plan = self.refirmar(self.planificar(), self.sint.activa())
        with self.assertRaisesRegex(PlanNoValido, "sintética"):
            validar_plan(plan, self.T0 + 120)

    def test_plan_real_modificado_sin_clave(self):
        plan = self.planificar()
        plan["real"]["topes"]["ficheros"] = 999
        with self.assertRaisesRegex(PlanNoValido, "huella|MAC"):
            validar_plan(plan, self.T0 + 120)

    def test_plan_forjado_con_clave_tope_por_encima_de_lo_autorizado(self):
        plan = self.planificar()
        plan["real"]["topes"]["bytes_fisicos"] = autorizacion.MAX_BYTES + 1
        with self.assertRaisesRegex(PlanNoValido, "supera el autorizado"):
            validar_plan(self.refirmar(plan), self.T0 + 120)

    def test_plan_forjado_con_clave_otra_regla_u_otra_autorizacion(self):
        npm = os.path.join(self.home, ".npm", "_cacache", "content-v2", "sha512", "ab", "blob")
        plan = self.planificar()
        plan["elementos"].append(elemento_forjado(npm, "x1", regla="npm", grupo="_cacache"))
        with self.assertRaisesRegex(PlanNoValido, "no autorizada"):
            validar_plan(self.refirmar(plan), self.T0 + 120)
        for campo, valor in (("regla", "npm"), ("autorizacion", "F4B-otra"), ("raiz", "/private/tmp")):
            with self.subTest(campo):
                plan = self.planificar()
                plan["real"][campo] = valor
                with self.assertRaises(PlanNoValido):
                    validar_plan(self.refirmar(plan), self.T0 + 120)

    def test_plan_real_con_zona_declarada(self):
        plan = self.planificar()
        plan["zona"] = zona_mod.crear_zona("mc-f4b-zona-")
        self.addCleanup(shutil.rmtree, plan["zona"], True)
        with self.assertRaisesRegex(PlanNoValido, "zona"):
            validar_plan(self.refirmar(plan), self.T0 + 120)

    def test_rutas_forjadas_fuera_de_la_lista_blanca_se_omiten(self):
        plan = self.planificar()
        plan["elementos"].append(elemento_forjado(self.intocables[0], "x1", regla="pip", grupo="wheels"))
        plan["real"]["topes"]["ficheros"] += 1
        plan["real"]["topes"]["bytes_fisicos"] += 1 << 20
        intacto = huella_fichero(self.intocables[0])
        res = Aplicador(self.refirmar(plan), ahora=self.T0 + 120, abiertos=VACIO).aplicar()
        self.assertEqual((res["movidos"], res["omitidos"]), (2, 1))
        self.assertEqual(huella_fichero(self.intocables[0]), intacto)

    def test_ruta_dentro_de_mac_cleaner_rechazada(self):
        with self.assertRaises(zona_mod.ZonaNoValida):
            zona_mod.exigir_dentro(os.path.join(self.home, ".mac-cleaner", "cuarentena", "x"), self.home)

    def test_lista_blanca_inyectada_rechazada(self):
        with self.assertRaisesRegex(PlanNoValido, "OFICIAL"):
            Aplicador(self.planificar(), ahora=self.T0 + 120, abiertos=VACIO, lista_blanca=LAB)
        with self.assertRaisesRegex(PlanNoValido, "OFICIAL"):
            self.planificar(lista_blanca=LAB)


# ── 3. condiciones previas (F4.md §4.5) ────────────────────────────────────────

class TestCondiciones(Real):
    def test_cache_de_pip_en_otro_sitio(self):
        plan = self.planificar()
        self.info_pip["ruta"] = os.path.join(self.home, "otra-cache")
        with self.assertRaisesRegex(PlanNoValido, "no es la autorizada"):
            self.planificar()
        with self.assertRaisesRegex(PlanNoValido, "no es la autorizada"):
            Aplicador(plan, ahora=self.T0 + 120, abiertos=VACIO)

    def test_pip_no_disponible(self):
        self.info_pip.update(disponible=False, motivo="pip no encontrado")
        with self.assertRaisesRegex(PlanNoValido, "pip no disponible"):
            self.planificar()

    def test_sin_lsof(self):
        sin = FicherosAbiertos()
        with self.assertRaisesRegex(PlanNoValido, "lsof"):
            crear_plan(self.escanear(), self.cfg(), abiertos=sin, ahora=self.T0 + 60, real=self.sombrear())
        with self.assertRaisesRegex(PlanNoValido, "lsof"):
            Aplicador(self.planificar(), ahora=self.T0 + 120, abiertos=sin)

    def test_pip_o_npm_en_ejecucion(self):
        plan = self.planificar()
        with mock.patch.object(autorizacion, "procesos_en_conflicto", lambda: ["123 pip install x"]):
            with self.assertRaisesRegex(PlanNoValido, "en ejecución"):
                self.planificar()
            with self.assertRaisesRegex(PlanNoValido, "en ejecución"):
                Aplicador(plan, ahora=self.T0 + 120, abiertos=VACIO)

    def test_fichero_abierto_se_omite(self):
        abiertos = FicherosAbiertos([self.permitidos[0]], disponible=True)
        res = Aplicador(self.planificar(), ahora=self.T0 + 120, abiertos=abiertos).aplicar()
        self.assertEqual((res["movidos"], res["omitidos"]), (1, 1))
        self.assertTrue(os.path.exists(self.permitidos[0]))

    def test_deteccion_de_procesos(self):
        salida = "  10 /usr/bin/python3 -m pip install x\n  11 node /opt/homebrew/bin/npm ci\n  12 /bin/zsh\n" \
                 "  13 /opt/homebrew/bin/pip3 download y\n  14 /Applications/Pipeline.app/x\n"
        with mock.patch.object(autorizacion.sistema, "ejecutar", lambda argv, **kw: (0, salida, "")):
            hallados = _procesos_reales()
        self.assertEqual([h.split()[0] for h in hallados], ["10", "11", "13"])

    def test_ps_falla_se_trata_como_conflicto(self):
        with mock.patch.object(autorizacion.sistema, "ejecutar", lambda argv, **kw: (1, "", "boom")):
            self.assertTrue(_procesos_reales())


def _procesos_reales():
    """La función original (el setUp la sustituye por un doble)."""
    return _ORIGINAL_PROCESOS()


_ORIGINAL_PROCESOS = autorizacion.procesos_en_conflicto


# ── 4. topes y sombra ──────────────────────────────────────────────────────────

class TestTopes(Real):
    def test_plan_por_encima_del_tope_de_la_sombra_se_rechaza_entero(self):
        escaneo = self.escanear()
        real = self.sombrear(escaneo)
        escribir(os.path.join(self.pip, "http-v2", "nuevo", "resp"), 2000)   # pip descarga algo tras la sombra
        with self.assertRaisesRegex(PlanNoValido, "supera los topes"):
            self.planificar(real=real, escaneo=self.escanear())

    def test_tope_de_bytes_limitado_a_lo_autorizado(self):
        with mock.patch.object(autorizacion, "MAX_BYTES", 4096):
            with self.assertRaisesRegex(PlanNoValido, "supera los topes"):
                self.planificar()

    def test_sombra_sin_pip_da_tope_cero(self):
        escaneo = self.escanear()
        for p in self.permitidos:
            os.remove(p)
        real = self.sombrear(self.escanear())
        for p in self.permitidos:
            escribir(p, 3000)
        with self.assertRaisesRegex(PlanNoValido, "tope 0"):
            self.planificar(real=real, escaneo=escaneo)

    def test_nada_que_limpiar(self):
        for p in self.permitidos:
            os.remove(p)
        with self.assertRaisesRegex(PlanNoValido, "nada que limpiar"):
            self.planificar()

    def test_sombras_que_no_sirven(self):
        casos = {
            "antigua": lambda r: r["sombra"].update(ahora=self.T0 - 3 * 3600),
            "otra configuración": lambda r: r["sombra"].update(config_sha256="0" * 64),
            "bloqueantes": lambda r: r["sombra"]["verificaciones"].update(bloqueantes=1),
            "candidatos": lambda r: r["candidatos"].append(["/x", 1, 8, 0]),
            "sin candidatos": lambda r: r.update(candidatos=None),
            "tipo": lambda r: r["sombra"].update(tipo="otra-cosa"),
        }
        for nombre, estropear in casos.items():
            with self.subTest(nombre):
                real = self.sombrear()
                estropear(real)
                with self.assertRaises(PlanNoValido):
                    self.planificar(real=real)

    def test_sombra_de_zona_sintetica(self):
        real = self.sombrear()
        real["sombra"]["escaneo"]["zona"] = "/private/tmp/x"
        real["sombra"]["huella_informe"] = sombra.huella_informe(real["sombra"])
        with self.assertRaisesRegex(PlanNoValido, "zona sintética"):
            self.planificar(real=real)

    def test_apply_aborta_si_se_superarian_los_topes(self):
        ap = Aplicador(self.planificar(), ahora=self.T0 + 120, abiertos=VACIO)
        ap.topes = {"ficheros": 1, "bytes_fisicos": autorizacion.MAX_BYTES}
        res = ap.aplicar()
        self.assertEqual(res["movidos"], 1)
        self.assertIn("topes", res["abortado"])
        self.assertEqual(restaurar(self.home, res["op"])["restaurados"], 1)

    def test_escaneo_de_zona_no_vale_para_un_plan_real(self):
        escaneo = self.escanear()
        escaneo["zona"] = zona_mod.crear_zona("mc-f4b-z-")
        self.addCleanup(shutil.rmtree, escaneo["zona"], True)
        with self.assertRaisesRegex(PlanNoValido, "escaneo real"):
            crear_plan(escaneo, self.cfg(), abiertos=VACIO, ahora=self.T0 + 60, real=self.sombrear())


# ── 5. estado por defecto y CLI ────────────────────────────────────────────────

class TestPorDefecto(unittest.TestCase):
    def test_la_limpieza_real_general_sigue_deshabilitada(self):
        self.assertFalse(zona_mod.LIMPIEZA_REAL_HABILITADA)
        self.assertEqual((autorizacion.REGLA, autorizacion.MAX_BYTES), ("pip", 1_500_000_000))

    def test_raiz_real_es_el_home_del_usuario_y_no_una_zona(self):
        raiz = zona_mod.raiz_real()
        self.assertEqual(raiz, os.path.realpath(os.path.expanduser("~")))
        with self.assertRaises(zona_mod.ZonaNoValida):
            zona_mod.validar_zona(raiz)
        self.assertEqual(zona_mod.directorio_cuarentena(raiz), os.path.join(raiz, ".mac-cleaner", "cuarentena"))

    def test_restore_exige_zona_o_real(self):
        with self.assertRaises(SystemExit):
            main(["restore", "--operacion", "20260101-000000-abcdef"])
        with self.assertRaises(SystemExit):
            main(["restore", "--real", "--zona", "/private/tmp/x", "--operacion", "20260101-000000-abcdef"])


if __name__ == "__main__":
    unittest.main()
