"""Pruebas de F5B: limpieza real desde la app (autorización F5B-app-1).

NINGUNA prueba toca el HOME real: `zona.raiz_real` se sustituye por un HOME ficticio temporal, `localizar_*` y
`procesos_en_conflicto` por dobles, y la clave «real» (no sintética) vive en memoria, nunca en el Llavero.
Se usa la configuración REAL del proyecto (config/reglas.toml) con ese HOME ficticio. «Ahora» se simula 40 días en
el futuro: todo lo creado en la prueba tiene 40 días, salvo lo que se marca como reciente con utime.
"""
from __future__ import annotations

import functools
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from maccleaner import autenticacion as aut, autorizacion, cli, limpieza, listablanca, sombra, zona as zona_mod  # noqa: E402
from maccleaner.aplicar import Aplicador  # noqa: E402
from maccleaner.config import cargar  # noqa: E402
from maccleaner.manifiesto import Manifiesto  # noqa: E402
from maccleaner.plan import PlanNoValido, calcular_huella, crear_plan  # noqa: E402
from maccleaner.purgar import purgar  # noqa: E402
from maccleaner.restaurar import restaurar  # noqa: E402

from test_f2 import VACIO, escribir, huella_fichero  # noqa: E402
from test_f4b import _Almacen  # noqa: E402

DIA = 86400
CONFIG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "reglas.toml")


class F5B(unittest.TestCase):
    def setUp(self) -> None:
        self.T0 = time.time() + 40 * DIA
        self.home = os.path.realpath(tempfile.mkdtemp(prefix="mc-f5b-home-"))
        self.addCleanup(shutil.rmtree, self.home, True)
        h = lambda *p: os.path.join(self.home, *p)  # noqa: E731
        self.c_pip, self.c_npm, self.c_brew = h("Library", "Caches", "pip"), h(".npm"), h("Library", "Caches", "Homebrew")
        self.permitidos = {
            "pip": escribir(os.path.join(self.c_pip, "http-v2", "a", "b", "resp"), 4000),
            "npm": escribir(os.path.join(self.c_npm, "_cacache", "content-v2", "sha512", "ab", "blob"), 3000),
            "homebrew": escribir(os.path.join(self.c_brew, "downloads", "abc--pkg-1.0.bottle.tar.gz"), 20000),
            "logs-usuario": escribir(h("Library", "Logs", "AppVieja", "viejo.log"), 5000),
            "caches-usuario": escribir(h("Library", "Caches", "com.example.viejo", "datos.bin"), 7000),
        }
        self.intocables = [
            escribir(os.path.join(self.c_pip, "wheels", "aa", "pkg.whl"), 900),
            escribir(os.path.join(self.c_npm, "_npx", "1", "node_modules", "mcp", "index.js"), 700),
            escribir(os.path.join(self.c_brew, "api", "formula.jws.json"), 800),
            escribir(h("Library", "Logs", "Claude", "main.log"), 600),                         # nombre protegido
            escribir(h("Library", "Caches", "com.apple.algo", "cache.db"), 900),               # com.apple.*
            escribir(h("Library", "Caches", "ru.keepcoder.Telegram", "media.bin"), 900),       # riesgo alto
            escribir(h("Library", "Caches", "claude-cli-nodejs", "x.json"), 300),              # protegido en el TOML
            escribir(h("Library", "Caches", "com.example.mixto", "viejo.bin"), 500),           # grupo con algo reciente
        ]
        recientes = [escribir(h("Library", "Logs", "AppNueva", "nuevo.log"), 400),
                     escribir(h("Library", "Caches", "com.example.reciente", "f.bin"), 400),
                     escribir(h("Library", "Caches", "com.example.mixto", "nuevo.bin"), 400)]
        for p in recientes:
            os.utime(p, (self.T0 - DIA, self.T0 - DIA))
        self.intocables += recientes
        self.real_clave = aut.Clave("k-" + "2" * 16, b"\x09" * 32, False)
        aut.establecer_almacen(_Almacen(self.real_clave, aut.AlmacenSintetico.nuevo().activa()))
        self.addCleanup(aut.establecer_almacen, None)
        self.info = {"pip": {"herramienta": "pip", "disponible": True, "ruta": self.c_pip},
                     "npm": {"herramienta": "npm", "disponible": True, "ruta": self.c_npm},
                     "brew": {"herramienta": "brew", "disponible": True, "ruta": self.c_brew}}
        self.procesos: list[str] = []
        for p in (mock.patch.object(zona_mod, "raiz_real", lambda: self.home),
                  mock.patch.object(autorizacion, "localizar_pip", lambda home: dict(self.info["pip"])),
                  mock.patch.object(autorizacion, "localizar_npm", lambda home: dict(self.info["npm"])),
                  mock.patch.object(autorizacion, "localizar_brew", lambda home: dict(self.info["brew"])),
                  mock.patch.object(autorizacion, "procesos_en_conflicto", lambda: list(self.procesos))):
            p.start()
            self.addCleanup(p.stop)

    def cfg(self, ruta=CONFIG):
        return cargar(ruta, home=self.home, tmpdir=os.path.join(self.home, "tmp"))

    def escanear(self, cfg=None, ahora=None):
        return cli.ejecutar_scan(cfg or self.cfg(), abiertos=VACIO, ahora=ahora or self.T0, herramientas_fijas=self.info)

    def planificar(self, cfg=None, hasta_bytes=None, reglas=None, ahora=None):
        cfg = cfg or self.cfg()
        escaneo = self.escanear(cfg)
        doc, lista = sombra.evaluar(escaneo, cfg, abiertos=VACIO, ahora=(ahora or self.T0) + 10)
        self.assertEqual(doc["verificaciones"]["bloqueantes"], 0, doc["verificaciones"])
        return crear_plan(escaneo, cfg, abiertos=VACIO, ahora=(ahora or self.T0) + 20,
                          real={"sombra": doc, "candidatos": lista, "ruta": "s.json", "hasta_bytes": hasta_bytes,
                                "reglas": reglas})

    def aplicar(self, plan):
        return Aplicador(plan, ahora=self.T0 + 60, abiertos=VACIO).aplicar()


class TestCategorias(F5B):
    def test_plan_con_las_cinco_categorias_y_nada_mas(self):
        plan = self.planificar()
        self.assertEqual(sorted(plan["real"]["reglas"]), sorted(autorizacion.REGLAS))
        self.assertEqual({e["ruta"] for e in plan["elementos"]}, set(self.permitidos.values()))
        self.assertEqual({e["regla"] for e in plan["elementos"]}, set(self.permitidos))
        for p in self.intocables:
            self.assertNotIn(p, {e["ruta"] for e in plan["elementos"]})
        self.assertEqual(plan["real"]["topes"]["ficheros"], 5)
        self.assertTrue(all(e["sha256"] for e in plan["elementos"]))
        self.assertIsNone(plan["real"]["ventana"])

    def test_ciclo_apply_restore(self):
        antes = {p: huella_fichero(p) for p in self.permitidos.values()}
        intactos = {p: huella_fichero(p) for p in self.intocables}
        res = self.aplicar(self.planificar())
        self.assertEqual((res["movidos"], res["omitidos"], res["errores"], res["abortado"]), (5, 0, 0, None))
        self.assertTrue(all(not os.path.exists(p) for p in self.permitidos.values()))
        self.assertEqual({p: huella_fichero(p) for p in self.intocables}, intactos)
        ini = Manifiesto.cargar(res["manifiesto"]).inicio
        self.assertEqual((ini["modo"], ini["autorizacion"]), ("real", "F5B-app-1"))
        r = restaurar(self.home, res["op"])
        self.assertEqual((r["restaurados"], r["conflictos"], r["errores"]), (5, 0, 0))
        self.assertEqual({p: huella_fichero(p) for p in self.permitidos.values()}, antes)

    def test_solo_las_categorias_elegidas(self):
        plan = self.planificar(reglas=["logs-usuario", "caches-usuario"])
        self.assertEqual({e["regla"] for e in plan["elementos"]}, {"logs-usuario", "caches-usuario"})
        self.assertEqual(plan["real"]["topes"]["ficheros"], 2)

    def test_edad_minima_autorizada_aunque_el_toml_diga_menos(self):
        otro = os.path.join(self.home, "..", os.path.basename(self.home) + "-cfg.toml")
        otro = os.path.realpath(otro)
        self.addCleanup(lambda: os.path.exists(otro) and os.remove(otro))
        with open(CONFIG, encoding="utf-8") as fh:
            texto = fh.read()
        texto = texto.replace('rutas = ["~/Library/Caches"]\ndescripcion = "Cachés de aplicaciones del usuario"\n'
                              'riesgo = "medio"\nedad_minima_dias = 30',
                              'rutas = ["~/Library/Caches"]\ndescripcion = "Cachés de aplicaciones del usuario"\n'
                              'riesgo = "medio"\nedad_minima_dias = 0')
        self.assertIn("edad_minima_dias = 0", texto)
        with open(otro, "w", encoding="utf-8") as fh:
            fh.write(texto)
        plan = self.planificar(cfg=self.cfg(otro))
        rutas = {e["ruta"] for e in plan["elementos"]}
        self.assertNotIn(os.path.join(self.home, "Library", "Caches", "com.example.reciente", "f.bin"), rutas)
        self.assertTrue(all(e["edad_minima_dias"] == 30 for e in plan["elementos"] if e["regla"] == "caches-usuario"))

    def test_com_apple_nunca_en_la_lista_blanca(self):
        subs = {"caches-usuario": [os.path.join(self.home, "Library", "Caches")]}
        ok, motivo = listablanca.OFICIAL.clasificar(
            "caches-usuario", os.path.join(subs["caches-usuario"][0], "com.apple.Safari", "x"), subs)
        self.assertFalse(ok)
        self.assertIn("excluido", motivo)
        ok, _ = listablanca.OFICIAL.clasificar("caches-usuario", os.path.join(subs["caches-usuario"][0], "pip", "x"), subs)
        self.assertFalse(ok)


class TestTopesYCondiciones(F5B):
    def test_tope_confirmado_por_el_usuario(self):
        total = self.planificar()["totales"]["bytes_fisicos"]
        with self.assertRaisesRegex(PlanNoValido, "supera los topes"):
            self.planificar(hasta_bytes=total - 1)
        self.assertEqual(self.planificar(hasta_bytes=total)["real"]["topes"]["bytes_fisicos"], total)

    def test_tope_maximo_autorizado(self):
        with mock.patch.object(autorizacion, "MAX_BYTES", 4096):
            with self.assertRaisesRegex(PlanNoValido, "supera los topes"):
                self.planificar()

    def test_npm_en_ejecucion_omite_solo_npm(self):
        self.procesos = ["4242 node /opt/homebrew/bin/npx -y servidor-mcp"]
        plan = self.planificar()
        self.assertNotIn("npm", plan["real"]["reglas"])
        self.assertIn("npm", plan["omitidas"])
        self.assertEqual({e["regla"] for e in plan["elementos"]}, set(self.permitidos) - {"npm"})

    def test_ps_falla_omite_todas_las_herramientas(self):
        self.procesos = ["no se puede comprobar con ps: boom"]
        plan = self.planificar()
        self.assertEqual(sorted(plan["real"]["reglas"]), ["caches-usuario", "logs-usuario"])

    def test_cache_de_brew_en_otro_sitio_rechaza_todo(self):
        self.info["brew"] = {"herramienta": "brew", "disponible": True, "ruta": os.path.join(self.home, "otra")}
        with self.assertRaisesRegex(PlanNoValido, "no es la autorizada"):
            crear_plan(self.escanear(), self.cfg(), abiertos=VACIO, ahora=self.T0 + 20,
                       real={"sombra": {}, "candidatos": [], "ruta": ""})

    def test_brew_no_instalado_omite_homebrew(self):
        self.info["brew"] = {"herramienta": "brew", "disponible": False, "motivo": "brew no encontrado"}
        plan = self.planificar()
        self.assertNotIn("homebrew", plan["real"]["reglas"])
        self.assertIn("no disponible", plan["omitidas"]["homebrew"])

    def test_apply_revisa_las_condiciones_otra_vez(self):
        plan = self.planificar()
        self.procesos = ["99 /opt/homebrew/bin/pip3 install algo"]
        res = self.aplicar(plan)
        self.assertEqual(res["movidos"], 4)
        self.assertTrue(os.path.exists(self.permitidos["pip"]))

    def test_regla_forjada_fuera_de_la_autorizacion(self):
        plan = self.planificar()
        plan["real"]["reglas"].append("temporales")
        plan["huella"] = calcular_huella(plan)                 # forjado CON la clave: lo para la autorización
        aut.firmar_plan(plan, self.real_clave)
        with self.assertRaisesRegex(PlanNoValido, "no corresponde a la autorización"):
            Aplicador(plan, ahora=self.T0 + 60, abiertos=VACIO)


class TestPurgaReal(F5B):
    def test_purga_tras_14_dias(self):
        res = self.aplicar(self.planificar())
        t = Manifiesto.cargar(res["manifiesto"]).inicio["t"]
        self.assertEqual(purgar(None, real=True, dias=14, ahora=t + 10 * DIA, ejecutar=True)["seleccionadas"], [])
        with self.assertRaisesRegex(ValueError, "al menos 14"):
            purgar(None, real=True, dias=13, ahora=t + 20 * DIA)
        r = purgar(None, real=True, dias=14, ahora=t + 15 * DIA, ejecutar=True)
        self.assertEqual((r["borrados"], r["errores"]), (5, 0))
        self.assertTrue(all(not os.path.exists(p) for p in self.permitidos.values()))
        self.assertEqual(restaurar(self.home, res["op"])["restaurados"], 0)     # ya no hay nada que devolver

    def test_purga_real_no_autorizada(self):
        self.aplicar(self.planificar())
        with mock.patch.object(autorizacion, "PURGA_REAL", False):
            with self.assertRaises(zona_mod.ZonaNoValida):
                purgar(None, real=True, dias=14, ahora=time.time() + 20 * DIA, ejecutar=True)


class TestLimpiezaApp(F5B):
    """Los dos pasos que usa la app (`limpiar --vista-previa` y `limpiar --ejecutar`)."""

    def setUp(self) -> None:
        super().setUp()
        p = mock.patch.object(cli, "ejecutar_scan", functools.partial(cli.ejecutar_scan, herramientas_fijas=self.info))
        p.start()
        self.addCleanup(p.stop)
        self.salida = limpieza.directorio_informes(self.home)

    def test_vista_previa_y_ejecucion(self):
        vp = limpieza.vista_previa(self.cfg(), abiertos=VACIO, ahora=self.T0, salida=self.salida)
        self.assertIsNone(vp["bloqueada"])
        self.assertEqual(set(vp["reglas"]), set(self.permitidos))
        self.assertEqual(vp["total_ficheros"], 5)
        self.assertTrue(all(os.path.exists(p) for p in self.permitidos.values()))      # la vista previa no mueve nada
        res = limpieza.ejecutar(self.cfg(), hasta_bytes=vp["total_bytes"], reglas=None, ahora=self.T0 + 30,
                                salida=self.salida, abiertos=VACIO, abiertos_apply=VACIO)
        self.assertEqual((res["movidos"], res["errores"], res["abortado"]), (5, 0, None))
        self.assertTrue(res["plan"].startswith(self.salida + "/"))

    def test_vista_previa_bloqueada_si_no_queda_nada(self):
        with mock.patch.object(autorizacion, "REGLAS", ("pip",)):
            self.procesos = ["7 pip3 install x"]
            vp = limpieza.vista_previa(self.cfg(), abiertos=VACIO, ahora=self.T0, salida=self.salida)
        self.assertIn("ninguna categoría", vp["bloqueada"])
        self.assertEqual(vp["reglas"], {})


class TestPorDefecto(unittest.TestCase):
    def test_autorizacion_f5b(self):
        self.assertEqual(autorizacion.ID, "F5B-app-1")
        self.assertEqual(set(autorizacion.REGLAS), {"pip", "npm", "homebrew", "logs-usuario", "caches-usuario"})
        self.assertEqual((autorizacion.MAX_BYTES, autorizacion.DIAS_CUARENTENA), (5_000_000_000, 14))
        self.assertTrue(autorizacion.PURGA_REAL)
        self.assertFalse(autorizacion.REQUIERE_VENTANA)
        self.assertEqual(autorizacion.EDAD_MINIMA_DIAS, {"homebrew": 30, "logs-usuario": 30, "caches-usuario": 30})
        for frase in ("no com.apple.*", "Limit per cleaning: 5 GB", "14 days", "purging from the app"):
            self.assertIn(frase, autorizacion.TEXTO)
        self.assertNotIn("temporales", autorizacion.REGLAS)
        self.assertFalse(zona_mod.LIMPIEZA_REAL_HABILITADA)       # la puerta general sigue cerrada

    def test_lista_blanca_homebrew_solo_downloads(self):
        self.assertEqual(listablanca.LISTA_BLANCA["homebrew"]["subdirectorios"], ("downloads",))


if __name__ == "__main__":
    unittest.main()
