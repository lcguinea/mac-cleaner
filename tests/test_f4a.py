"""Pruebas de F4A: lista blanca OFICIAL integrada en plan y apply, sombra v2 y observación de 7 días.

SOLO zonas sintéticas temporales y claves sintéticas en memoria. Ninguna prueba mueve, borra ni escribe datos reales.
"""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from maccleaner import autenticacion as aut, listablanca, observacion, sombra, zona as zona_mod  # noqa: E402
from maccleaner.aplicar import Aplicador  # noqa: E402
from maccleaner.cli import ejecutar_scan  # noqa: E402
from maccleaner.manifiesto import Manifiesto  # noqa: E402
from maccleaner.plan import PlanNoValido, calcular_huella, crear_plan  # noqa: E402
from maccleaner.restaurar import restaurar  # noqa: E402
from maccleaner.sistema import FicherosAbiertos  # noqa: E402

from test_f2 import DIA, ENV_CLI, PROYECTO, VACIO, escribir, huella_fichero  # noqa: E402
from test_f25 import elemento_forjado  # noqa: E402
from test_f3 import ZonaHerramientas  # noqa: E402


class Oficial(ZonaHerramientas):
    """Zona con cachés npm/pip ficticias; plan y apply con la lista blanca OFICIAL (la predeterminada)."""

    def escanear_oficial(self, ahora=None):
        return ejecutar_scan(self.cfg(), abiertos=VACIO, zona=self.zona, ahora=ahora or self.T0,
                             herramientas_fijas=zona_mod.herramientas_de_zona(self.zona))

    def plan_oficial(self, ahora=None, **kw):
        t = ahora or self.T0
        return crear_plan(self.escanear_oficial(t), self.cfg(), abiertos=VACIO, ahora=t + 60, **kw)

    def aplicar_oficial(self, plan, ahora=None, abiertos=VACIO):
        return Aplicador(plan, ahora=ahora or self.T0 + 120, abiertos=abiertos)

    def firmar(self, plan):
        plan["huella"] = calcular_huella(plan)
        aut.firmar_plan(plan, self.almacen.activa())
        return plan

    def estados(self, res):
        return Manifiesto.cargar(res["manifiesto"]).estados()


# ── 1. rutas fuera de la lista blanca ──────────────────────────────────────────

class TestListaBlancaIntegrada(Oficial):
    def test_plan_solo_contiene_npm_cacache_y_pip_http(self):
        plan = self.plan_oficial()
        self.assertEqual({e["ruta"] for e in plan["elementos"]}, set(self.permitidos))
        self.assertTrue(all(e["lista_blanca"] for e in plan["elementos"]))
        self.assertEqual(plan["lista_blanca"]["nombre"], "oficial")
        motivos = {x.get("ruta"): x["motivo"] for x in plan["excluidos"]}
        for p in self.fuera_lista + [self.node_modules_en_cache]:
            self.assertIn("fuera de la lista blanca", motivos[p])

    def test_apply_mueve_solo_lo_permitido_y_restore_lo_devuelve(self):
        intactos = {p: huella_fichero(p) for p in self.fuera_lista + self.nunca + list(self.f.values())}
        antes = {p: huella_fichero(p) for p in self.permitidos}
        res = self.aplicar_oficial(self.plan_oficial()).aplicar()
        self.assertEqual((res["movidos"], res["omitidos"]), (4, 0))
        self.assertTrue(all(not os.path.exists(p) for p in self.permitidos))
        self.todo_en_su_sitio(intactos)
        self.assertEqual(Manifiesto.cargar(res["manifiesto"]).inicio["lista_blanca"]["nombre"], "oficial")
        r = restaurar(self.zona, res["op"])
        self.assertEqual((r["restaurados"], r["errores"]), (4, 0))
        self.todo_en_su_sitio(antes)

    def test_plan_forjado_con_rutas_fuera_de_la_lista_blanca(self):
        """Un atacante CON la clave añade al plan rutas no permitidas: apply las rechaza todas."""
        plan = self.plan_oficial()
        npx = next(p for p in self.nunca if "/_npx/" in p)
        mcp = next(p for p in self.nunca if "ms-playwright-mcp" in p)
        forjados = [
            elemento_forjado(self.fuera_lista[0], "x1", regla="npm", grupo="_logs"),
            elemento_forjado(self.fuera_lista[2], "x2", regla="pip", grupo="wheels"),
            elemento_forjado(self.f["a"], "x3", regla="caches", grupo="app1"),
            elemento_forjado(self.node_modules_en_cache, "x4", regla="npm", grupo="_cacache"),
            elemento_forjado(npx, "x5", regla="npm", grupo="_npx"),
            elemento_forjado(mcp, "x6", regla="caches", grupo="ms-playwright-mcp"),
        ]
        plan["elementos"] += forjados
        intactos = {e["ruta"]: huella_fichero(e["ruta"]) for e in forjados}
        res = self.aplicar_oficial(self.firmar(plan)).aplicar()
        self.assertEqual(res["movidos"], 4)
        self.todo_en_su_sitio(intactos)
        est = self.estados(res)
        for i in ("x1", "x2", "x3", "x4"):
            self.assertIn("lista blanca", est[i]["motivo"], est[i])
        for i in ("x5", "x6"):
            self.assertTrue(est[i]["motivo"].startswith("protegido"), est[i])

    def test_cli_no_puede_usar_otra_lista_blanca(self):
        """La CLI no tiene opción para cambiar la lista blanca: en una zona solo con ~/Library/Caches no mueve nada."""
        lanz = os.path.join(PROYECTO, "mac-cleaner")
        p = subprocess.run([lanz, "apply", "--help"], capture_output=True, text=True, env=ENV_CLI, timeout=60)
        self.assertNotIn("lista", p.stdout.lower())
        p = subprocess.run([lanz, "sombra", "--help"], capture_output=True, text=True, env=ENV_CLI, timeout=60)
        self.assertNotIn("lista-blanca", p.stdout.lower())


# ── 2. manipulación de planes y configuración ──────────────────────────────────

class TestManipulacion(Oficial):
    def _toml(self, reemplazar_npm: str):
        with open(self.cfg_ruta) as fh:
            t = fh.read()
        bloque = t[t.index('[[regla]]\nid = "npm"'):t.index('[[regla]]\nid = "caches"')]
        with open(self.cfg_ruta, "w") as fh:
            fh.write(t.replace(bloque, reemplazar_npm))

    def test_toml_no_puede_ampliar_la_lista_blanca(self):
        # «npm» redefinida como regla de RUTA sobre ~/Library/Caches: la lista blanca no la reconoce.
        self._toml('[[regla]]\nid = "npm"\ntipo = "ruta"\nrutas = ["~/Library/Caches"]\nriesgo = "bajo"\nedad_minima_dias = 0\n')
        plan = self.plan_oficial()
        self.assertTrue(all(e["regla"] == "pip" for e in plan["elementos"]))
        self.assertTrue(any("no es la herramienta npm" in r["motivo"] for r in plan["lista_blanca"]["rechazos"]))

    def test_regla_npm_con_otra_herramienta(self):
        self._toml('[[regla]]\nid = "npm"\ntipo = "herramienta"\nherramienta = "brew"\nriesgo = "bajo"\nedad_minima_dias = 0\n')
        plan = self.plan_oficial()
        self.assertTrue(all(e["regla"] == "pip" for e in plan["elementos"]))

    def test_el_plan_no_decide_la_lista_blanca(self):
        plan = self.plan_oficial()
        plan["lista_blanca"]["nombre"] = "laboratorio-pruebas"
        plan["lista_blanca"]["subarboles"]["caches"] = [self.caches]
        plan["elementos"].append(elemento_forjado(self.f["b"], "x1", regla="caches", grupo="app1"))
        res = self.aplicar_oficial(self.firmar(plan)).aplicar()
        self.assertEqual(res["movidos"], 4)
        self.assertIn("lista blanca", self.estados(res)["x1"]["motivo"])
        self.assertTrue(os.path.exists(self.f["b"]))

    def test_configuracion_cambiada_despues_del_plan(self):
        plan = self.plan_oficial()
        with open(self.cfg_ruta, "a") as fh:
            fh.write("\n# cambio\n")
        with self.assertRaisesRegex(PlanNoValido, "configuración"):
            self.aplicar_oficial(plan)


# ── 3. sustitución concurrente / 4. abiertos y modificados ────────────────────

class TestConcurrencia(Oficial):
    def test_subarbol_sustituido_por_un_enlace(self):
        plan = self.plan_oficial()
        cacache = os.path.join(self.zona, "home", ".npm", "_cacache")
        os.rename(cacache, cacache + ".real")
        os.symlink(cacache + ".real", cacache)
        res = self.aplicar_oficial(plan).aplicar()
        self.assertEqual(res["movidos"], 2)                          # solo los de pip
        ids_npm = {x["id"] for x in plan["elementos"] if x["regla"] == "npm"}
        self.assertTrue(all(self.estados(res)[i]["estado"] == "omitido" for i in ids_npm))
        self.assertEqual(len(os.listdir(os.path.join(cacache + ".real", "content-v2", "sha512", "ab", "cd"))), 1)

    def test_revalidacion_inmediatamente_antes_de_mover(self):
        """Aparece un marcador de proyecto por ENCIMA de la base protegida (~/Library) durante apply: las
        protecciones de F1 no lo ven, pero la revalidación de la lista blanca justo antes de mover sí."""
        plan = self.plan_oficial()
        ap = self.aplicar_oficial(plan)
        from maccleaner import fsseguro
        n = {"i": 0}

        def renombrar(*args):
            n["i"] += 1
            if n["i"] == 1:
                escribir(os.path.join(self.zona, "home", "Library", "package.json"), 10)
            fsseguro.mover_excl(*args)

        ap._renombrar = renombrar
        res = ap.aplicar()
        est = self.estados(res)
        revalidados = [e for e in est.values() if "lista blanca revalidada" in (e.get("motivo") or "")]
        self.assertEqual(len(revalidados), 1)                        # el segundo de pip
        self.assertEqual(res["movidos"], 3)

    def test_abiertos_o_modificados(self):
        plan = self.plan_oficial()
        abierto, modificado = self.permitidos[0], self.permitidos[2]
        with open(modificado, "ab") as fh:
            fh.write(b"cambio")
        res = self.aplicar_oficial(plan, abiertos=FicherosAbiertos([abierto], disponible=True)).aplicar()
        ids = {x["ruta"]: x["id"] for x in plan["elementos"]}
        todos = self.estados(res)
        self.assertIn("abierto", todos[ids[abierto]]["motivo"])
        self.assertIn("modificado", todos[ids[modificado]]["motivo"])
        self.assertTrue(os.path.exists(abierto) and os.path.exists(modificado))
        self.assertEqual(res["movidos"], 2)

    def test_sombra_informa_de_abiertos_y_modificados(self):
        cfg = self.cfg()
        esc = self.escanear_oficial()
        os.utime(self.permitidos[1], (self.T0 + 30, self.T0 + 30))  # modificado tras el escaneo
        doc, _ = sombra.evaluar(esc, cfg, abiertos=FicherosAbiertos([self.permitidos[3]], disponible=True), ahora=self.T0 + 60)
        am = doc["abiertos_y_modificados"]
        self.assertEqual(am["abiertos_bajo_lista_blanca"], 1)
        self.assertGreaterEqual(am["modificados_desde_escaneo"], 1)
        self.assertTrue(am["grupos_excluidos_en_uso"])               # pip/http en uso → grupo excluido


# ── 5. _npx y MCP / 7. solo zonas sintéticas / 8. sin escrituras reales ────────

class TestExclusionesYZonas(Oficial):
    def test_npx_y_mcp_nunca_son_candidatos(self):
        plan = self.plan_oficial()
        doc, lista = sombra.evaluar(self.escanear_oficial(), self.cfg(), abiertos=VACIO, ahora=self.T0 + 60)
        rutas = {e["ruta"] for e in plan["elementos"]} | {r for r, *_ in lista}
        self.assertFalse(any("/_npx/" in r or "ms-playwright-mcp" in r for r in rutas))
        self.assertEqual(doc["verificaciones"]["bloqueantes"], 0)

    def test_plan_real_rechazado_por_la_cli(self):
        plan = self.plan_oficial()
        plan["zona"] = None
        self.firmar(plan)
        ruta = os.path.join(self.zona, "plan-real.json")
        with open(ruta, "w") as fh:
            json.dump(plan, fh)
        p = subprocess.run([os.path.join(PROYECTO, "mac-cleaner"), "apply", "--plan", ruta], capture_output=True,
                           text=True, env=ENV_CLI, timeout=60)
        self.assertEqual(p.returncode, 2)
        self.assertIn("deshabilitada", p.stderr)
        self.assertFalse(zona_mod.LIMPIEZA_REAL_HABILITADA)

    def test_cli_sombra_observacion_solo_escribe_en_informes(self):
        antes = self.instantanea()
        lanz = os.path.join(PROYECTO, "mac-cleaner")
        args = [lanz, "sombra", "--zona-sintetica", self.zona, "--config", self.cfg_ruta, "--sin-lsof", "--observacion"]
        p = subprocess.run(args, capture_output=True, text=True, env=ENV_CLI, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("Observación registrada", p.stdout)
        self.assertEqual(self.instantanea(), antes)                  # nada fuera de informes/ cambió
        informes = os.path.join(self.zona, "informes")
        nombres = sorted(os.listdir(informes))
        self.assertTrue(any(n.endswith("-candidatos.jsonl") for n in nombres))
        self.assertTrue(os.path.exists(os.path.join(informes, "observacion", "registro.jsonl")))
        ruta = p.stdout.split("JSON: ")[1].splitlines()[0].strip()
        with open(ruta) as fh:
            self.assertEqual(json.load(fh)["guardia"]["bloqueos"], [])

    def test_demo_usa_la_lista_blanca_oficial(self):
        env = {k: v for k, v in ENV_CLI.items() if k != aut.ENV_SINTETICA}
        p = subprocess.run([os.path.join(PROYECTO, "mac-cleaner"), "demo"], capture_output=True, text=True,
                           env=env, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        d = json.loads(p.stdout[:p.stdout.rindex("}") + 1])
        self.addCleanup(shutil.rmtree, d["zona"], True)
        self.assertEqual((d["apply"]["movidos"], d["restore"]["restaurados"]), (12, 12))
        self.assertTrue(os.path.exists(os.path.join(d["zona"], "home", ".npm", "_npx", "1", "node_modules", "mcp", "x")))


# ── 9. sombra reproducible y observación ───────────────────────────────────────

class TestSombraReproducible(Oficial):
    def test_misma_entrada_mismo_informe(self):
        esc = self.escanear_oficial()
        d1, l1 = sombra.evaluar(esc, self.cfg(), abiertos=VACIO, ahora=self.T0 + 60)
        d2, l2 = sombra.evaluar(copy.deepcopy(esc), self.cfg(), abiertos=VACIO, ahora=self.T0 + 60)
        self.assertEqual(d1, d2)
        self.assertEqual(l1, l2)
        d3, _ = sombra.evaluar(esc, self.cfg(), abiertos=VACIO, ahora=self.T0 + 3600)
        self.assertEqual(d1["huella_informe"], d3["huella_informe"])   # el momento no cambia la huella
        os.remove(self.permitidos[0])
        d4, l4 = sombra.evaluar(self.escanear_oficial(self.T0 + 10), self.cfg(), abiertos=VACIO, ahora=self.T0 + 70,
                                anterior=d1, candidatos_anteriores=l1)
        self.assertNotEqual(d1["huella_informe"], d4["huella_informe"])
        self.assertEqual((d4["cambios"]["candidatos"]["retirados"], d4["cambios"]["candidatos"]["anadidos"]), (1, 0))

    def _doc(self, dia: int, **cambios):
        doc, _ = sombra.evaluar(self.escanear_oficial(self.T0 + dia * DIA), self.cfg(), abiertos=VACIO,
                                ahora=self.T0 + dia * DIA + 60)
        doc["escaneo"]["zona"] = None if cambios.pop("como_real", True) else doc["escaneo"]["zona"]
        doc.update(cambios)
        return doc

    def test_resumen_de_observacion(self):
        """Datos SINTÉTICOS de prueba (no son observaciones): verifican las reglas del resumen."""
        salida = os.path.join(self.zona, "informes")
        for dia in range(3):
            observacion.registrar(salida, self._doc(dia), f"sombra-{dia}.json")
        observacion.registrar(salida, self._doc(2), "sombra-2b.json")         # dos el mismo día: cuenta una
        r = observacion.resumen(salida)
        self.assertEqual(r["dias_observados"], 3)
        self.assertFalse(r["criterios_objetivos_cumplidos"])
        self.assertIn("faltan observaciones", r["motivos"][0])
        for dia in range(3, 7):
            observacion.registrar(salida, self._doc(dia), f"sombra-{dia}.json")
        r = observacion.resumen(salida)
        self.assertEqual(r["dias_observados"], 7)
        self.assertTrue(r["criterios_objetivos_cumplidos"], r["motivos"])
        malo = self._doc(7)
        malo["verificaciones"] = dict(malo["verificaciones"], bloqueantes=1)
        observacion.registrar(salida, malo, "sombra-7.json")
        r = observacion.resumen(salida)
        self.assertFalse(r["criterios_objetivos_cumplidos"])
        self.assertTrue(any("bloqueantes" in m for m in r["motivos"]))
        self.assertIn("Cumplir los criterios objetivos NO autoriza F4B", observacion.markdown(r))

    def test_resumen_ignora_ejecuciones_sinteticas(self):
        salida = os.path.join(self.zona, "informes")
        observacion.registrar(salida, self._doc(0, como_real=False), "sombra-z.json")
        self.assertEqual(observacion.resumen(salida)["dias_observados"], 0)
        self.assertEqual(observacion.resumen(salida, incluir_sinteticas=True)["dias_observados"], 1)


if __name__ == "__main__":
    unittest.main()
