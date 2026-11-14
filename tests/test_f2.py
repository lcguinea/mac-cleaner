"""Pruebas de F2 (plan, apply, restore, purge). SOLO datos ficticios dentro de zonas sintéticas temporales."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import textwrap
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from maccleaner import fsseguro, oficiales, zona as zona_mod  # noqa: E402
from maccleaner.aplicar import Aplicador, directorio_cuarentena  # noqa: E402
from maccleaner.cli import ejecutar_scan  # noqa: E402
from maccleaner.config import cargar  # noqa: E402
from maccleaner.escaner import Escaner  # noqa: E402
from maccleaner.informe import generar  # noqa: E402
from maccleaner.manifiesto import Manifiesto, ManifiestoCorrupto  # noqa: E402
from maccleaner.plan import PlanNoValido, calcular_huella, crear_plan, guardar  # noqa: E402
from maccleaner.purgar import purgar, seleccionar  # noqa: E402
from maccleaner.restaurar import restaurar  # noqa: E402
from maccleaner.sistema import FicherosAbiertos  # noqa: E402

DIA = 86400
PROYECTO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VACIO = FicherosAbiertos([], disponible=True)


class Caida(BaseException):
    """Simula que el proceso muere (SIGKILL): no la captura `except Exception`."""


def escribir(ruta: str, n: int) -> str:
    os.makedirs(os.path.dirname(ruta), exist_ok=True)
    with open(ruta, "wb") as fh:
        fh.write(os.urandom(n))
    return ruta


def xattr(ruta: str, valor: str | None = None) -> str:
    if valor is not None:
        subprocess.run(["/usr/bin/xattr", "-w", "com.mac-cleaner.prueba", valor, ruta], check=True)
    p = subprocess.run(["/usr/bin/xattr", "-p", "com.mac-cleaner.prueba", ruta], capture_output=True, text=True)
    return p.stdout.strip()


def huella_fichero(ruta: str) -> tuple:
    st = os.lstat(ruta)
    with open(ruta, "rb") as fh:
        h = hashlib.sha256(fh.read()).hexdigest()
    return (h, st.st_mode, st.st_uid, st.st_size, st.st_mtime_ns, st.st_ino, st.st_birthtime, xattr(ruta))


class ZonaBase(unittest.TestCase):
    EDAD = 30

    def setUp(self) -> None:
        self.zona = zona_mod.crear_zona("mc-f2-test-")
        self.caches = os.path.join(self.zona, "home", "Library", "Caches")
        self.cfg_ruta = os.path.join(self.zona, "reglas.toml")
        with open(self.cfg_ruta, "w") as fh:
            fh.write(textwrap.dedent(f"""
                [general]
                usar_lsof = false
                baja_prioridad = false
                [cuarentena]
                dias = 14
                [proteccion]
                nombres = ['(ableton|remotion)']
                extensiones = [".als", ".gguf"]
                marcadores_proyecto = [".git", "package.json"]
                marcadores_venv = ["pyvenv.cfg"]
                [[ajuste_riesgo]]
                patron = 'telegram'
                riesgo = "alto"
                motivo = "medios"
                [[regla]]
                id = "caches"
                tipo = "ruta"
                rutas = ["~/Library/Caches"]
                riesgo = "medio"
                edad_minima_dias = {self.EDAD}
            """))
        self.f = {
            "a": escribir(os.path.join(self.caches, "app1", "a.bin"), 10_000),
            "b": escribir(os.path.join(self.caches, "app1", "sub", "b.bin"), 5_000),
            "c": escribir(os.path.join(self.caches, "app2", "c.bin"), 20_000),
            "d": escribir(os.path.join(self.caches, "app3", "d.bin"), 7_000),
        }
        # Protegidos o de riesgo alto: nunca deben llegar a un plan.
        self.protegidos = [
            escribir(os.path.join(self.caches, "claude-cli-nodejs", "k.bin"), 3000),
            escribir(os.path.join(self.caches, "com.anthropic.x", "k.bin"), 3000),
            escribir(os.path.join(self.caches, "argos-cache", "k.bin"), 3000),
            escribir(os.path.join(self.caches, "aeon_tools", "k.bin"), 3000),
            escribir(os.path.join(self.caches, "proyecto", "src.py"), 3000),
            escribir(os.path.join(self.caches, "entorno", "lib.py"), 3000),
            escribir(os.path.join(self.caches, "app1", "cancion.als"), 3000),
            escribir(os.path.join(self.caches, "ru.keepcoder.Telegram", "media.bin"), 3000),
        ]
        os.makedirs(os.path.join(self.caches, "proyecto", ".git"))
        escribir(os.path.join(self.caches, "entorno", "pyvenv.cfg"), 10)
        self.fuera = escribir(os.path.join(self.zona, "fuera", "ajeno.bin"), 4000)   # dentro de la zona, fuera de las bases
        self.T0 = time.time() + 40 * DIA     # «ahora» simulado: todo lo creado tiene 40 días

    def tearDown(self) -> None:
        for d, dirs, _ in os.walk(self.zona):
            for x in dirs:
                try:
                    os.chmod(os.path.join(d, x), 0o755)
                except OSError:
                    pass
        shutil.rmtree(self.zona, ignore_errors=True)

    # ── utilidades ──
    def cfg(self):
        return cargar(self.cfg_ruta, home=os.path.join(self.zona, "home"), tmpdir=os.path.join(self.zona, "tmp"))

    def escanear(self, ahora=None):
        return ejecutar_scan(self.cfg(), abiertos=VACIO, zona=self.zona, ahora=ahora or self.T0)

    def planificar(self, escaneo=None, ahora=None, **kw):
        return crear_plan(escaneo or self.escanear(), self.cfg(), abiertos=VACIO, ahora=ahora or self.T0 + 60, **kw)

    def aplicador(self, plan, ahora=None, abiertos=VACIO):
        return Aplicador(plan, ahora=ahora or self.T0 + 120, abiertos=abiertos)

    def rutas_plan(self, plan):
        return {e["ruta"] for e in plan["elementos"]}

    def retocar(self, plan):
        plan["huella"] = calcular_huella(plan)
        return plan

    def todo_en_su_sitio(self, antes: dict):
        for ruta, h in antes.items():
            self.assertTrue(os.path.exists(ruta), f"falta {ruta}")
            self.assertEqual(huella_fichero(ruta), h, f"{ruta} no es idéntico al original")


class TestPlan(ZonaBase):
    def test_plan_solo_incluye_lo_admisible(self):
        plan = self.planificar()
        self.assertEqual(self.rutas_plan(plan), set(self.f.values()))
        for p in self.protegidos:
            self.assertNotIn(p, self.rutas_plan(plan))
        self.assertTrue(all(e["sha256"] and e["ino"] and e["mtime_ns"] for e in plan["elementos"]))
        self.assertEqual(plan["huella"], calcular_huella(plan))
        self.assertIn("no es una firma", plan["nota_huella"])

    def test_escaneo_caducado_o_futuro(self):
        esc = self.escanear()
        with self.assertRaisesRegex(PlanNoValido, "más de 24 h"):
            self.planificar(esc, ahora=self.T0 + 25 * 3600)
        with self.assertRaisesRegex(PlanNoValido, "futura"):
            self.planificar(esc, ahora=self.T0 - 3600)

    def test_configuracion_cambiada_desde_el_escaneo(self):
        esc = self.escanear()
        with open(self.cfg_ruta, "a") as fh:
            fh.write("\n# cambio\n")
        with self.assertRaisesRegex(PlanNoValido, "configuración cambió"):
            self.planificar(esc)

    def test_modificado_despues_del_escaneo_reevalua_el_grupo(self):
        esc = self.escanear()
        nuevo = escribir(os.path.join(self.caches, "app2", "reciente.bin"), 100)
        os.utime(nuevo, (self.T0 - DIA, self.T0 - DIA))   # reciente respecto al «ahora» simulado
        plan = self.planificar(esc)
        self.assertNotIn(self.f["c"], self.rutas_plan(plan))
        self.assertTrue(any(x["grupo"] == "app2" and "activo ahora" in x["motivo"] for x in plan["excluidos"]))

    def test_grupo_abierto_ahora_se_excluye(self):
        esc = self.escanear()
        plan = crear_plan(esc, self.cfg(), abiertos=FicherosAbiertos([self.f["d"]], disponible=True), ahora=self.T0 + 60)
        self.assertNotIn(self.f["d"], self.rutas_plan(plan))


class TestApplyRestore(ZonaBase):
    def test_ciclo_completo_restauracion_exacta(self):
        os.chmod(self.f["a"], 0o640)
        xattr(self.f["b"], "valor-de-prueba")
        os.utime(self.f["c"], ns=(1_700_000_000_123_456_789, 1_600_000_000_987_654_321))
        self.T0 = time.time() + 40 * DIA
        antes = {r: huella_fichero(r) for r in self.f.values()}
        protegidos_antes = {r: huella_fichero(r) for r in self.protegidos + [self.fuera]}
        plan = self.planificar()
        res = self.aplicador(plan).aplicar()
        self.assertEqual((res["movidos"], res["omitidos"], res["errores"]), (4, 0, 0))
        for r in self.f.values():
            self.assertFalse(os.path.exists(r))
        qarch = os.path.join(res["cuarentena"], "archivos")
        self.assertTrue(os.path.exists(os.path.join(qarch, "home/Library/Caches/app1/sub/b.bin")))
        self.todo_en_su_sitio(protegidos_antes)
        r = restaurar(self.zona, res["op"])
        self.assertEqual((r["restaurados"], r["conflictos"], r["errores"]), (4, 0, 0))
        self.todo_en_su_sitio(antes)          # contenido, modo, uid, tamaño, mtime_ns, inodo, birthtime, xattr
        self.todo_en_su_sitio(protegidos_antes)

    def test_restaurar_un_elemento(self):
        plan = self.planificar()
        res = self.aplicador(plan).aplicar()
        eid = next(e["id"] for e in plan["elementos"] if e["ruta"] == self.f["d"])
        r = restaurar(self.zona, res["op"], elemento=eid)
        self.assertEqual(r["restaurados"], 1)
        self.assertTrue(os.path.exists(self.f["d"]))
        self.assertFalse(os.path.exists(self.f["a"]))
        r = restaurar(self.zona, res["op"], ruta=self.f["a"])
        self.assertEqual(r["restaurados"], 1)
        self.assertEqual(restaurar(self.zona, res["op"])["restaurados"], 2)   # quedan b y c
        self.assertEqual(restaurar(self.zona, res["op"])["restaurados"], 0)   # idempotente

    def test_fichero_modificado_tras_el_plan(self):
        plan = self.planificar()
        with open(self.f["a"], "ab") as fh:
            fh.write(b"cambio")
        os.utime(self.f["b"], (time.time(), time.time() - 5))   # solo mtime
        res = self.aplicador(plan).aplicar()
        man = Manifiesto.cargar(res["manifiesto"])
        motivos = {e["origen"] if "origen" in e else e["id"]: e.get("motivo") for e in man.estados().values()}
        self.assertEqual(res["movidos"], 2)
        self.assertTrue(os.path.exists(self.f["a"]) and os.path.exists(self.f["b"]))
        self.assertTrue(all("modificado" in (m or "") for k, m in motivos.items() if k.startswith("e")))

    def test_contenido_cambiado_con_metadatos_falsificados(self):
        plan = self.planificar()
        st = os.lstat(self.f["d"])
        with open(self.f["d"], "r+b") as fh:
            fh.write(b"X")                                   # mismo tamaño
        os.utime(self.f["d"], ns=(st.st_atime_ns, st.st_mtime_ns))
        # ctime cambia siempre, así que se ajusta el plan como haría un atacante con la huella recalculada.
        e = next(x for x in plan["elementos"] if x["ruta"] == self.f["d"])
        e["ctime_ns"] = os.lstat(self.f["d"]).st_ctime_ns
        res = self.aplicador(self.retocar(plan)).aplicar()
        self.assertTrue(os.path.exists(self.f["d"]))
        est = Manifiesto.cargar(res["manifiesto"]).estados()[e["id"]]
        self.assertIn("SHA-256", est["motivo"])

    def test_enlace_simbolico_en_lugar_del_fichero(self):
        plan = self.planificar()
        os.remove(self.f["a"])
        os.symlink(self.fuera, self.f["a"])
        antes_fuera = huella_fichero(self.fuera)
        res = self.aplicador(plan).aplicar()
        self.assertEqual(res["movidos"], 3)
        self.assertTrue(os.path.islink(self.f["a"]))
        self.assertEqual(huella_fichero(self.fuera), antes_fuera)

    def test_directorio_intermedio_sustituido_por_enlace(self):
        plan = self.planificar()
        sub = os.path.join(self.caches, "app1", "sub")
        os.rename(sub, sub + "_real")
        os.symlink(sub + "_real", sub)                       # mismo fichero (mismo inodo) detrás de un enlace
        res = self.aplicador(plan).aplicar()
        self.assertTrue(os.path.exists(os.path.join(sub + "_real", "b.bin")))
        eid = next(e["id"] for e in plan["elementos"] if e["ruta"] == self.f["b"])
        self.assertIn("ruta cambiada", Manifiesto.cargar(res["manifiesto"]).estados()[eid]["motivo"])

    def test_ruta_sustituida_por_otro_fichero(self):
        plan = self.planificar()
        with open(self.f["c"], "rb") as fh:
            datos = fh.read()
        os.remove(self.f["c"])
        with open(self.f["c"], "wb") as fh:
            fh.write(datos)                                  # mismo contenido, otro inodo
        res = self.aplicador(plan).aplicar()
        self.assertTrue(os.path.exists(self.f["c"]))
        self.assertEqual(res["movidos"], 3)

    def test_abierto_o_de_otro_propietario(self):
        plan = self.planificar()
        res = self.aplicador(plan, abiertos=FicherosAbiertos([self.f["a"]], disponible=True)).aplicar()
        self.assertEqual(res["movidos"], 3)
        self.assertTrue(os.path.exists(self.f["a"]))
        restaurar(self.zona, res["op"])
        plan = self.planificar()
        ap = self.aplicador(plan)
        ap.uid = 99999
        self.assertEqual(ap.aplicar()["movidos"], 0)

    @unittest.skipIf(os.geteuid() == 0, "como root los permisos no bloquean")
    def test_error_de_permisos_aborta_sin_perder_nada(self):
        antes = {r: huella_fichero(r) for r in self.f.values()}
        plan = self.planificar()
        os.chmod(os.path.join(self.caches, "app2"), 0o555)   # no se pueden sacar entradas de app2
        res = self.aplicador(plan).aplicar()
        self.assertEqual(res["errores"], 1)
        self.assertIn("error del sistema", res["abortado"])
        man = Manifiesto.cargar(res["manifiesto"])
        self.assertTrue(man.cerrado)
        r = restaurar(self.zona, res["op"])
        self.assertEqual(r["errores"], 0)
        self.todo_en_su_sitio(antes)

    def test_caida_tras_mover_y_antes_de_registrar(self):
        antes = {r: huella_fichero(r) for r in self.f.values()}
        plan = self.planificar()
        ap = self.aplicador(plan)
        n = {"i": 0}

        def renombrar(*args):
            n["i"] += 1
            fsseguro.mover_excl(*args)
            if n["i"] == 3:
                raise Caida()                                 # movido, pero sin registro «movido»

        ap._renombrar = renombrar
        with self.assertRaises(Caida):
            ap.aplicar()
        qbase = directorio_cuarentena(self.zona)
        op = os.listdir(qbase)[0]
        man = Manifiesto.cargar(os.path.join(qbase, op, "manifiesto.jsonl"))
        self.assertFalse(man.cerrado)
        self.assertEqual(sum(1 for e in man.estados().values() if e["estado"] == "intento"), 1)
        r = restaurar(self.zona, op)
        self.assertEqual((r["restaurados"], r["errores"]), (3, 0))
        self.todo_en_su_sitio(antes)

    def test_caida_antes_de_mover(self):
        antes = {r: huella_fichero(r) for r in self.f.values()}
        plan = self.planificar()
        ap = self.aplicador(plan)

        def renombrar(*args):
            raise Caida()

        ap._renombrar = renombrar
        with self.assertRaises(Caida):
            ap.aplicar()
        op = os.listdir(directorio_cuarentena(self.zona))[0]
        r = restaurar(self.zona, op)
        self.assertEqual((r["restaurados"], r["sin_cambios"], r["errores"]), (0, 1, 0))
        self.todo_en_su_sitio(antes)

    def test_conflicto_con_fichero_existente(self):
        plan = self.planificar()
        res = self.aplicador(plan).aplicar()
        with open(self.f["a"], "wb") as fh:
            fh.write(b"fichero nuevo del usuario")
        r = restaurar(self.zona, res["op"])
        self.assertEqual((r["restaurados"], r["conflictos"]), (3, 1))
        with open(self.f["a"], "rb") as fh:
            self.assertEqual(fh.read(), b"fichero nuevo del usuario")   # nunca se sobrescribe
        os.remove(self.f["a"])
        self.assertEqual(restaurar(self.zona, res["op"])["restaurados"], 1)

    def test_conflicto_directorio_de_destino_desaparecido(self):
        plan = self.planificar()
        res = self.aplicador(plan).aplicar()
        shutil.rmtree(os.path.join(self.caches, "app3"))
        r = restaurar(self.zona, res["op"], ruta=self.f["d"])
        self.assertEqual(r["conflictos"], 1)
        self.assertFalse(os.path.exists(os.path.join(self.caches, "app3")))   # no se recrea a escondidas


class TestPlanManipulado(ZonaBase):
    def test_huella_rota(self):
        plan = self.planificar()
        plan["elementos"][0]["tam"] += 1
        with self.assertRaisesRegex(PlanNoValido, "huella"):
            self.aplicador(plan)

    def test_caducado_y_futuro(self):
        plan = self.planificar()
        with self.assertRaisesRegex(PlanNoValido, "caducado"):
            self.aplicador(plan, ahora=plan["caduca"] + 1)
        with self.assertRaisesRegex(PlanNoValido, "futura"):
            self.aplicador(plan, ahora=plan["creado"] - 3600)
        plan["caduca"] = plan["creado"] + 30 * DIA       # caducidad alargada con la huella recalculada
        with self.assertRaisesRegex(PlanNoValido, "caducado"):
            self.aplicador(self.retocar(plan), ahora=plan["creado"] + 2 * DIA)

    def test_ruta_fuera_de_la_zona_o_real(self):
        plan = self.planificar()
        plan["elementos"][0]["ruta"] = os.path.expanduser("~/Library/Caches/x.bin")
        with self.assertRaises(zona_mod.ZonaNoValida):
            self.aplicador(self.retocar(plan))
        plan = self.planificar()
        plan["elementos"][0]["ruta"] = self.f["a"].replace("/app1/", "/app1/../app2/")
        with self.assertRaises(zona_mod.ZonaNoValida):
            self.aplicador(self.retocar(plan))
        plan = self.planificar()
        plan["zona"] = None                               # plan «real»: deshabilitado en F2
        with self.assertRaisesRegex(zona_mod.ZonaNoValida, "deshabilitada"):
            self.aplicador(self.retocar(plan))

    def test_elemento_protegido_inyectado(self):
        plan = self.planificar()
        for i, p in enumerate(self.protegidos[:5] + [self.fuera]):
            st = os.lstat(p)
            plan["elementos"].append({
                "id": f"x{i}", "regla": "caches", "grupo": "x", "riesgo": "medio", "ruta": p, "dev": st.st_dev,
                "ino": st.st_ino, "uid": st.st_uid, "modo": st.st_mode, "tam": st.st_size, "bloques": st.st_blocks,
                "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns, "sha256": None, "edad_minima_dias": 0})
        antes = {p: huella_fichero(p) for p in self.protegidos + [self.fuera]}
        res = self.aplicador(self.retocar(plan)).aplicar()
        self.assertEqual(res["movidos"], 4)
        self.todo_en_su_sitio(antes)
        est = Manifiesto.cargar(res["manifiesto"]).estados()
        self.assertTrue(all(est[f"x{i}"]["motivo"].startswith("protegido") for i in range(6)))

    def test_riesgo_alto_duplicados_y_campos(self):
        plan = self.planificar()
        p2 = copy.deepcopy(plan)
        p2["elementos"][0]["riesgo"] = "alto"
        with self.assertRaisesRegex(PlanNoValido, "riesgo alto"):
            self.aplicador(self.retocar(p2))
        p3 = copy.deepcopy(plan)
        p3["elementos"].append(dict(p3["elementos"][0], id="otro"))
        with self.assertRaisesRegex(PlanNoValido, "duplicado"):
            self.aplicador(self.retocar(p3))
        p4 = copy.deepcopy(plan)
        del p4["elementos"][0]["ino"]
        with self.assertRaisesRegex(PlanNoValido, "campos"):
            self.aplicador(self.retocar(p4))
        p5 = copy.deepcopy(plan)
        p5["home"] = os.path.expanduser("~")
        with self.assertRaisesRegex(PlanNoValido, "home"):
            self.aplicador(self.retocar(p5))


class TestManifiestoYPurga(ZonaBase):
    def _operacion(self):
        res = self.aplicador(self.planificar()).aplicar()
        return res, Manifiesto.cargar(res["manifiesto"])

    def test_manifiesto_modificado_o_con_hueco(self):
        res, _ = self._operacion()
        with open(res["manifiesto"]) as fh:
            lineas = fh.read().splitlines()
        alterado = lineas[:]
        reg = json.loads(alterado[2])
        reg["origen"] = "/otra/ruta"
        alterado[2] = json.dumps(reg)
        with open(res["manifiesto"], "w") as fh:
            fh.write("\n".join(alterado) + "\n")
        with self.assertRaises(ManifiestoCorrupto):
            restaurar(self.zona, res["op"])
        with open(res["manifiesto"], "w") as fh:
            fh.write("\n".join(lineas[:2] + lineas[3:]) + "\n")   # registro intermedio eliminado
        with self.assertRaises(ManifiestoCorrupto):
            Manifiesto.cargar(res["manifiesto"])
        with open(res["manifiesto"], "w") as fh:
            fh.write("\n".join(lineas[:-1]) + "\n")                # sin «cierre»: válido pero incompleto
        man = Manifiesto.cargar(res["manifiesto"])
        self.assertFalse(man.cerrado)
        sel = seleccionar(self.zona, dias=14, ahora=man.inicio["t"] + 30 * DIA)
        self.assertEqual(sel["seleccionadas"], [])
        self.assertIn("sin cierre", sel["descartadas"][0]["motivo"])

    def test_purga_por_antiguedad_configurable(self):
        res, man = self._operacion()
        t = man.inicio["t"]
        self.assertEqual(seleccionar(self.zona, dias=14, ahora=t + 5 * DIA)["seleccionadas"], [])
        self.assertEqual(len(seleccionar(self.zona, dias=3, ahora=t + 5 * DIA)["seleccionadas"]), 1)
        sel = seleccionar(self.zona, dias=14, ahora=t + 20 * DIA)
        self.assertEqual(len(sel["seleccionadas"][0]["elementos"]), 4)
        self.assertEqual(cargar(os.path.join(PROYECTO, "config", "reglas.toml")).dias_cuarentena, 14)
        r = purgar(self.zona, dias=14, ahora=t + 20 * DIA)          # sin ejecutar: solo lista
        self.assertFalse(r["ejecutado"])
        self.assertTrue(all(os.path.exists(x["destino"]) for x in r["seleccionadas"][0]["elementos"]))

    def test_purga_ejecutada_solo_borra_lo_registrado(self):
        res, man = self._operacion()
        restaurar(self.zona, res["op"], ruta=self.f["a"])            # restaurado: no se purga
        intruso = escribir(os.path.join(res["cuarentena"], "archivos", "intruso.bin"), 100)
        r = purgar(self.zona, dias=14, ahora=man.inicio["t"] + 20 * DIA, ejecutar=True)
        self.assertEqual((r["borrados"], r["errores"]), (3, 0))
        self.assertTrue(os.path.exists(self.f["a"]))
        self.assertTrue(os.path.exists(intruso))                    # no estaba en el manifiesto
        est = Manifiesto.cargar(res["manifiesto"]).estados()
        self.assertEqual(sorted(e["estado"] for e in est.values()), ["purgado"] * 3 + ["restaurado"])
        self.assertEqual(restaurar(self.zona, res["op"])["restaurados"], 0)
        for p in self.protegidos:
            self.assertTrue(os.path.exists(p))

    def test_purga_no_borra_si_cambia_el_inodo(self):
        res, man = self._operacion()
        dest = next(e["destino"] for e in man.estados().values())
        os.remove(dest)
        escribir(dest, 50)                                          # otro fichero en el mismo sitio
        r = purgar(self.zona, dias=14, ahora=man.inicio["t"] + 20 * DIA, ejecutar=True)
        self.assertEqual(r["errores"], 1)
        self.assertTrue(os.path.exists(dest))


class TestZona(unittest.TestCase):
    def test_puerta_de_zona(self):
        import tempfile
        with self.assertRaisesRegex(zona_mod.ZonaNoValida, "deshabilitada"):
            zona_mod.validar_zona(None)
        for real in ("~/Library/Caches", "~", "/private/tmp", os.environ.get("TMPDIR", "/private/tmp")):
            with self.assertRaises(zona_mod.ZonaNoValida):
                zona_mod.validar_zona(os.path.realpath(os.path.expanduser(real)))
        d = os.path.realpath(tempfile.mkdtemp(prefix="mc-zona-"))
        try:
            with self.assertRaisesRegex(zona_mod.ZonaNoValida, "marcador"):
                zona_mod.validar_zona(d)
            with open(os.path.join(d, zona_mod.MARCADOR), "w") as fh:
                fh.write("otra cosa")
            with self.assertRaisesRegex(zona_mod.ZonaNoValida, "contenido"):
                zona_mod.validar_zona(d)
            os.remove(os.path.join(d, zona_mod.MARCADOR))
            buena = zona_mod.crear_zona("mc-zona-buena-")
            os.symlink(os.path.join(buena, zona_mod.MARCADOR), os.path.join(d, zona_mod.MARCADOR))
            with self.assertRaisesRegex(zona_mod.ZonaNoValida, "regular"):
                zona_mod.validar_zona(d)
            enlace = d + "-enlace"
            os.symlink(buena, enlace)
            with self.assertRaisesRegex(zona_mod.ZonaNoValida, "canónica"):
                zona_mod.validar_zona(enlace)
            os.chmod(buena, 0o777)
            with self.assertRaisesRegex(zona_mod.ZonaNoValida, "cualquiera"):
                zona_mod.validar_zona(buena)
            os.chmod(buena, 0o700)
            self.assertEqual(zona_mod.validar_zona(buena), buena)
            self.assertFalse(zona_mod.LIMPIEZA_REAL_HABILITADA)
        finally:
            for p in (d, d + "-enlace"):
                if os.path.islink(p):
                    os.remove(p)
            shutil.rmtree(d, ignore_errors=True)
            shutil.rmtree(buena, ignore_errors=True)


class TestCompatibilidadYCLI(ZonaBase):
    EDAD = 0

    def test_f1_ignora_la_cuarentena_y_report_sigue_funcionando(self):
        res = self.aplicador(self.planificar()).aplicar()
        os.makedirs(os.path.join(self.caches, ".mac-cleaner-cuarentena"))
        escribir(os.path.join(self.caches, ".mac-cleaner-cuarentena", "x.bin"), 100)
        esc = self.escanear(ahora=time.time())
        nombres = {g["nombre"] for r in esc["escaneo"]["reglas"] for g in r["grupos"]}
        self.assertNotIn(".mac-cleaner-cuarentena", nombres)
        self.assertIn("Ocupado ≠ recuperable", generar(esc))
        viejo = os.path.join(PROYECTO, "informes", "scan-20261114-150517.json")
        if os.path.exists(viejo):                       # JSON de F1 (sin config_sha256 ni zona)
            with open(viejo) as fh:
                self.assertIn("Resumen por regla", generar(json.load(fh)))
        self.assertTrue(res["movidos"] > 0)

    def test_cli_ciclo_completo_con_guardia(self):
        lanz = os.path.join(PROYECTO, "mac-cleaner")
        env = {"PATH": "/usr/bin:/bin:/usr/sbin", "HOME": os.path.expanduser("~"), "TMPDIR": os.environ.get("TMPDIR", "")}

        def run(*args):
            return subprocess.run([lanz, *args], capture_output=True, text=True, env=env, timeout=120)

        p = run("scan", "--zona-sintetica", self.zona, "--config", self.cfg_ruta, "--sin-lsof")
        self.assertEqual(p.returncode, 0, p.stderr)
        scan_json = p.stdout.split("JSON: ")[1].strip()
        self.assertTrue(scan_json.startswith(self.zona))
        p = run("plan", "--entrada", scan_json, "--sin-lsof")
        self.assertEqual(p.returncode, 0, p.stderr)
        plan_json = p.stdout.split("Plan: ")[1].strip()
        antes = {r: huella_fichero(r) for r in self.f.values()}
        p = run("apply", "--plan", plan_json)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        res = json.loads(p.stdout)
        self.assertEqual(res["movidos"], 4)
        p = run("purge", "--zona", self.zona)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(json.loads(p.stdout)["ejecutado"])
        p = run("restore", "--zona", self.zona, "--operacion", res["op"])
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.todo_en_su_sitio(antes)
        # Un plan sin zona (real) se rechaza por la CLI.
        with open(plan_json) as fh:
            plan = json.load(fh)
        plan["zona"] = None
        plan["huella"] = calcular_huella(plan)
        falso = os.path.join(self.zona, "informes", "plan-real.json")
        with open(falso, "w") as fh:
            json.dump(plan, fh)
        p = run("apply", "--plan", falso)
        self.assertEqual(p.returncode, 2)
        self.assertIn("deshabilitada", p.stderr)
        p = run("oficiales")
        self.assertIn("DESTRUCTIVA", p.stdout)


class TestOficiales(unittest.TestCase):
    def test_clasificacion(self):
        destructivas = {o["orden"] for o in oficiales.destructivas()}
        self.assertIn("npm cache clean --force", destructivas)
        self.assertIn("npm cache verify", destructivas)
        self.assertTrue(any(o.startswith("pip cache purge") for o in destructivas))
        self.assertTrue(any(o.startswith("brew cleanup [") for o in destructivas))
        self.assertTrue(all(not o["destructiva"] for o in oficiales.reversibles()))


if __name__ == "__main__":
    unittest.main()
