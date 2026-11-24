"""Pruebas de F3: autenticación HMAC, lista blanca npm/pip y modo sombra.

SOLO datos ficticios en zonas sintéticas y claves sintéticas en memoria: ninguna prueba toca el Llavero real
(el almacén del Llavero se prueba con un Llavero simulado en memoria).
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from maccleaner import autenticacion as aut, listablanca, sombra, zona as zona_mod  # noqa: E402
from maccleaner.aplicar import Aplicador, directorio_cuarentena  # noqa: E402
from maccleaner.cli import ejecutar_scan, herramientas_de_zona  # noqa: E402
from maccleaner.config import cargar  # noqa: E402
from maccleaner.manifiesto import Manifiesto, ManifiestoNoAutenticado  # noqa: E402
from maccleaner.plan import PlanNoValido, calcular_huella, crear_plan, validar_plan  # noqa: E402
from maccleaner.purgar import purgar, seleccionar  # noqa: E402
from maccleaner.restaurar import inventario_recuperacion, restaurar, restaurar_recuperacion  # noqa: E402


def recuperar_sin_clave(zona, op):
    """F3.5: recuperación en dos pasos (inventario + confirmación con código)."""
    inv = inventario_recuperacion(zona, op)
    return inv, restaurar_recuperacion(zona, op, inv, inv["codigo"])

from test_f2 import DIA, ENV_CLI, PROYECTO, VACIO, Caida, ZonaBase, escribir, huella_fichero  # noqa: E402


# ── autenticación de planes ─────────────────────────────────────────────────────

class TestPlanAutenticado(ZonaBase):
    def test_plan_de_zona_firmado_y_sin_secretos(self):
        plan = self.planificar()
        a = plan["autenticacion"]
        clave = self.almacen.activa()
        self.assertEqual((a["alg"], a["id_clave"], a["sintetica"]), ("HMAC-SHA256", clave.id, True))
        self.assertEqual(plan["version"], 2)
        texto = json.dumps(plan)
        self.assertNotIn(clave.secreto.hex(), texto)
        self.assertNotIn(clave.secreto.hex(), repr(clave) + str(clave))
        self.assertEqual(validar_plan(plan, self.T0 + 120), self.zona)

    def test_plan_alterado_con_huella_recalculada_se_rechaza(self):
        """La huella SHA-256 ya no basta: sin la clave, recalcularla no sirve."""
        plan = self.planificar()
        casos = [
            lambda p: p["elementos"][0].__setitem__("edad_minima_dias", 0),
            lambda p: p.__setitem__("caduca", p["caduca"] + 1),
            lambda p: p["elementos"].pop(),
            lambda p: p.__setitem__("config_sha256", "0" * 64),
        ]
        for i, cambiar in enumerate(casos):
            p = copy.deepcopy(plan)
            cambiar(p)
            p["huella"] = calcular_huella(p)
            with self.subTest(caso=i), self.assertRaisesRegex(PlanNoValido, "MAC del plan no válido"):
                self.aplicador(p)

    def test_mac_ausente_o_manipulado(self):
        plan = self.planificar()
        p = copy.deepcopy(plan)
        del p["autenticacion"]
        with self.assertRaisesRegex(PlanNoValido, "no está autenticado"):
            self.aplicador(p)
        p = copy.deepcopy(plan)
        p["autenticacion"]["mac"] = "0" * 64
        with self.assertRaisesRegex(PlanNoValido, "MAC del plan no válido"):
            self.aplicador(p)
        p = copy.deepcopy(plan)
        p["autenticacion"]["sintetica"] = False
        with self.assertRaisesRegex(PlanNoValido, "tipo de clave"):
            self.aplicador(p)

    def test_clave_incorrecta_o_ausente(self):
        plan = self.planificar()
        otra = aut.AlmacenSintetico.nuevo()
        # Firmado con otra clave pero declarando el id de la buena → MAC no válido.
        p = copy.deepcopy(plan)
        falsa = aut.Clave(self.almacen.activa().id, otra.activa().secreto, True)
        aut.firmar_plan(p, falsa)
        with self.assertRaisesRegex(PlanNoValido, "MAC del plan no válido"):
            self.aplicador(p)
        # Firmado con una clave que el almacén no tiene → clave no disponible.
        p = copy.deepcopy(plan)
        aut.firmar_plan(p, otra.activa())
        with self.assertRaisesRegex(PlanNoValido, "no está disponible"):
            self.aplicador(p)
        # Clave perdida: el plan legítimo ya no se puede aplicar.
        self.almacen.olvidar(self.almacen.activa().id)
        with self.assertRaisesRegex(PlanNoValido, "no está disponible"):
            self.aplicador(plan)
        # Sin clave activa no se puede ni planificar en zona sintética.
        with self.assertRaisesRegex(PlanNoValido, "no se puede firmar"):
            self.planificar()

    def test_plan_v1_de_f2_se_rechaza(self):
        plan = self.planificar()
        plan["version"] = 1
        self.retocar(plan)
        with self.assertRaisesRegex(PlanNoValido, "versión de plan no admitida"):
            self.aplicador(plan)

    def test_clave_sintetica_nunca_autoriza_datos_reales(self):
        plan = self.planificar()
        plan["zona"] = None
        self.retocar(plan)
        with self.assertRaisesRegex(aut.ErrorAutenticacion, "sintética no puede autorizar"):
            aut.verificar_plan(plan, self.almacen)
        with self.assertRaisesRegex(zona_mod.ZonaNoValida, "deshabilitada"):
            validar_plan(plan, self.T0 + 120)          # y la puerta de zona sigue siendo la primera barrera

    def test_plan_de_otra_zona(self):
        """Un plan firmado para la zona A no sirve en la zona B (la zona está dentro del MAC)."""
        plan = self.planificar()
        otra = zona_mod.crear_zona("mc-f3-otra-")
        self.addCleanup(shutil.rmtree, otra, True)
        p = copy.deepcopy(plan)
        p["zona"] = otra
        p["huella"] = calcular_huella(p)
        with self.assertRaisesRegex(PlanNoValido, "MAC del plan no válido"):
            self.aplicador(p)


class TestReproduccion(ZonaBase):
    def test_un_plan_solo_se_aplica_una_vez_incluso_en_paralelo(self):
        plan = self.planificar()
        a1, a2 = self.aplicador(plan), self.aplicador(plan)      # dos apply validados a la vez
        res = a1.aplicar()
        self.assertEqual(res["movidos"], 4)
        with self.assertRaisesRegex(PlanNoValido, "ya se aplicó"):
            a2.aplicar()
        self.assertEqual(len([x for x in os.listdir(directorio_cuarentena(self.zona)) if x != "planes-aplicados"]), 1)

    def test_registro_de_otra_operacion_no_se_acepta(self):
        """El MAC de cada registro incluye la operación: copiar registros entre operaciones se detecta."""
        res1 = self.aplicador(self.planificar()).aplicar()
        restaurar(self.zona, res1["op"])
        res2 = self.aplicador(self.planificar(ahora=self.T0 + 200), ahora=self.T0 + 260).aplicar()
        with open(res1["manifiesto"]) as fh:
            ajeno = [json.loads(x) for x in fh.read().splitlines()]
        with open(res2["manifiesto"]) as fh:
            propio = [json.loads(x) for x in fh.read().splitlines()]
        # Se sustituye un registro de res2 por el registro equivalente de res1, ajustando n y prev (la cadena
        # no lleva clave), pero sin poder recalcular el MAC.
        r = dict(ajeno[3], n=3, prev=propio[2]["h"])
        r.pop("h")
        mac = r.pop("mac")
        from maccleaner.manifiesto import _huella
        r["h"] = _huella(r["prev"], r)
        r["mac"] = mac
        lineas = [json.dumps(x, sort_keys=True) for x in propio[:3] + [r]]
        with open(res2["manifiesto"], "w") as fh:
            fh.write("\n".join(lineas) + "\n")
        with self.assertRaises(ManifiestoNoAutenticado):
            restaurar(self.zona, res2["op"])

    def test_manifiesto_copiado_a_otra_operacion(self):
        res = self.aplicador(self.planificar()).aplicar()
        qbase = directorio_cuarentena(self.zona)
        falso = os.path.join(qbase, "20990101-000000-abcdef")
        os.mkdir(falso, 0o700)
        shutil.copy(res["manifiesto"], os.path.join(falso, "manifiesto.jsonl"))
        with self.assertRaisesRegex(Exception, "otra zona u operación"):
            restaurar(self.zona, "20990101-000000-abcdef")


class TestManifiestoAutenticado(ZonaBase):
    def test_manifiesto_alterado_sin_clave_se_rechaza(self):
        from test_f25 import reencadenar
        antes = {r: huella_fichero(r) for r in self.f.values()}
        res = self.aplicador(self.planificar()).aplicar()
        editado = {}

        def editar_origen(regs):
            r = next(x for x in regs if x["evento"] == "intento")
            editado["original"] = r["origen"]
            r["origen"] = r["origen"] + ".otro"

        reencadenar(res["manifiesto"], editar_origen)
        with self.assertRaisesRegex(ManifiestoNoAutenticado, "MAC no válido"):
            restaurar(self.zona, res["op"])
        sel = seleccionar(self.zona, dias=14, ahora=Manifiesto.cargar(res["manifiesto"], verificar=False).inicio["t"] + 20 * DIA)
        self.assertEqual(sel["seleccionadas"], [])
        self.assertIn("MAC no válido", sel["descartadas"][0]["motivo"])
        # Los ficheros siguen en la cuarentena: la recuperación sin clave restaura lo no manipulado y rechaza el
        # elemento cuyo origen se editó (destino y origen ya no son coherentes).
        inv, r = recuperar_sin_clave(self.zona, res["op"])
        self.assertEqual(sorted(e["clasificacion"] for e in inv["elementos"]), ["ambiguo"] + ["restaurable"] * 3)
        self.assertEqual((r["restaurados"], r["omitidos"]), (3, 0))
        self.assertFalse(os.path.exists(editado["original"] + ".otro"))
        self.assertFalse(os.path.exists(editado["original"]))       # sigue en la cuarentena, para revisión
        for ruta, h in antes.items():
            if ruta != editado["original"]:
                self.assertEqual(huella_fichero(ruta), h)

    def test_manifiesto_f2_sin_autenticacion(self):
        """Un manifiesto sin autenticación (formato F2) se rechaza en modo normal y se recupera sin clave."""
        antes = {r: huella_fichero(r) for r in self.f.values()}
        res = self.aplicador(self.planificar()).aplicar()
        from test_f25 import reencadenar

        def quitar_aut(regs):
            regs[0].pop("autenticacion")
            for r in regs:
                r.pop("mac", None)

        reencadenar(res["manifiesto"], quitar_aut)
        with self.assertRaisesRegex(ManifiestoNoAutenticado, "sin autenticación"):
            restaurar(self.zona, res["op"])
        _, r = recuperar_sin_clave(self.zona, res["op"])
        self.assertEqual((r["restaurados"], r["omitidos"]), (4, 0))
        self.todo_en_su_sitio(antes)
        man = Manifiesto.cargar(res["manifiesto"], verificar=False)
        self.assertFalse(any(x["evento"] == "restaurado" for x in man.registros))   # F3.5: el manifiesto no se toca
        self.assertTrue(os.path.exists(os.path.join(res["cuarentena"], "recuperacion.jsonl")))


class TestPerdidaYRotacionDeClave(ZonaBase):
    def test_perdida_de_clave_restaurar_sin_clave_y_purga_bloqueada(self):
        antes = {r: huella_fichero(r) for r in self.f.values()}
        res = self.aplicador(self.planificar()).aplicar()
        t = Manifiesto.cargar(res["manifiesto"]).inicio["t"]
        self.almacen.olvidar(self.almacen.activa().id)             # la clave se pierde
        with self.assertRaisesRegex(ManifiestoNoAutenticado, "no está disponible"):
            restaurar(self.zona, res["op"])
        r = purgar(self.zona, dias=14, ahora=t + 20 * DIA, ejecutar=True)
        self.assertEqual(r["borrados"], 0)                          # nunca se purga sin MAC válidos
        self.assertTrue(all(os.path.exists(e["destino"]) for e in Manifiesto.cargar(res["manifiesto"], verificar=False).estados().values()))
        _, r = recuperar_sin_clave(self.zona, res["op"])
        self.assertEqual((r["restaurados"], r["omitidos"]), (4, 0))
        self.todo_en_su_sitio(antes)

    def test_rotacion_mantiene_verificables_las_operaciones_antiguas(self):
        antes = {r: huella_fichero(r) for r in self.f.values()}
        plan = self.planificar()
        res = self.aplicador(plan).aplicar()
        vieja = self.almacen.activa().id
        nueva = self.almacen.rotar()
        self.assertNotEqual(vieja, nueva.id)
        r = restaurar(self.zona, res["op"])                         # firmado con la vieja: sigue verificable
        self.assertEqual(r["restaurados"], 4)
        self.todo_en_su_sitio(antes)
        plan2 = self.planificar(ahora=self.T0 + 200)
        self.assertEqual(plan2["autenticacion"]["id_clave"], nueva.id)

    def test_interrupcion_durante_apply_firmado(self):
        antes = {r: huella_fichero(r) for r in self.f.values()}
        ap = self.aplicador(self.planificar())
        from maccleaner import fsseguro
        n = {"i": 0}

        def renombrar(*args):
            n["i"] += 1
            fsseguro.mover_excl(*args)
            if n["i"] == 2:
                raise Caida()

        ap._renombrar = renombrar
        with self.assertRaises(Caida):
            ap.aplicar()
        op = next(x for x in os.listdir(directorio_cuarentena(self.zona)) if x != "planes-aplicados")
        man = Manifiesto.cargar(os.path.join(directorio_cuarentena(self.zona), op, "manifiesto.jsonl"))
        self.assertTrue(man.autenticado)
        self.assertFalse(man.cerrado)
        r = restaurar(self.zona, op)
        self.assertEqual((r["restaurados"], r["errores"]), (2, 0))
        self.todo_en_su_sitio(antes)


class TestSustitucionYGrandesConAutenticacion(ZonaBase):
    def test_sustitucion_tras_firmar_el_plan(self):
        """El MAC protege el plan, no el disco: la sustitución entre plan y apply la detecta la revalidación."""
        plan = self.planificar()
        os.rename(self.f["a"], self.f["a"] + ".original")
        escribir(self.f["a"], 10_000)
        h_nuevo = huella_fichero(self.f["a"])
        res = self.aplicador(plan).aplicar()
        self.assertEqual(res["movidos"], 3)
        self.assertEqual(huella_fichero(self.f["a"]), h_nuevo)

    def test_fichero_grande_restaurado_con_manifiesto_autenticado(self):
        grande = os.path.join(self.caches, "app5", "grande.bin")
        os.makedirs(os.path.dirname(grande))
        with open(grande, "wb") as fh:
            fh.truncate(70 << 20)
            fh.write(b"cabecera")
        antes = huella_fichero(grande)
        plan = self.planificar()
        self.assertIsNone(next(e for e in plan["elementos"] if e["ruta"] == grande)["sha256"])
        res = self.aplicador(plan).aplicar()
        # Un atacante sin clave no puede «legalizar» una alteración cambiando el ctime registrado.
        from test_f25 import reencadenar
        dest = next(e["destino"] for e in Manifiesto.cargar(res["manifiesto"]).estados().values() if e["origen"] == grande)
        with open(dest, "r+b") as fh:
            fh.write(b"ALTERADO")
        nuevo_ctime = os.lstat(dest).st_ctime_ns

        def legalizar(regs):
            for r in regs:
                if r.get("evento") == "movido" and r.get("ino") == os.lstat(dest).st_ino:
                    r["ctime_ns"] = nuevo_ctime

        copia = res["manifiesto"] + ".bak"
        shutil.copy(res["manifiesto"], copia)
        reencadenar(res["manifiesto"], legalizar)
        with self.assertRaises(ManifiestoNoAutenticado):
            restaurar(self.zona, res["op"], ruta=grande)
        shutil.copy(copia, res["manifiesto"])
        os.remove(copia)
        r = restaurar(self.zona, res["op"], ruta=grande)
        self.assertEqual((r["restaurados"], r["errores"]), (0, 1))     # el ctime delata la alteración
        self.assertFalse(os.path.exists(grande))
        self.assertNotEqual(antes, None)


# ── almacén del Llavero (simulado) ──────────────────────────────────────────────

class LlaveroFalso:
    def __init__(self):
        self.d: dict[str, bytes] = {}

    def leer(self, cuenta):
        return self.d.get(cuenta)

    def escribir(self, cuenta, valor, reemplazar=False):
        if cuenta in self.d and not reemplazar:
            raise aut.ClaveNoDisponible("duplicada")
        self.d[cuenta] = valor

    def crear_con_confirmacion(self, cuenta, valor):
        if cuenta in self.d:
            raise aut.ClaveNoDisponible("duplicada")
        self.d[cuenta] = valor


class TestAlmacenLlavero(unittest.TestCase):
    def test_crear_rotar_obtener_sin_llavero_real(self):
        k = LlaveroFalso()
        alm = aut.AlmacenLlavero(k)
        with self.assertRaisesRegex(aut.ClaveNoDisponible, "clave crear"):
            alm.activa()
        c1 = alm.crear()
        self.assertFalse(c1.sintetica)
        self.assertEqual(len(c1.secreto), 32)
        with self.assertRaisesRegex(aut.ClaveNoDisponible, "ya existe"):
            alm.crear()
        c2 = alm.rotar()
        self.assertEqual(alm.activa(), c2)
        self.assertEqual(alm.obtener(c1.id), c1)
        est = alm.estado()
        self.assertEqual([x["id"] for x in est["claves"]], [c1.id, c2.id])
        self.assertNotIn(c1.secreto.hex(), json.dumps(est))
        indice = json.loads(k.d[aut.CUENTA_INDICE])
        self.assertNotIn(c2.secreto.hex(), json.dumps(indice))
        with self.assertRaisesRegex(aut.ClaveNoDisponible, "no válido"):
            alm.obtener("sintetica-0123456789abcdef")              # una clave sintética nunca sale del Llavero
        with self.assertRaisesRegex(aut.ClaveNoDisponible, "no válido"):
            alm.obtener("../otra")

    def test_clave_sintetica_desde_entorno(self):
        a = aut.AlmacenSintetico.desde_hex("ab" * 32)
        b = aut.AlmacenSintetico.desde_hex("ab" * 32)
        self.assertEqual(a.activa().id, b.activa().id)              # reproducible
        self.assertNotIn("ab" * 32, a.activa().id)
        with self.assertRaises(aut.ClaveNoDisponible):
            aut.AlmacenSintetico.desde_hex("corta")

    def test_cli_clave_estado_no_revela_el_secreto(self):
        p = subprocess.run([os.path.join(PROYECTO, "mac-cleaner"), "clave", "estado"], capture_output=True,
                           text=True, env=ENV_CLI, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["almacen"], "sintetico")
        self.assertNotIn(ENV_CLI[aut.ENV_SINTETICA], p.stdout + p.stderr)


# ── lista blanca y sombra ───────────────────────────────────────────────────────

class ZonaHerramientas(ZonaBase):
    """Zona con cachés ficticias de npm y pip, y datos que nunca deben ser candidatos."""

    def setUp(self) -> None:
        super().setUp()
        home = os.path.join(self.zona, "home")
        with open(self.cfg_ruta, "w") as fh:
            fh.write(textwrap.dedent(f"""
                [general]
                usar_lsof = false
                baja_prioridad = false
                [proteccion]
                rutas = ["~/.npm/_npx", "~/Library/Caches/ms-playwright-mcp"]
                nombres = ['(ableton|remotion)']
                extensiones = [".als", ".gguf"]
                marcadores_proyecto = [".git", "package.json"]
                marcadores_venv = ["pyvenv.cfg"]
                [[ajuste_riesgo]]
                patron = 'telegram'
                riesgo = "alto"
                motivo = "medios"
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
                [[regla]]
                id = "caches"
                tipo = "ruta"
                rutas = ["~/Library/Caches"]
                riesgo = "medio"
                edad_minima_dias = {self.EDAD}
            """))
        npm = os.path.join(home, ".npm")
        pip = os.path.join(home, "Library", "Caches", "pip")
        self.permitidos = [
            escribir(os.path.join(npm, "_cacache", "content-v2", "sha512", "ab", "cd", "blob1"), 3000),
            escribir(os.path.join(npm, "_cacache", "index-v5", "01", "02", "idx"), 500),
            escribir(os.path.join(pip, "http-v2", "a", "b", "c", "resp"), 4000),
            escribir(os.path.join(pip, "http", "x", "y", "resp"), 1000),
        ]
        # Candidato de la regla npm, pero la lista blanca lo rechaza (componente de instalación).
        self.node_modules_en_cache = escribir(os.path.join(npm, "_cacache", "tmp", "node_modules", "x.js"), 100)
        self.fuera_lista = [
            escribir(os.path.join(npm, "_logs", "debug.log"), 200),
            escribir(os.path.join(npm, "_prebuilds", "x.node"), 800),
            escribir(os.path.join(pip, "wheels", "aa", "pkg.whl"), 900),
            escribir(os.path.join(pip, "selfcheck", "state.json"), 50),
        ]
        self.nunca = self.protegidos + [
            escribir(os.path.join(npm, "_npx", "1234", "node_modules", "mcp-server", "index.js"), 700),
            escribir(os.path.join(self.caches, "ms-playwright-mcp", "chromium", "bin"), 600),
            escribir(os.path.join(self.caches, "Codex", "c.bin"), 600),
            escribir(os.path.join(self.caches, "gemini-cli", "g.bin"), 600),
            escribir(os.path.join(self.caches, "rea-cache", "r.bin"), 600),
        ]

    def evaluar(self, anterior=None, ahora=None):
        cfg = self.cfg()
        esc = ejecutar_scan(cfg, abiertos=VACIO, zona=self.zona, ahora=ahora or self.T0,
                            herramientas_fijas=herramientas_de_zona(self.zona))
        return sombra.evaluar(esc, cfg, abiertos=VACIO, ahora=(ahora or self.T0) + 60, anterior=anterior)[0]

    def instantanea(self):
        out = {}
        for d, dirs, files in os.walk(self.zona):
            dirs[:] = [x for x in dirs if x != "informes"]
            for f in files:
                p = os.path.join(d, f)
                st = os.lstat(p)
                with open(p, "rb") as fh:
                    out[p] = (hashlib.sha256(fh.read()).hexdigest(), st.st_mtime_ns, st.st_ctime_ns, st.st_ino)
        return out


class TestListaBlancaYSombra(ZonaHerramientas):
    def test_clasificacion_de_la_lista_blanca(self):
        d = self.evaluar()
        grupos = {f"{g['regla']}:{g['grupo']}": g for g in d["candidatos"]["grupos"]}
        rutas = {r for g in grupos.values() for r in g["muestra"]}
        self.assertEqual(grupos["npm:_cacache"]["lista_blanca"]["no"], 1)      # el node_modules dentro de la caché
        self.assertTrue(any("instalación" in m for m in grupos["npm:_cacache"]["motivos_no"]))
        self.assertEqual(grupos["pip:http-v2"]["lista_blanca"]["no"], 0)
        self.assertEqual(grupos["pip:http"]["lista_blanca"]["no"], 0)
        for g in ("npm:_logs", "npm:_prebuilds", "pip:wheels", "pip:selfcheck"):
            self.assertEqual(grupos[g]["lista_blanca"]["si"], 0, g)
        self.assertTrue(all(not g.startswith("caches:") or grupos[g]["lista_blanca"]["si"] == 0 for g in grupos))
        for p in self.nunca:
            self.assertNotIn(p, rutas)
            self.assertFalse(any(p in g["muestra"] for g in grupos.values()))
        self.assertNotIn("npm:_npx", grupos)
        t = d["candidatos"]["totales"]
        self.assertEqual(t["lista_blanca_ficheros"], 4)            # solo los 4 permitidos
        ops = {o["regla"]: o for o in d["operaciones_que_requieren_autorizacion"] if o["en_lista_blanca"]}
        self.assertEqual({r for r, o in ops.items() if o["ficheros"]}, {"npm", "pip"})   # F5B lista más reglas (vacías)
        self.assertFalse(d["limpieza_real_habilitada"])

    def test_nada_de_node_modules_ni_entornos_aunque_esten_en_cacache(self):
        subs = {"npm": [os.path.join(self.zona, "home", ".npm", "_cacache")]}
        ok, motivo = listablanca.clasificar("npm", os.path.join(subs["npm"][0], "tmp", "node_modules", "x.js"), subs)
        self.assertFalse(ok)
        self.assertIn("instalación", motivo)
        ok, _ = listablanca.clasificar("npm", os.path.join(self.zona, "home", ".npm", "_npx", "x"), subs)
        self.assertFalse(ok)
        ok, _ = listablanca.clasificar("homebrew", "/x", subs)
        self.assertFalse(ok)

    def test_raices_de_cache_no_aceptables(self):
        home = os.path.join(self.zona, "home")
        self.assertIsNone(listablanca.motivo_raiz(os.path.join(home, ".npm"), home))
        self.assertIn("HOME", listablanca.motivo_raiz("/opt/homebrew/var/cache", home))
        venv = os.path.join(home, "proyecto-x", ".venv", "cache")
        os.makedirs(venv)
        self.assertIn("instalación o entorno", listablanca.motivo_raiz(venv, home))
        proyecto = os.path.join(home, "app", "npm-cache")
        os.makedirs(proyecto)
        escribir(os.path.join(home, "app", "package.json"), 10)
        self.assertIn("proyecto o entorno", listablanca.motivo_raiz(proyecto, home))

    def test_sombra_no_modifica_nada_y_detecta_cambios(self):
        antes = self.instantanea()
        d1 = self.evaluar()
        self.assertEqual(self.instantanea(), antes)
        os.remove(self.permitidos[3])                               # pip/http desaparece
        escribir(os.path.join(self.zona, "home", ".npm", "_cacache", "content-v2", "sha512", "ef", "01", "blob2"), 5000)
        d2 = self.evaluar(anterior=d1, ahora=self.T0 + 100)
        c = d2["cambios"]
        self.assertTrue(c["disponible"])
        self.assertIn("pip:http", [x["grupo"] for x in c["desaparecidos"]])
        cam = {x["grupo"]: x for x in c["cambiados"]}
        self.assertEqual(cam["npm:_cacache"]["delta_ficheros"], 1)
        self.assertEqual(c["delta_totales"]["lista_blanca_ficheros"], 0)
        md = sombra.markdown(d2)
        for seccion in ("Candidatos, riesgo y justificación", "Autorizaciones que serían necesarias", "Exclusiones",
                        "Riesgos", "Cambios respecto a la ejecución anterior"):
            self.assertIn(seccion, md)


class TestSombraCLI(ZonaHerramientas):
    EDAD = 0

    def test_cli_sombra_con_guardia_sin_tocar_nada(self):
        antes = self.instantanea()
        lanz = os.path.join(PROYECTO, "mac-cleaner")
        args = [lanz, "sombra", "--zona-sintetica", self.zona, "--config", self.cfg_ruta, "--sin-lsof"]
        p = subprocess.run(args, capture_output=True, text=True, env=ENV_CLI, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("Nada se ha movido ni borrado", p.stdout)
        ruta = p.stdout.split("JSON: ")[1].splitlines()[0].strip()
        self.assertTrue(ruta.startswith(os.path.join(self.zona, "informes")))
        with open(ruta) as fh:
            d = json.load(fh)
        self.assertEqual(d["guardia"]["bloqueos"], [])
        self.assertEqual(d["candidatos"]["totales"]["lista_blanca_ficheros"], 4)
        self.assertEqual(self.instantanea(), antes)
        self.assertFalse(os.path.exists(directorio_cuarentena(self.zona)))
        p = subprocess.run(args, capture_output=True, text=True, env=ENV_CLI, timeout=120)  # segunda: compara
        ruta2 = p.stdout.split("JSON: ")[1].splitlines()[0].strip()
        with open(ruta2) as fh:
            self.assertTrue(json.load(fh)["cambios"]["disponible"])


if __name__ == "__main__":
    unittest.main()
