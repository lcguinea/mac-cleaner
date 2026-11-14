"""Pruebas adversariales de la auditoría F3.5 (criptografía, Llavero y recuperación sin clave).

SOLO claves sintéticas, almacenes simulados y zonas sintéticas temporales. La prueba con un Llavero TEMPORAL
(fichero en un directorio temporal, interacción desactivada, sin tocar la lista de búsqueda) es opcional:
MAC_CLEANER_PRUEBA_LLAVERO_TEMPORAL=1.
"""
from __future__ import annotations

import copy
import ctypes
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from maccleaner import autenticacion as aut, zona as zona_mod  # noqa: E402
from maccleaner.aplicar import directorio_cuarentena  # noqa: E402
from maccleaner.manifiesto import Manifiesto, ManifiestoCorrupto, ManifiestoOcupado  # noqa: E402
from maccleaner.plan import PlanNoValido, calcular_huella, validar_plan  # noqa: E402
from maccleaner.purgar import purgar, seleccionar  # noqa: E402
from maccleaner import restaurar as rest  # noqa: E402

from test_f2 import DIA, ENV_CLI, PROYECTO, ZonaBase, escribir, huella_fichero  # noqa: E402
from test_f25 import reencadenar  # noqa: E402


def recuperacion():
    """Funciones de F3.5; con el código de F3 no existen (así se reproduce el defecto)."""
    return rest.inventario_recuperacion, rest.restaurar_recuperacion


class Base(ZonaBase):
    def operacion(self):
        res = self.aplicador(self.planificar()).aplicar()
        return res, Manifiesto.cargar(res["manifiesto"])

    def perder_clave(self):
        clave = self.almacen.activa()
        self.almacen.olvidar(clave.id)
        return clave


# ── 1. Manifiestos truncados ───────────────────────────────────────────────────

class TestTruncamiento(Base):
    def test_registro_final_incompleto_no_impide_restaurar(self):
        """V3: una caída a mitad de escribir un registro dejaba una línea incompleta y el manifiesto entero se
        rechazaba, también en recuperación: la operación ya no se podía restaurar con la herramienta."""
        antes = {r: huella_fichero(r) for r in self.f.values()}
        res, man = self.operacion()
        with open(res["manifiesto"], "ab") as fh:
            fh.write(b'{"evento": "restaurar_intento", "id": "e0000')        # caída a mitad de línea
        m = Manifiesto.cargar(res["manifiesto"])
        self.assertTrue(m.cola_incompleta)
        r = rest.restaurar(self.zona, res["op"])
        self.assertEqual((r["restaurados"], r["errores"]), (4, 0))
        self.todo_en_su_sitio(antes)
        m = Manifiesto.cargar(res["manifiesto"])
        self.assertFalse(m.cola_incompleta)
        self.assertIn("cola_descartada", [x["evento"] for x in m.registros])

    def test_operacion_con_cola_incompleta_o_descartada_no_se_purga(self):
        res, man = self.operacion()
        with open(res["manifiesto"], "ab") as fh:
            fh.write(b'{"evento": "purg')
        t = man.inicio["t"] + 20 * DIA
        sel = seleccionar(self.zona, dias=14, ahora=t)
        self.assertEqual(sel["seleccionadas"], [])
        self.assertIn("incompleto", sel["descartadas"][0]["motivo"])
        self.assertEqual(purgar(self.zona, dias=14, ahora=t, ejecutar=True)["borrados"], 0)

    def test_no_se_escribe_detras_de_una_linea_incompleta(self):
        res, man = self.operacion()
        with open(res["manifiesto"], "ab") as fh:
            fh.write(b'{"basura"')
        m = Manifiesto.cargar(res["manifiesto"])
        with self.assertRaises(ManifiestoCorrupto):
            m.anotar("nota")

    def test_cortar_los_ultimos_registros_no_permite_borrar_nada_restaurado(self):
        """Truncar el final con registros completos no se detecta con la cadena ni con los MAC; se comprueba que
        no habilita ninguna operación destructiva: lo restaurado ya no está en la cuarentena."""
        res, man = self.operacion()
        rest.restaurar(self.zona, res["op"])
        with open(res["manifiesto"]) as fh:
            lineas = fh.read().splitlines()
        n_apply = next(i for i, x in enumerate(lineas) if json.loads(x)["evento"] == "cierre") + 1
        with open(res["manifiesto"], "w") as fh:
            fh.write("\n".join(lineas[:n_apply]) + "\n")              # «desaparecen» los restaurado
        self.assertEqual({e["estado"] for e in Manifiesto.cargar(res["manifiesto"]).estados().values()}, {"movido"})
        r = purgar(self.zona, dias=14, ahora=man.inicio["t"] + 20 * DIA, ejecutar=True)
        self.assertEqual(r["borrados"], 0)
        for ruta in self.f.values():
            self.assertTrue(os.path.exists(ruta))

    def test_quitar_el_cierre_bloquea_la_purga(self):
        res, man = self.operacion()
        with open(res["manifiesto"]) as fh:
            lineas = fh.read().splitlines()
        with open(res["manifiesto"], "w") as fh:
            fh.write("\n".join(lineas[:-1]) + "\n")
        r = purgar(self.zona, dias=14, ahora=man.inicio["t"] + 20 * DIA, ejecutar=True)
        self.assertEqual(r["borrados"], 0)


# ── 2. Registros eliminados o reordenados / 3. firmas ──────────────────────────

class TestRegistrosAlterados(Base):
    def test_eliminar_o_reordenar_registros_con_mac_validos(self):
        res, _ = self.operacion()
        with open(res["manifiesto"]) as fh:
            lineas = fh.read().splitlines()
        for nombre, nuevas in (("reordenado", lineas[:1] + [lineas[2], lineas[1]] + lineas[3:]),
                               ("eliminado", lineas[:2] + lineas[3:])):
            with open(res["manifiesto"], "w") as fh:
                fh.write("\n".join(nuevas) + "\n")
            with self.subTest(nombre), self.assertRaises(ManifiestoCorrupto):
                rest.restaurar(self.zona, res["op"])
        with open(res["manifiesto"], "w") as fh:
            fh.write("\n".join(lineas) + "\n")

    def test_firma_invalida_impide_restaurar_y_purgar(self):
        res, man = self.operacion()
        reencadenar(res["manifiesto"], lambda regs: regs[-1].__setitem__("movidos", 0))
        with self.assertRaises(ManifiestoCorrupto):
            rest.restaurar(self.zona, res["op"])
        self.assertEqual(purgar(self.zona, dias=14, ahora=man.inicio["t"] + 20 * DIA, ejecutar=True)["borrados"], 0)


# ── 4. Recuperación sin clave: intervención manual ─────────────────────────────

class TestRecuperacionManual(Base):
    def test_sin_confirmacion_no_se_mueve_nada(self):
        """V1: `--recuperacion-sin-clave` restauraba automáticamente a partir de datos sin autenticar. Ahora el
        primer paso solo inventaría; mover exige revisar el inventario y confirmar con su código."""
        inventario, restaurar_rec = recuperacion()
        antes = {r: huella_fichero(r) for r in self.f.values()}
        res, man = self.operacion()
        self.perder_clave()
        inv = inventario(self.zona, res["op"])
        self.assertEqual(sorted(e["clasificacion"] for e in inv["elementos"]), ["restaurable"] * 4)
        self.assertTrue(all(not os.path.exists(r) for r in self.f.values()))     # nada movido
        self.assertIn("no autenticado", inv["aviso"])
        with self.assertRaisesRegex(rest.ErrorRestauracion, "código"):
            restaurar_rec(self.zona, res["op"], inv, "000000000000")
        r = restaurar_rec(self.zona, res["op"], inv, inv["codigo"])
        self.assertEqual((r["restaurados"], r["errores"]), (4, 0))
        self.todo_en_su_sitio(antes)

    def test_rutas_manipuladas_quedan_en_cuarentena(self):
        inventario, restaurar_rec = recuperacion()
        res, man = self.operacion()
        self.perder_clave()
        qarch = os.path.join(res["cuarentena"], "archivos")
        ids = [e["id"] for e in man.estados().values()]
        home = os.path.expanduser("~")

        def manipular(regs):
            intentos = {r["id"]: r for r in regs if r.get("evento") == "intento"}
            intentos[ids[0]]["origen"] = os.path.join(self.zona, "home", "..", "..", "fuera.bin")
            intentos[ids[1]]["origen"] = os.path.join(home, "Documents", "robado.bin")
            intentos[ids[2]]["origen"] = os.path.join(self.zona, ".mac-cleaner-cuarentena", "x.bin")
            intentos[ids[3]]["meta"]["ino"] = 1

        reencadenar(res["manifiesto"], manipular)
        inv = inventario(self.zona, res["op"])
        cls = {e["id"]: e for e in inv["elementos"]}
        for i in ids:
            self.assertEqual(cls[i]["clasificacion"], "ambiguo", cls[i])
        r = restaurar_rec(self.zona, res["op"], inv, inv["codigo"])
        self.assertEqual(r["restaurados"], 0)
        self.assertEqual(len([f for _, _, fs in os.walk(qarch) for f in fs]), 4)   # todo sigue en cuarentena
        self.assertFalse(os.path.exists(os.path.join(home, "Documents", "robado.bin")))

    def test_conflicto_y_sustitucion_tras_el_inventario(self):
        inventario, restaurar_rec = recuperacion()
        res, man = self.operacion()
        self.perder_clave()
        inv = inventario(self.zona, res["op"])
        est = list(man.estados().values())
        escribir(est[0]["origen"], 77)                                # el destino aparece después
        with open(est[1]["destino"], "r+b") as fh:                    # el contenido cambia después
            fh.write(b"X")
        r = restaurar_rec(self.zona, res["op"], inv, inv["codigo"])
        self.assertEqual((r["restaurados"], r["omitidos"]), (2, 2))
        self.assertEqual(os.path.getsize(est[0]["origen"]), 77)       # no se sobrescribe
        self.assertTrue(os.path.exists(est[1]["destino"]))            # sigue en cuarentena

    def test_inventario_caducado_alterado_o_de_otro_estado(self):
        inventario, restaurar_rec = recuperacion()
        res, _ = self.operacion()
        self.perder_clave()
        inv = inventario(self.zona, res["op"])
        viejo = copy.deepcopy(inv)
        with self.assertRaisesRegex(rest.ErrorRestauracion, "caducado"):
            restaurar_rec(self.zona, res["op"], viejo, viejo["codigo"], ahora=inv["generado"] + 7200)
        alterado = copy.deepcopy(inv)
        alterado["elementos"][0]["origen"] += ".otro"
        with self.assertRaisesRegex(rest.ErrorRestauracion, "código"):
            restaurar_rec(self.zona, res["op"], alterado, inv["codigo"])
        with open(res["manifiesto"], "ab") as fh:                     # el manifiesto cambió tras el inventario
            fh.write(b'{"evento": "par')
        with self.assertRaisesRegex(rest.ErrorRestauracion, "manifiesto cambió"):
            restaurar_rec(self.zona, res["op"], inv, inv["codigo"])

    def test_recuperacion_no_contamina_el_manifiesto(self):
        """V2: la recuperación anotaba registros SIN MAC en el manifiesto; si la clave volvía (copia del
        Llavero), el manifiesto ya no se podía autenticar y el resto de la operación quedaba bloqueado."""
        inventario, restaurar_rec = recuperacion()
        antes = {r: huella_fichero(r) for r in self.f.values()}
        res, man = self.operacion()
        clave = self.perder_clave()
        inv = inventario(self.zona, res["op"])
        un_id = inv["elementos"][0]["id"]
        r = restaurar_rec(self.zona, res["op"], inv, inv["codigo"], elementos={un_id})
        self.assertEqual(r["restaurados"], 1)
        self.almacen._claves[clave.id] = clave                      # la clave reaparece
        r = rest.restaurar(self.zona, res["op"])
        self.assertEqual((r["restaurados"], r["errores"]), (4, 0))   # 3 + 1 que ya estaba en su sitio
        self.todo_en_su_sitio(antes)
        self.assertTrue(os.path.exists(os.path.join(res["cuarentena"], "recuperacion.jsonl")))

    def test_recuperacion_con_operacion_ocupada(self):
        inventario, restaurar_rec = recuperacion()
        res, man = self.operacion()
        inv = inventario(self.zona, res["op"])
        with Manifiesto.cargar(res["manifiesto"]).bloquear():
            with self.assertRaises(ManifiestoOcupado):
                restaurar_rec(self.zona, res["op"], inv, inv["codigo"])

    def test_cli_recuperacion_en_dos_pasos(self):
        antes = {r: huella_fichero(r) for r in self.f.values()}
        res, _ = self.operacion()                                     # firmado con la clave en memoria
        lanz = os.path.join(PROYECTO, "mac-cleaner")                  # el proceso hijo NO tiene esa clave
        p = subprocess.run([lanz, "restore", "--zona", self.zona, "--operacion", res["op"]],
                           capture_output=True, text=True, env=ENV_CLI, timeout=60)
        self.assertEqual(p.returncode, 2)
        self.assertIn("recuperacion-sin-clave", p.stderr)
        p = subprocess.run([lanz, "restore", "--zona", self.zona, "--operacion", res["op"], "--recuperacion-sin-clave"],
                           capture_output=True, text=True, env=ENV_CLI, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("No se ha movido nada", p.stdout)
        self.assertTrue(all(not os.path.exists(r) for r in self.f.values()))
        ruta = p.stdout.split("Inventario: ")[1].splitlines()[0].strip()
        codigo = p.stdout.split("Código: ")[1].split()[0]
        p = subprocess.run([lanz, "restore", "--zona", self.zona, "--operacion", res["op"], "--recuperacion-sin-clave",
                            "--confirmar", ruta, "--codigo", codigo], capture_output=True, text=True, env=ENV_CLI, timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.todo_en_su_sitio(antes)


# ── 5. Intentos de operar sobre datos reales ───────────────────────────────────

class TestOperacionesReales(Base):
    def test_plan_real_firmado_con_clave_no_sintetica_sigue_bloqueado(self):
        k = aut.AlmacenLlavero(_LlaveroFalso())
        real = k.crear()
        aut.establecer_almacen(_Combinado(self.almacen, k))
        plan = self.planificar()
        plan["zona"] = None
        plan["huella"] = calcular_huella(plan)
        aut.firmar_plan(plan, real)
        self.assertEqual(aut.verificar_plan(plan).id, real.id)      # criptográficamente válido…
        with self.assertRaisesRegex(zona_mod.ZonaNoValida, "deshabilitada"):
            validar_plan(plan, self.T0 + 120)                       # …pero la limpieza real está deshabilitada

    def test_restore_purge_y_recuperacion_fuera_de_zonas_sinteticas(self):
        inventario, _ = recuperacion()
        sin_marcador = tempfile.mkdtemp(prefix="mc-f35-sin-marcador-")
        self.addCleanup(shutil.rmtree, sin_marcador, True)
        for z in (os.path.expanduser("~"), sin_marcador, "/private/tmp"):
            with self.subTest(z):
                with self.assertRaises(zona_mod.ZonaNoValida):
                    rest.restaurar(z, "20260101-000000-abcdef")
                with self.assertRaises(zona_mod.ZonaNoValida):
                    purgar(z, dias=14, ejecutar=True)
                with self.assertRaises(zona_mod.ZonaNoValida):
                    inventario(z, "20260101-000000-abcdef")
        self.assertFalse(zona_mod.LIMPIEZA_REAL_HABILITADA)


# ── 6. Llavero ─────────────────────────────────────────────────────────────────

class _LlaveroFalso:
    def __init__(self):
        self.d, self.acl, self.lecturas = {}, {}, 0

    def leer(self, cuenta):
        self.lecturas += 1
        return self.d.get(cuenta)

    def escribir(self, cuenta, valor, reemplazar=False):
        if cuenta in self.d and not reemplazar:
            raise aut.ClaveNoDisponible("duplicada")
        self.d[cuenta], self.acl[cuenta] = valor, "por defecto"

    def crear_con_confirmacion(self, cuenta, valor):
        if cuenta in self.d:
            raise aut.ClaveNoDisponible("duplicada")
        self.d[cuenta], self.acl[cuenta] = valor, "confirmar siempre"


class _Combinado:
    def __init__(self, *almacenes):
        self.a = almacenes

    def activa(self):
        return self.a[0].activa()

    def obtener(self, cid):
        for x in self.a:
            try:
                return x.obtener(cid)
            except aut.ClaveNoDisponible:
                pass
        raise aut.ClaveNoDisponible(cid)


class TestLlavero(unittest.TestCase):
    def test_claves_creadas_con_confirmacion_obligatoria_y_cache(self):
        """V4: con la ACL por defecto el intérprete que creó la clave la leía sin preguntar (evidencia en
        docs/SEGURIDAD-F3.md §10). Las claves se crean ahora con confirmación obligatoria; el índice no es secreto."""
        k = _LlaveroFalso()
        alm = aut.AlmacenLlavero(k)
        c1, c2 = alm.crear(), alm.rotar()
        self.assertEqual(k.acl[c1.id], "confirmar siempre")
        self.assertEqual(k.acl[c2.id], "confirmar siempre")
        self.assertEqual(k.acl[aut.CUENTA_INDICE], "por defecto")
        otro = aut.AlmacenLlavero(k)
        k.lecturas = 0
        for _ in range(3):
            otro.obtener(c1.id)
        self.assertEqual(k.lecturas, 1)                               # una confirmación por proceso

    def test_errores_del_llavero_explicados(self):
        class Denegado(_LlaveroFalso):
            def leer(self, cuenta):
                raise aut.ClaveNoDisponible("Llavero: error -25293 al leer x: acceso denegado o no confirmado")
        with self.assertRaisesRegex(aut.ClaveNoDisponible, "no confirmado"):
            aut.AlmacenLlavero(Denegado()).activa()

    @unittest.skipUnless(os.environ.get("MAC_CLEANER_PRUEBA_LLAVERO_TEMPORAL") == "1",
                         "opcional: crea un Llavero TEMPORAL (fichero en /tmp, sin diálogos, fuera de la lista de búsqueda)")
    def test_llavero_temporal_real_exige_confirmacion(self):
        S = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        vp = ctypes.c_void_p
        S.SecKeychainSetUserInteractionAllowed.argtypes = [ctypes.c_bool]
        S.SecKeychainCreate.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_bool, vp,
                                        ctypes.POINTER(vp)]
        S.SecKeychainDelete.argtypes = [vp]
        self.assertEqual(S.SecKeychainSetUserInteractionAllowed(False), 0)   # nunca un diálogo en pantalla
        d = tempfile.mkdtemp(prefix="mc-f35-llavero-")
        ruta, pw, kc = os.path.join(d, "t.keychain-db").encode(), secrets.token_hex(16).encode(), vp()
        self.assertEqual(S.SecKeychainCreate(ruta, len(pw), pw, False, None, ctypes.byref(kc)), 0)
        try:
            alm = aut.AlmacenLlavero(aut._Llavero(ref=kc))
            c = alm.crear()
            nuevo = aut.AlmacenLlavero(aut._Llavero(ref=kc))       # otro «proceso»: sin caché
            self.assertEqual(nuevo.estado()["activa"], c.id)         # el índice (no secreto) se lee
            with self.assertRaisesRegex(aut.ClaveNoDisponible, "-25293"):
                nuevo.obtener(c.id)                                 # la clave exige confirmación
        finally:
            S.SecKeychainDelete(kc)
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
