"""Pruebas de regresión de la auditoría F2.5. SOLO datos ficticios dentro de zonas sintéticas temporales.

Cada prueba reproduce un defecto encontrado en la auditoría (ver docs/SEGURIDAD-F2.md, §8) o fija una
garantía que antes no estaba cubierta por ninguna prueba.
"""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from maccleaner import fsseguro, purgar as purgar_mod, restaurar as restaurar_mod  # noqa: E402
from maccleaner.aplicar import directorio_cuarentena  # noqa: E402
from maccleaner.manifiesto import Manifiesto, ManifiestoCorrupto, _huella  # noqa: E402
try:
    from maccleaner.manifiesto import ManifiestoOcupado  # noqa: E402
except ImportError:  # código anterior a F2.5 (para reproducir los defectos)
    class ManifiestoOcupado(Exception):
        pass
from maccleaner.plan import PlanNoValido  # noqa: E402
from maccleaner.purgar import purgar  # noqa: E402
from maccleaner.restaurar import restaurar  # noqa: E402

from test_f2 import DIA, PROYECTO, Caida, ZonaBase, escribir, huella_fichero  # noqa: E402


def elemento_forjado(ruta: str, eid: str, **extra) -> dict:
    st = os.lstat(ruta)
    e = {"id": eid, "regla": "caches", "grupo": os.path.basename(os.path.dirname(ruta)), "riesgo": "medio",
         "ruta": ruta, "dev": st.st_dev, "ino": st.st_ino, "uid": st.st_uid, "modo": st.st_mode,
         "tam": st.st_size, "bloques": st.st_blocks, "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns,
         "sha256": None, "edad_minima_dias": 0}
    e.update(extra)
    return e


def reencadenar(ruta: str, modificar) -> None:
    """Reescribe un manifiesto aplicando `modificar(registros)` y RECALCULA la cadena (atacante informado)."""
    with open(ruta) as fh:
        regs = [json.loads(x) for x in fh.read().splitlines()]
    modificar(regs)
    prev = "0" * 64
    with open(ruta, "w") as fh:
        for i, r in enumerate(regs):
            r["n"], r["prev"] = i, prev
            r.pop("h", None)
            r["h"] = _huella(prev, r)
            prev = r["h"]
            fh.write(json.dumps(r, sort_keys=True) + "\n")


class TestPurgaF25(ZonaBase):
    def _operacion(self):
        res = self.aplicador(self.planificar()).aplicar()
        return res, Manifiesto.cargar(res["manifiesto"])

    def test_purga_directorio_sustituido_por_enlace_entre_comprobacion_y_borrado(self):
        """D1: purge borraba por RUTA tras comprobar el inodo por descriptor; un enlace intermedio colocado
        entre ambas cosas desviaba el borrado a un fichero ajeno."""
        res, man = self._operacion()
        qarch = os.path.join(res["cuarentena"], "archivos")
        victima = escribir(os.path.join(self.zona, "victima", "Library", "Caches", "app1", "a.bin"), 999)
        h_victima = huella_fichero(victima)
        original = fsseguro.stat_en
        hecho = {"v": False}

        def stat_y_sustituir(fd, nombre):
            st = original(fd, nombre)
            if not hecho["v"]:
                hecho["v"] = True
                os.rename(os.path.join(qarch, "home"), os.path.join(qarch, "home-real"))
                os.symlink(os.path.join(self.zona, "victima"), os.path.join(qarch, "home"))
            return st

        purgar_mod.fsseguro.stat_en = stat_y_sustituir
        try:
            purgar(self.zona, dias=14, ahora=man.inicio["t"] + 20 * DIA, ejecutar=True)
        finally:
            purgar_mod.fsseguro.stat_en = original
        self.assertTrue(os.path.exists(victima), "purge borró un fichero ajeno a través del enlace")
        self.assertEqual(huella_fichero(victima), h_victima)

    def test_purga_rechaza_retencion_menor_de_un_dia(self):
        """D2: `purge --dias 0 --ejecutar` se saltaba el mínimo de 1 día documentado."""
        res, man = self._operacion()
        for dias in (0, 0.5, -3):
            with self.assertRaises(ValueError):
                purgar(self.zona, dias=dias, ahora=man.inicio["t"] + 1, ejecutar=True)
        self.assertTrue(all(os.path.exists(e["destino"]) for e in man.estados().values()))
        lanz = os.path.join(PROYECTO, "mac-cleaner")
        p = subprocess.run([lanz, "purge", "--zona", self.zona, "--dias", "0", "--ejecutar"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertTrue(all(os.path.exists(e["destino"]) for e in man.estados().values()))

    def test_purga_con_manifiesto_forjado_no_se_interrumpe(self):
        """D11: un destino forjado igual a la raíz de la cuarentena hacía saltar ValueError a mitad de purga."""
        res, man = self._operacion()
        qarch = os.path.join(res["cuarentena"], "archivos")
        primero = next(iter(man.estados()))

        def forjar(regs):
            for r in regs:
                if r.get("evento") == "intento" and r["id"] == primero:
                    r["destino"] = qarch

        reencadenar(res["manifiesto"], forjar)
        r = purgar(self.zona, dias=14, ahora=man.inicio["t"] + 20 * DIA, ejecutar=True)
        self.assertEqual((r["borrados"], r["errores"]), (3, 1))

    def test_purga_relee_el_manifiesto_bajo_bloqueo(self):
        """D4: purge decidía con la selección previa; un restore concurrente entre selección y borrado
        quedaba ignorado. Ahora se relee el estado con la operación bloqueada."""
        res, man = self._operacion()
        sel_original = purgar_mod.seleccionar

        def seleccionar_y_restaurar(*a, **k):
            sel = sel_original(*a, **k)
            restaurar(self.zona, res["op"], ruta=self.f["a"])      # «otro proceso» restaura entre medias
            return sel

        purgar_mod.seleccionar = seleccionar_y_restaurar
        try:
            r = purgar(self.zona, dias=14, ahora=man.inicio["t"] + 20 * DIA, ejecutar=True)
        finally:
            purgar_mod.seleccionar = sel_original
        self.assertEqual((r["borrados"], r["errores"]), (3, 0))
        self.assertTrue(os.path.exists(self.f["a"]))
        est = Manifiesto.cargar(res["manifiesto"]).estados()
        self.assertEqual(sorted(e["estado"] for e in est.values()), ["purgado"] * 3 + ["restaurado"])


class TestManifiestoF25(ZonaBase):
    def test_escrituras_concurrentes_no_corrompen_el_manifiesto(self):
        """D4: dos procesos con el mismo manifiesto escribían registros con el mismo número y rompían la
        cadena; la operación quedaba irrecuperable con la herramienta."""
        res = self.aplicador(self.planificar()).aplicar()
        m1 = Manifiesto.cargar(res["manifiesto"])
        m2 = Manifiesto.cargar(res["manifiesto"])
        m1.anotar("nota", texto="proceso 1")
        with self.assertRaises(ManifiestoCorrupto):
            m2.anotar("nota", texto="proceso 2 con estado viejo")
        Manifiesto.cargar(res["manifiesto"])                      # sigue íntegro
        r = restaurar(self.zona, res["op"])
        self.assertEqual((r["restaurados"], r["errores"]), (4, 0))

    def test_operacion_bloqueada_rechaza_restore_y_purge(self):
        res = self.aplicador(self.planificar()).aplicar()
        man = Manifiesto.cargar(res["manifiesto"])
        with man.bloquear():
            with self.assertRaises(ManifiestoOcupado):
                restaurar(self.zona, res["op"])
            r = purgar(self.zona, dias=14, ahora=man.inicio["t"] + 20 * DIA, ejecutar=True)
            self.assertEqual(r["borrados"], 0)
            self.assertIn("ocupada", json.dumps(r, ensure_ascii=False))
        self.assertEqual(restaurar(self.zona, res["op"])["restaurados"], 4)

    def test_manifiesto_sustituido_por_enlace(self):
        """D5: anotar() abría el manifiesto siguiendo enlaces: un enlace hacia otro fichero recibía los registros."""
        res = self.aplicador(self.planificar()).aplicar()
        copia = os.path.join(self.zona, "fuera", "copia.jsonl")
        with open(res["manifiesto"], "rb") as fh, open(copia, "wb") as out:
            out.write(fh.read())
        tam = os.path.getsize(copia)
        man = Manifiesto.cargar(res["manifiesto"])
        os.remove(res["manifiesto"])
        os.symlink(copia, res["manifiesto"])
        with self.assertRaises(OSError):
            man.anotar("nota", texto="no debe salir de la cuarentena")
        self.assertEqual(os.path.getsize(copia), tam)
        with self.assertRaises(ManifiestoCorrupto):
            Manifiesto.cargar(res["manifiesto"])


class TestRestoreF25(ZonaBase):
    @unittest.skipIf(os.geteuid() == 0, "como root los permisos no bloquean")
    def test_error_transitorio_permite_reintentar(self):
        """D3: un error pasajero (permisos) marcaba el elemento como «error» y restore ya no lo reintentaba:
        el fichero quedaba atrapado en la cuarentena (ni restaurable ni purgable)."""
        antes = {r: huella_fichero(r) for r in self.f.values()}
        res = self.aplicador(self.planificar()).aplicar()
        app2 = os.path.join(self.caches, "app2")
        os.chmod(app2, 0o555)
        r1 = restaurar(self.zona, res["op"])
        self.assertEqual((r1["restaurados"], r1["errores"]), (3, 1))
        os.chmod(app2, 0o755)
        r2 = restaurar(self.zona, res["op"])
        self.assertEqual((r2["restaurados"], r2["errores"]), (1, 0))
        self.todo_en_su_sitio(antes)

    def test_caida_durante_restore_despues_de_mover(self):
        """D6: si restore moría tras devolver el fichero y antes de anotarlo, el reintento daba error y el
        manifiesto seguía diciendo «movido»."""
        antes = {r: huella_fichero(r) for r in self.f.values()}
        res = self.aplicador(self.planificar()).aplicar()
        original = fsseguro.mover_excl
        n = {"i": 0}

        def mover_y_morir(*args):
            n["i"] += 1
            original(*args)
            if n["i"] == 2:
                raise Caida()

        restaurar_mod.fsseguro.mover_excl = mover_y_morir
        try:
            with self.assertRaises(Caida):
                restaurar(self.zona, res["op"])
        finally:
            restaurar_mod.fsseguro.mover_excl = original
        r = restaurar(self.zona, res["op"])
        self.assertEqual((r["restaurados"], r["errores"]), (3, 0))
        self.todo_en_su_sitio(antes)
        est = Manifiesto.cargar(res["manifiesto"]).estados()
        self.assertEqual([e["estado"] for e in est.values()], ["restaurado"] * 4)

    def test_fichero_grande_sin_hash_se_restaura_y_se_detecta_su_alteracion(self):
        """D7: los ficheros > hash_max (64 MB) no tienen SHA-256; restore solo miraba tamaño y mtime, así que
        un cambio de contenido con la mtime restituida (os.utime) pasaba inadvertido."""
        grande = os.path.join(self.caches, "app5", "grande.bin")
        os.makedirs(os.path.dirname(grande))
        with open(grande, "wb") as fh:
            fh.truncate(80 << 20)                                  # 80 MB dispersos: no ocupan disco
            fh.seek(10 << 20)
            fh.write(b"contenido original")
        antes = huella_fichero(grande)
        plan = self.planificar()
        e = next(x for x in plan["elementos"] if x["ruta"] == grande)
        self.assertIsNone(e["sha256"])
        res = self.aplicador(plan).aplicar()
        self.assertFalse(os.path.exists(grande))
        r = restaurar(self.zona, res["op"], ruta=grande)
        self.assertEqual(r["restaurados"], 1)
        self.assertEqual(huella_fichero(grande), antes)
        # Segunda operación: se altera la copia en cuarentena conservando tamaño y mtime.
        res2 = self.aplicador(self.planificar(ahora=self.T0 + 200), ahora=self.T0 + 260).aplicar()
        dest = next(x["destino"] for x in Manifiesto.cargar(res2["manifiesto"]).estados().values()
                    if x.get("origen") == grande)
        st = os.lstat(dest)
        with open(dest, "r+b") as fh:
            fh.seek(10 << 20)
            fh.write(b"CONTENIDO ALTERADO")
        os.utime(dest, ns=(st.st_atime_ns, st.st_mtime_ns))
        r = restaurar(self.zona, res2["op"], ruta=grande)
        self.assertEqual((r["restaurados"], r["errores"]), (0, 1))
        self.assertIn("ctime", json.dumps(r, ensure_ascii=False))
        self.assertFalse(os.path.exists(grande))                   # no se devuelve un contenido alterado


class TestApplyF25(ZonaBase):
    def test_plan_forjado_no_puede_rebajar_riesgo_ni_antiguedad(self):
        """D8: apply se fiaba del riesgo, de la regla y de la antigüedad mínima escritos en el plan. Un plan
        con la huella recalculada movía ficheros de riesgo alto o recientes."""
        plan = self.planificar()
        telegram = self.protegidos[-1]
        reciente = escribir(os.path.join(self.caches, "app4", "nuevo.bin"), 1000)
        os.utime(reciente, (self.T0 + 60, self.T0 + 60))           # modificado «hace un momento»
        en_tmp = escribir(os.path.join(self.zona, "tmp", "t.bin"), 1000)
        plan["elementos"] += [
            elemento_forjado(telegram, "f1", grupo="x"),
            elemento_forjado(reciente, "f2"),
            elemento_forjado(en_tmp, "f3"),
        ]
        antes = {p: huella_fichero(p) for p in (telegram, reciente, en_tmp)}
        res = self.aplicador(self.retocar(plan)).aplicar()
        self.assertEqual(res["movidos"], 4)
        self.todo_en_su_sitio(antes)
        est = Manifiesto.cargar(res["manifiesto"]).estados()
        self.assertIn("riesgo alto", est["f1"]["motivo"])
        self.assertIn("antigüedad", est["f2"]["motivo"])
        self.assertIn("regla", est["f3"]["motivo"])

    def test_plan_forjado_con_regla_inexistente(self):
        plan = self.planificar()
        plan["elementos"][0]["regla"] = "inventada"
        res = self.aplicador(self.retocar(plan)).aplicar()
        self.assertEqual(res["movidos"], 3)
        est = Manifiesto.cargar(res["manifiesto"]).estados()
        self.assertIn("regla", est[plan["elementos"][0]["id"]]["motivo"])

    def test_tipos_no_validos_en_el_plan(self):
        """D10: valores con tipos inesperados provocaban TypeError/ValueError en vez de PlanNoValido."""
        plan = self.planificar()
        casos = [
            lambda p: p.__setitem__("creado", "ayer"),
            lambda p: p.__setitem__("elementos", {"no": "lista"}),
            lambda p: p["elementos"][0].__setitem__("ruta", 123),
            lambda p: p["elementos"][0].__setitem__("ino", "1"),
            lambda p: p["elementos"][0].__setitem__("sha256", "zz"),
            lambda p: p["elementos"][0].__setitem__("edad_minima_dias", -1),
            lambda p: p["elementos"].append("texto"),
            lambda p: p.__setitem__("zona", ["lista"]),
        ]
        for i, cambiar in enumerate(casos):
            p = copy.deepcopy(plan)
            cambiar(p)
            with self.subTest(caso=i), self.assertRaises(PlanNoValido):
                self.aplicador(self.retocar(p))

    def test_sustitucion_que_no_se_puede_revertir_no_aborta_ni_pierde_rastro(self):
        """D9: si al devolver un objeto sustituido el origen ya estaba ocupado, la excepción abortaba toda la
        operación y el objeto ajeno quedaba en la cuarentena sin registro."""
        plan = self.planificar()
        primero = plan["elementos"][0]["ruta"]
        ap = self.aplicador(plan)
        n = {"i": 0}

        def renombrar(src_fd, src, dst_fd, dst):
            n["i"] += 1
            if n["i"] == 1:
                os.rename(primero, primero + ".original")           # el atacante aparta el original…
                escribir(primero, 64)                               # …y pone otro fichero en su lugar
                fsseguro.mover_excl(src_fd, src, dst_fd, dst)
                escribir(primero, 32)                               # y ocupa de nuevo el origen
                return
            fsseguro.mover_excl(src_fd, src, dst_fd, dst)

        ap._renombrar = renombrar
        res = ap.aplicar()
        self.assertIsNone(res["abortado"])
        self.assertEqual(res["movidos"], 3)
        est = Manifiesto.cargar(res["manifiesto"]).estados()
        e1 = est[plan["elementos"][0]["id"]]
        self.assertEqual(e1["estado"], "retenido")
        self.assertTrue(os.path.exists(e1["retenido_en"]))
        r = restaurar(self.zona, res["op"])
        self.assertEqual((r["restaurados"], r["errores"]), (3, 0))
        t = Manifiesto.cargar(res["manifiesto"]).inicio["t"]
        purgar(self.zona, dias=14, ahora=t + 20 * DIA, ejecutar=True)
        self.assertTrue(os.path.exists(e1["retenido_en"]))        # nunca se purga lo no registrado como movido

    def test_cuarentena_preexistente_con_permisos_abiertos(self):
        """D12: una cuarentena creada antes por otro proceso con permisos 0777 se aceptaba tal cual."""
        q = directorio_cuarentena(self.zona)
        os.mkdir(q)
        os.chmod(q, 0o777)
        antes = {r: huella_fichero(r) for r in self.f.values()}
        with self.assertRaisesRegex(PermissionError, "cuarentena"):
            self.aplicador(self.planificar()).aplicar()
        self.todo_en_su_sitio(antes)

    def test_reproducir_un_plan_tras_restaurar_no_vuelve_a_mover(self):
        """Garantía (sin defecto): el rename cambia ctime, así que un plan ya aplicado no se puede repetir."""
        plan = self.planificar()
        res = self.aplicador(plan).aplicar()
        restaurar(self.zona, res["op"])
        res2 = self.aplicador(plan).aplicar()
        self.assertEqual(res2["movidos"], 0)
        est = Manifiesto.cargar(res2["manifiesto"]).estados()
        self.assertTrue(all("modificado después del plan" in e["motivo"] for e in est.values()))


class TestFsseguroYGuardiaF25(ZonaBase):
    def test_asegurar_dir_no_crea_directorios_a_traves_de_enlaces(self):
        """D13: asegurar_dir creaba con mkdir por ruta: un enlace intermedio hacía crear el directorio fuera."""
        fuera = os.path.join(self.zona, "fuera")
        base = os.path.join(self.zona, "base")
        os.mkdir(base)
        os.symlink(fuera, os.path.join(base, "a"))
        with self.assertRaises(OSError):
            fsseguro.asegurar_dir(base, "a/b")
        self.assertFalse(os.path.exists(os.path.join(fuera, "b")))

    def test_guardia_resuelve_rutas_relativas_a_un_descriptor(self):
        """La guardia resolvía las rutas relativas contra el cwd e ignoraba dir_fd: bloqueaba borrados
        legítimos por descriptor dentro de la zona y no comprobaba bien los de fuera."""
        dentro = escribir(os.path.join(self.zona, "home", "x.bin"), 10)
        otra = escribir(os.path.join(self.zona, "fuera", "y.bin"), 10)
        guion = textwrap.dedent("""
            import os, sys
            sys.path.insert(0, sys.argv[1])
            from maccleaner import guardia
            guardia.activar(sys.argv[2])
            fd = os.open(os.path.dirname(sys.argv[3]), os.O_RDONLY | os.O_DIRECTORY)
            os.unlink(os.path.basename(sys.argv[3]), dir_fd=fd)
            fd2 = os.open(os.path.dirname(sys.argv[4]), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.unlink(os.path.basename(sys.argv[4]), dir_fd=fd2)
                print("NO BLOQUEADO")
            except PermissionError:
                print("BLOQUEADO")
        """)
        p = subprocess.run([sys.executable, "-I", "-B", "-c", guion, PROYECTO, os.path.join(self.zona, "home"),
                            dentro, otra], capture_output=True, text=True, cwd=PROYECTO, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.strip(), "BLOQUEADO")
        self.assertFalse(os.path.exists(dentro))
        self.assertTrue(os.path.exists(otra))



class TestCLIF25(ZonaBase):
    EDAD = 0                       # la CLI usa la hora real: los ficheros ficticios acaban de crearse

    def run_cli(self, *args):
        env = {"PATH": "/usr/bin:/bin:/usr/sbin", "HOME": os.path.expanduser("~"), "TMPDIR": os.environ.get("TMPDIR", "")}
        return subprocess.run([os.path.join(PROYECTO, "mac-cleaner"), *args], capture_output=True, text=True,
                              env=env, timeout=120)

    def _plan_cli(self):
        p = self.run_cli("scan", "--zona-sintetica", self.zona, "--config", self.cfg_ruta, "--sin-lsof")
        self.assertEqual(p.returncode, 0, p.stderr)
        p = self.run_cli("plan", "--entrada", p.stdout.split("JSON: ")[1].strip(), "--sin-lsof")
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout.split("Plan: ")[1].strip()

    def test_purga_ejecutada_por_la_cli_con_la_guardia_activa(self):
        """unlinkat/rmdirat por descriptor deben pasar la guardia dentro de la zona (0 bloqueos)."""
        p = self.run_cli("apply", "--plan", self._plan_cli())
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        res = json.loads(p.stdout)
        # Se envejece la operación 2 días reescribiendo la marca de inicio (la cadena no es una firma).
        reencadenar(res["manifiesto"], lambda regs: regs[0].__setitem__("t", regs[0]["t"] - 2 * DIA))
        p = self.run_cli("purge", "--zona", self.zona, "--dias", "1", "--ejecutar")
        self.assertEqual(p.returncode, 0, p.stderr)
        r = json.loads(p.stdout)
        self.assertEqual((r["borrados"], r["errores"]), (4, 0), p.stdout)
        self.assertEqual(os.listdir(os.path.join(res["cuarentena"], "archivos")), [])
        for ruta in self.protegidos:
            self.assertTrue(os.path.exists(ruta))

    def test_apply_por_la_cli_rechaza_una_cuarentena_insegura(self):
        plan = self._plan_cli()
        q = directorio_cuarentena(self.zona)
        os.mkdir(q)
        os.chmod(q, 0o777)
        antes = {r: huella_fichero(r) for r in self.f.values()}
        p = self.run_cli("apply", "--plan", plan)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("inseguro", p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        self.todo_en_su_sitio(antes)


if __name__ == "__main__":
    unittest.main()
