"""Pruebas focalizadas de F1, con un HOME ficticio. Nunca tocan rutas reales del usuario."""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from maccleaner import herramientas  # noqa: E402
from maccleaner.config import cargar  # noqa: E402
from maccleaner.escaner import Escaner  # noqa: E402
from maccleaner.informe import generar  # noqa: E402
from maccleaner.sistema import FicherosAbiertos  # noqa: E402

DIA = 86400
PROYECTO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def escribir(ruta: str, n: int = 0, contenido: bytes | None = None) -> str:
    os.makedirs(os.path.dirname(ruta), exist_ok=True)
    with open(ruta, "wb") as fh:
        fh.write(contenido if contenido is not None else os.urandom(n))
    return ruta


def instantanea(raiz: str) -> dict:
    """Estado completo del árbol: metadatos (sin atime) y SHA-256 de cada fichero regular."""
    out = {}
    for d, dirs, files in os.walk(raiz, followlinks=False):
        for nombre in dirs + files + [""]:
            p = os.path.join(d, nombre) if nombre else d
            try:
                st = os.lstat(p)
            except OSError:
                continue
            h = None
            if stat.S_ISREG(st.st_mode) and os.access(p, os.R_OK):
                with open(p, "rb") as fh:
                    h = hashlib.sha256(fh.read()).hexdigest()
            out[p] = (st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino, st.st_nlink, st.st_uid,
                      os.readlink(p) if stat.S_ISLNK(st.st_mode) else None, h)
    return out


class Base(unittest.TestCase):
    """Crea un HOME y un TMPDIR ficticios y una configuración mínima apuntando a ellos."""

    def setUp(self) -> None:
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="mc-test-"))
        self.home = os.path.join(self.tmp, "home")
        self.tmpdir = os.path.join(self.tmp, "tmpdir")
        self.caches = os.path.join(self.home, "Library", "Caches")
        self.logs = os.path.join(self.home, "Library", "Logs")
        for d in (self.caches, self.logs, self.tmpdir, os.path.join(self.home, ".ssh"), os.path.join(self.home, "Documents")):
            os.makedirs(d)
        self.fuera = os.path.join(self.tmp, "fuera")       # fuera de las bases permitidas
        escribir(os.path.join(self.fuera, "grande.bin"), 2_000_000)
        self.registro_lstat: list[str] = []
        self.registro_scandir: list[str] = []

    def tearDown(self) -> None:
        for d, dirs, _ in os.walk(self.tmp):
            for x in dirs:
                try:
                    os.chmod(os.path.join(d, x), 0o755)
                except OSError:
                    pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def config(self, reglas: str, proteccion: str = "") -> object:
        ruta = os.path.join(self.tmp, "reglas.toml")
        with open(ruta, "w") as fh:
            fh.write(textwrap.dedent(f"""
                [general]
                edad_minima_dias = 30
                usar_lsof = false
                baja_prioridad = false
                [proteccion]
                rutas = ["~/Library/Caches/claude-cli-nodejs"]
                nombres = ['(ableton|remotion)']
                extensiones = [".als", ".gguf", ".pem"]
                marcadores_proyecto = [".git", "package.json"]
                marcadores_venv = ["pyvenv.cfg"]
                {proteccion}
                [[ajuste_riesgo]]
                patron = 'telegram'
                riesgo = "alto"
                motivo = "medios"
            """) + textwrap.dedent(reglas))
        return cargar(ruta, home=self.home, tmpdir=self.tmpdir)

    def escaner(self, cfg, **kw) -> Escaner:
        esc = Escaner(cfg, **kw)
        real_lstat, real_scandir = os.lstat, os.scandir

        def lstat(p, *a, **k):
            self.registro_lstat.append(p)
            return real_lstat(p, *a, **k)

        def scandir(p, *a, **k):
            self.registro_scandir.append(p)
            return real_scandir(p, *a, **k)

        esc._lstat, esc._scandir = lstat, scandir
        return esc

    def tocados(self) -> list[str]:
        return self.registro_lstat + self.registro_scandir

    REGLA_CACHES = """
        [[regla]]
        id = "caches"
        tipo = "ruta"
        rutas = ["~/Library/Caches"]
        riesgo = "medio"
        edad_minima_dias = 30
    """


class TestNoModifica(Base):
    def test_el_escaner_no_modifica_nada(self):
        escribir(os.path.join(self.caches, "app", "a.bin"), 100_000)
        escribir(os.path.join(self.caches, "app", "sub", "b.bin"), 5000)
        escribir(os.path.join(self.logs, "x.log"), 300, b"log\n" * 75)
        os.link(os.path.join(self.caches, "app", "a.bin"), os.path.join(self.caches, "app", "a-hard.bin"))
        os.symlink(self.fuera, os.path.join(self.caches, "enlace"))
        with open(os.path.join(self.caches, "disperso.bin"), "wb") as fh:
            fh.seek(5_000_000)
            fh.write(b"x")
        cfg = self.config(self.REGLA_CACHES + """
            [[regla]]
            id = "logs"
            tipo = "ruta"
            rutas = ["~/Library/Logs"]
            riesgo = "bajo"
        """)
        antes = instantanea(self.tmp)
        # Si el escáner intentara abrir un fichero con os.open, la prueba falla.
        with mock.patch("os.open", side_effect=AssertionError("el escáner no debe abrir ficheros")), \
             mock.patch("os.remove", side_effect=AssertionError), mock.patch("os.unlink", side_effect=AssertionError), \
             mock.patch("os.rename", side_effect=AssertionError), mock.patch("os.utime", side_effect=AssertionError), \
             mock.patch("os.chmod", side_effect=AssertionError), mock.patch("shutil.rmtree", side_effect=AssertionError):
            res = self.escaner(cfg).escanear()
        self.assertGreater(res["contadores"]["ficheros"], 0)
        self.assertEqual(antes, instantanea(self.tmp), "el árbol cambió durante el escaneo")


class TestExclusiones(Base):
    def test_rutas_protegidas_no_se_inspeccionan(self):
        casos = {
            "config": os.path.join(self.caches, "claude-cli-nodejs", "x.bin"),
            "nombre_fijo": os.path.join(self.caches, "com.anthropic.claudefordesktop", "x.bin"),
            "argos": os.path.join(self.caches, "Argos-web", "x.bin"),
            "rea": os.path.join(self.caches, "rea-investigacion", "x.bin"),
            "codex": os.path.join(self.caches, "Codex", "x.bin"),
            "gemini": os.path.join(self.caches, "com.google.antigravity", "x.bin"),
            "aeon": os.path.join(self.caches, "aeon_tools", "x.bin"),
            "git": os.path.join(self.caches, "proyecto", "src", "main.py"),
            "venv": os.path.join(self.caches, "entorno", "lib", "x.py"),
            "venv_nombre": os.path.join(self.caches, "algo", ".venv", "x.py"),
            "music": os.path.join(self.caches, "Ableton", "x.bin"),
            "ext": os.path.join(self.caches, "app", "cancion.als"),
            "modelo": os.path.join(self.caches, "app", "llama.gguf"),
        }
        for p in casos.values():
            escribir(p, 1000)
        os.makedirs(os.path.join(self.caches, "proyecto", ".git"))
        escribir(os.path.join(self.caches, "entorno", "pyvenv.cfg"), 10)
        normal = escribir(os.path.join(self.caches, "area51", "ok.bin"), 4096)   # «rea» dentro de otra palabra: no protegido
        escribir(os.path.join(self.caches, "app", "ok.bin"), 4096)

        res = self.escaner(self.config(self.REGLA_CACHES)).escanear()
        tocados = self.tocados()
        for nombre, p in casos.items():
            self.assertNotIn(p, tocados, f"{nombre}: {p} fue inspeccionado")
        for d in ("claude-cli-nodejs", "com.anthropic.claudefordesktop", "Argos-web", "rea-investigacion", "Codex",
                  "com.google.antigravity", "aeon_tools", "Ableton"):
            self.assertFalse(any(t.startswith(os.path.join(self.caches, d)) for t in tocados), f"{d} fue tocado")
        # El proyecto y el entorno se listan (para ver el marcador) pero sus hijos no se inspeccionan.
        self.assertFalse(any(t.startswith(os.path.join(self.caches, "proyecto") + "/") for t in self.registro_lstat))
        self.assertNotIn(os.path.join(self.caches, "proyecto", "src"), self.registro_scandir)
        self.assertIn(normal, self.registro_lstat)
        grupos = {g["nombre"] for g in res["reglas"][0]["grupos"]}
        self.assertTrue({"area51", "app"} <= grupos, grupos)
        self.assertNotIn("proyecto", grupos)
        self.assertNotIn("entorno", grupos)
        app = next(g for g in res["reglas"][0]["grupos"] if g["nombre"] == "app")
        self.assertEqual(app["ficheros"], 1)  # solo ok.bin: .als y .gguf excluidos
        self.assertEqual(sum(res["reglas"][0]["totales"][k] for k in ("ficheros",)), 2)  # ok.bin + area51/ok.bin
        self.assertGreaterEqual(sum(res["exclusiones"]["por_motivo"].values()), 13)

    def test_raices_fuera_de_bases_o_protegidas_se_rechazan(self):
        os.symlink(self.fuera, os.path.join(self.caches, "atajo"))
        cfg = self.config("""
            [[regla]]
            id = "mala"
            tipo = "ruta"
            rutas = ["~/Documents", "~/.ssh", "/etc", "~/Library/Caches/atajo", "~/Library/Caches/claude-cli-nodejs"]
        """)
        os.makedirs(os.path.join(self.caches, "claude-cli-nodejs"))
        res = self.escaner(cfg).escanear()
        raices = res["reglas"][0]["raices"]
        self.assertTrue(all(not r["escaneada"] for r in raices), raices)
        self.assertEqual(self.tocados(), [])

    def test_la_config_no_puede_quitar_la_proteccion_fija(self):
        escribir(os.path.join(self.caches, "claude-algo", "x.bin"), 100)
        cfg = self.config(self.REGLA_CACHES)
        cfg.proteccion.nombres = []   # aunque se vacíe la lista configurable…
        res = self.escaner(cfg).escanear()
        self.assertNotIn("claude-algo", {g["nombre"] for g in res["reglas"][0]["grupos"]})


class TestEnlaces(Base):
    def test_no_sigue_enlaces_simbolicos(self):
        escribir(os.path.join(self.caches, "app", "real.bin"), 8192)
        os.symlink(self.fuera, os.path.join(self.caches, "fuera"))                      # directorio externo
        os.symlink(os.path.join(self.fuera, "grande.bin"), os.path.join(self.caches, "app", "f.bin"))  # fichero externo
        os.symlink(self.caches, os.path.join(self.caches, "app", "bucle"))              # bucle
        os.symlink(os.path.join(self.home, ".ssh"), os.path.join(self.caches, "llaves"))  # destino protegido
        os.symlink("/no/existe", os.path.join(self.caches, "roto"))
        res = self.escaner(self.config(self.REGLA_CACHES)).escanear()
        t = res["reglas"][0]["totales"]
        self.assertEqual(t["ficheros"], 1)
        self.assertLess(t["fisico"], 100_000)
        self.assertEqual(res["contadores"]["enlaces_omitidos"], 5)
        self.assertFalse(any(x.startswith(self.fuera) or x.startswith(os.path.join(self.home, ".ssh")) for x in self.tocados()))

    def test_raiz_canonica_y_otro_volumen(self):
        escribir(os.path.join(self.caches, "vol", "x.bin"), 4096)
        escribir(os.path.join(self.caches, "app", "y.bin"), 4096)
        cfg = self.config(self.REGLA_CACHES)
        esc = self.escaner(cfg)
        lstat_real = esc._lstat
        vol = os.path.join(self.caches, "vol")

        class St:  # simula un punto de montaje con otro st_dev
            def __init__(self, st):
                self._st = st

            def __getattr__(self, k):
                return self._st.st_dev + 1 if k == "st_dev" else getattr(self._st, k)

        esc._lstat = lambda p: St(lstat_real(p)) if p == vol else lstat_real(p)
        res = esc.escanear()
        self.assertEqual(res["contadores"]["otro_volumen"], 1)
        self.assertNotIn(os.path.join(vol, "x.bin"), self.registro_lstat)


class TestPermisos(Base):
    @unittest.skipIf(os.geteuid() == 0, "como root los permisos no bloquean")
    def test_errores_de_permiso_no_detienen_el_escaneo(self):
        escribir(os.path.join(self.caches, "cerrado", "secreto.bin"), 1000)
        escribir(os.path.join(self.caches, "abierto", "ok.bin"), 4096)
        os.chmod(os.path.join(self.caches, "cerrado"), 0o000)
        res = self.escaner(self.config(self.REGLA_CACHES)).escanear()
        self.assertGreaterEqual(res["errores"]["n"], 1)
        self.assertTrue(any(e["ruta"].endswith("cerrado") for e in res["errores"]["muestra"]))
        self.assertIn("abierto", {g["nombre"] for g in res["reglas"][0]["grupos"]})


class TestDobleConteo(Base):
    def test_enlaces_duros_y_reglas_solapadas(self):
        a = escribir(os.path.join(self.caches, "a", "x.bin"), 50_000)
        os.makedirs(os.path.join(self.caches, "b"))
        os.link(a, os.path.join(self.caches, "b", "y.bin"))
        escribir(os.path.join(self.caches, "pip", "w.bin"), 20_000)
        cfg = self.config("""
            [[regla]]
            id = "pip"
            tipo = "ruta"
            rutas = ["~/Library/Caches/pip"]
            riesgo = "bajo"
            edad_minima_dias = 0
        """ + self.REGLA_CACHES + """
            [[regla]]
            id = "repetida"
            tipo = "ruta"
            rutas = ["~/Library/Caches", "~/Library/Caches/a"]
        """)
        res = self.escaner(cfg).escanear()
        por_id = {r["id"]: r for r in res["reglas"]}
        self.assertEqual(por_id["pip"]["totales"]["ficheros"], 1)
        self.assertEqual(por_id["caches"]["totales"]["ficheros"], 1)        # x.bin una vez; y.bin es el mismo inodo
        self.assertEqual(res["contadores"]["duplicados_enlace_duro"], 1)
        self.assertNotIn("pip", {g["nombre"] for g in por_id["caches"]["grupos"]})
        self.assertTrue(all(not r["escaneada"] for r in por_id["repetida"]["raices"]))
        total = sum(r["totales"]["fisico"] for r in res["reglas"])
        du = int(subprocess.run(["du", "-sk", self.caches], capture_output=True, text=True).stdout.split()[0]) * 1024
        self.assertLessEqual(abs(total - du), max(16384, du * 0.02), (total, du))


class TestTamanos(Base):
    def test_consistencia_con_du(self):
        for i in range(40):
            escribir(os.path.join(self.caches, f"app{i % 4}", f"f{i}.bin"), (i + 1) * 3001)
        with open(os.path.join(self.caches, "app0", "disperso.bin"), "wb") as fh:
            fh.seek(20_000_000)
            fh.write(b"z")
        res = self.escaner(self.config(self.REGLA_CACHES)).escanear()
        t = res["reglas"][0]["totales"]
        du = int(subprocess.run(["du", "-sk", self.caches], capture_output=True, text=True).stdout.split()[0]) * 1024
        self.assertLessEqual(abs(t["fisico"] - du), max(16384, du * 0.02), (t["fisico"], du))
        logico_esperado = sum((i + 1) * 3001 for i in range(40)) + 20_000_001
        self.assertEqual(t["logico"], logico_esperado)
        self.assertLess(t["fisico"], t["logico"] / 2, "el fichero disperso debe ocupar mucho menos de lo que mide")


class TestClasificacion(Base):
    def test_antiguedad_abiertos_y_riesgo(self):
        viejo = escribir(os.path.join(self.caches, "viejo", "a.bin"), 10_000)
        reciente = escribir(os.path.join(self.caches, "mixto", "nuevo.bin"), 10_000)
        escribir(os.path.join(self.caches, "mixto", "viejo.bin"), 10_000)
        abierto = escribir(os.path.join(self.caches, "enuso", "db.sqlite"), 10_000)
        escribir(os.path.join(self.caches, "ru.keepcoder.Telegram", "media.bin"), 10_000)
        ahora = time.time() + 40 * DIA                      # todo «tiene» 40 días…
        os.utime(reciente, (ahora - DIA, ahora - DIA))       # …salvo este, de hace 1 día
        res = self.escaner(self.config(self.REGLA_CACHES), ahora=ahora,
                           abiertos=FicherosAbiertos([abierto], disponible=True)).escanear()
        g = {x["nombre"]: x for x in res["reglas"][0]["grupos"]}
        self.assertEqual(g["viejo"]["estado"], "inactivo")
        self.assertEqual(g["viejo"]["recuperable_conservador"], g["viejo"]["fisico"])
        self.assertTrue(g["mixto"]["estado"].startswith("activo"))
        self.assertEqual(g["mixto"]["recuperable_conservador"], 0)
        self.assertEqual(g["mixto"]["candidatos_ficheros"], 1)
        self.assertTrue(g["enuso"]["estado"].startswith("en uso"))
        self.assertEqual(g["enuso"]["candidatos_fisico"], 0)
        self.assertEqual(g["ru.keepcoder.Telegram"]["riesgo"], "alto")
        self.assertEqual(g["ru.keepcoder.Telegram"]["recuperable_conservador"], 0)
        self.assertIn(viejo, self.registro_lstat)

    def test_solo_propietario_en_temporales(self):
        escribir(os.path.join(self.tmpdir, "mio.tmp"), 4096)
        ajeno = escribir(os.path.join(self.tmpdir, "ajeno.tmp"), 4096)
        cfg = self.config("""
            [[regla]]
            id = "tmp"
            tipo = "ruta"
            rutas = ["$TMPDIR"]
            edad_minima_dias = 7
            solo_propietario = true
        """)
        esc = self.escaner(cfg)
        real_l = esc._lstat

        class St:
            def __init__(self, st):
                self._st = st

            def __getattr__(self, k):
                return 12345 if k == "st_uid" else getattr(self._st, k)

        esc._lstat = lambda p: St(real_l(p)) if p == ajeno else real_l(p)
        res = esc.escanear()
        self.assertEqual(res["reglas"][0]["totales"]["ficheros"], 1)
        self.assertEqual(res["contadores"]["ajenos_omitidos"], 1)


class TestHerramientasEInforme(Base):
    def test_regla_herramienta_simulada_e_informe(self):
        pipdir = os.path.join(self.caches, "pip")
        escribir(os.path.join(pipdir, "http-v2", "a"), 9000)
        cfg = self.config("""
            [[regla]]
            id = "pip"
            tipo = "herramienta"
            herramienta = "pip"
            riesgo = "bajo"
            edad_minima_dias = 0
            limpieza_oficial = "pip cache purge"
        """ + self.REGLA_CACHES)
        res = self.escaner(cfg, herramientas_fijas={"pip": {"herramienta": "pip", "disponible": True, "ruta": pipdir,
                                                            "consultas": ["pip cache dir"]}}).escanear()
        self.assertEqual(res["reglas"][0]["totales"]["ficheros"], 1)
        self.assertEqual(res["reglas"][0]["totales"]["recuperable_conservador"], res["reglas"][0]["totales"]["fisico"])
        md = generar({"generado": "x", "config": "c", "escaneo": res, "ahora": time.time()})
        self.assertIn("Ocupado ≠ recuperable", md)
        self.assertIn("pip cache purge", md)

    def test_npm_se_resuelve_sin_ejecutar_npm(self):
        os.makedirs(os.path.join(self.home, ".npm"))
        with mock.patch.dict(os.environ, {}, clear=False), mock.patch("subprocess.run", side_effect=AssertionError):
            os.environ.pop("npm_config_cache", None)
            os.environ.pop("NPM_CONFIG_CACHE", None)
            info = herramientas.npm(self.home)
        self.assertTrue(info["disponible"])
        self.assertEqual(info["ruta"], os.path.join(self.home, ".npm"))

    def test_parse_brew_dry_run_y_lista_blanca(self):
        out = ("Would remove: /x/a.tar.gz (12.5MB)\nWould remove: /x/b (1,707 files, 34.6MB)\n"
               "==> This operation would free approximately 47.1MB of disk space.\n")
        r = herramientas._parse_brew_dry_run(out)
        self.assertEqual(r["n_elementos"], 2)
        self.assertEqual(r["bytes_estimados"], 47_100_000)
        with self.assertRaises(ValueError):
            herramientas.localizar("rm", self.home)


class TestGuardia(Base):
    def test_guardia_bloquea_escrituras_y_subprocesos(self):
        permitido = os.path.join(self.tmp, "salida")
        os.makedirs(permitido)
        victima = escribir(os.path.join(self.caches, "victima.bin"), 100)
        codigo = textwrap.dedent(f"""
            import os, subprocess, sys
            sys.path.insert(0, {PROYECTO!r})
            from maccleaner import guardia
            guardia.activar({permitido!r})
            fallos = []
            def debe_fallar(nombre, f):
                try:
                    f()
                    fallos.append(nombre)
                except PermissionError:
                    pass
            debe_fallar("open-w", lambda: open({victima!r}, "a"))
            debe_fallar("os.open", lambda: os.open({victima!r}, os.O_WRONLY))
            debe_fallar("remove", lambda: os.remove({victima!r}))
            debe_fallar("rename", lambda: os.rename({victima!r}, {victima!r} + ".x"))
            debe_fallar("utime", lambda: os.utime({victima!r}, (0, 0)))
            debe_fallar("chmod", lambda: os.chmod({victima!r}, 0o600))
            debe_fallar("mkdir", lambda: os.mkdir({self.caches!r} + "/nuevo"))
            debe_fallar("rm", lambda: subprocess.run(["/bin/rm", {victima!r}]))
            debe_fallar("sh", lambda: subprocess.run("echo hola", shell=True))
            # ejecutable de la lista blanca con stdin=DEVNULL (abre /dev/null en O_RDWR): permitido
            subprocess.run(["/usr/sbin/lsof", "-v"], stdin=subprocess.DEVNULL, capture_output=True)
            open(os.path.join({permitido!r}, "ok.json"), "w").write("{{}}")   # dentro de salida: permitido
            open({victima!r}, "rb").read()                                    # lectura: permitida
            print("FALLOS=" + ",".join(fallos))
        """)
        antes = instantanea(self.caches)
        p = subprocess.run([sys.executable, "-I", "-B", "-c", codigo], capture_output=True, text=True,
                           env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"})
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("FALLOS=\n", p.stdout + "\n")
        self.assertEqual(p.stdout.strip(), "FALLOS=")
        self.assertTrue(os.path.exists(os.path.join(permitido, "ok.json")))
        self.assertEqual(antes, instantanea(self.caches))


class TestConfigProyecto(unittest.TestCase):
    def test_reglas_toml_del_proyecto_es_valido(self):
        cfg = cargar(os.path.join(PROYECTO, "config", "reglas.toml"))
        ids = [r.id for r in cfg.reglas]
        self.assertEqual(ids[:3], ["homebrew", "pip", "npm"])   # las específicas antes que caches-usuario
        self.assertEqual(ids[-1], "caches-usuario")


if __name__ == "__main__":
    unittest.main()
