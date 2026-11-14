"""`apply`: mueve a cuarentena los elementos de un plan. En F2 SOLO dentro de una zona sintética.

Orden de comprobaciones (todas antes de tocar nada):
  1. Plan: tipo, versión, huella, caducidad, zona sintética válida, elementos dentro de la zona, sin duplicados
     ni riesgo alto (plan.validar_plan).
  2. Configuración: la del plan, con la misma huella; su HOME y TMPDIR deben estar dentro de la zona.
  3. Por elemento, en el momento de moverlo:
     - protecciones de F1 recalculadas (bases, rutas y nombres protegidos, extensión, marcadores de
       proyecto o entorno en cualquier antepasado);
     - regla, grupo, riesgo y antigüedad mínima recalculados con la configuración verificada (F2.5): del plan
       no se acepta ni el riesgo ni la antigüedad; la ruta debe colgar de una raíz de su regla;
     - directorio padre abierto componente a componente con O_NOFOLLOW (ningún enlace intermedio);
     - lstat del nombre: fichero regular, mismo st_dev/st_ino, propietario = usuario, nlink = 1,
       tamaño, mtime_ns y ctime_ns idénticos a los del plan;
     - antigüedad todavía mayor o igual al umbral y fichero no abierto (lsof tomado al empezar);
     - SHA-256 igual al del plan, si se calculó;
     - cuarentena en el mismo volumen (st_dev).
  4. Movimiento: `intento` en el manifiesto (fsync) → renameatx_np(RENAME_EXCL) → verificación de inodo en
     destino (si no coincide, se devuelve a su sitio y se registra; si el origen ya está ocupado, el objeto
     ajeno queda «retenido» y registrado) → `movido` con el ctime en cuarentena (fsync).
La cuarentena debe ser del usuario y no escribible por grupo ni otros, y la operación se hace con el
manifiesto bloqueado (flock): un restore o purge simultáneo de la misma operación se rechaza.
Un elemento que no supera una comprobación se OMITE (con motivo) y se sigue con el siguiente. Un error del
sistema al mover ABORTA el resto: lo ya movido queda registrado y es restaurable.
"""
from __future__ import annotations

import datetime as dt
import os
import secrets
import stat
import time

from . import fsseguro, zona as zona_mod
from .config import cargar as cargar_config
from .escaner import DIA, ref_antiguedad, riesgo_de
from .guards import bajo, expandir
from .manifiesto import Manifiesto
from .plan import PlanNoValido, sha256_fichero, validar_plan
from .sistema import FicherosAbiertos

DIR_ARCHIVOS = "archivos"


def directorio_cuarentena(zona: str) -> str:
    return os.path.join(zona, zona_mod.NOMBRE_CUARENTENA)


class Aplicador:
    def __init__(self, plan: dict, *, ahora: float | None = None, abiertos: FicherosAbiertos | None = None):
        self.plan = plan
        self.ahora = ahora or time.time()
        self.zona = validar_plan(plan, self.ahora)
        for clave in ("home", "tmpdir"):
            if not bajo(os.path.realpath(plan[clave]), self.zona):
                raise PlanNoValido(f"el {clave} del plan no está dentro de la zona sintética")
        if not os.path.exists(plan["config"]) or sha256_fichero(plan["config"]) != plan["config_sha256"]:
            raise PlanNoValido("la configuración del plan no existe o cambió: vuelve a planificar")
        self.cfg = cargar_config(plan["config"], home=plan["home"], tmpdir=plan["tmpdir"])
        self.prot = self.cfg.proteccion
        self.reglas = {r.id: r for r in self.cfg.reglas}
        self._raices_regla = {r.id: [os.path.realpath(expandir(x, self.cfg.home, self.cfg.tmpdir)) for x in r.rutas]
                              for r in self.cfg.reglas if r.tipo == "ruta"}
        self.abiertos = abiertos if abiertos is not None else FicherosAbiertos.capturar()
        self.uid = os.getuid()
        self._renombrar = fsseguro.mover_excl       # punto de inyección para las pruebas de fallos
        self._marcadores_cache: dict[str, str | None] = {}
        if not fsseguro.disponible():  # pragma: no cover
            raise PlanNoValido("renameatx_np no disponible: no se puede garantizar el movimiento sin sobrescritura")

    # ── protecciones recalculadas ──
    def _motivo_marcador_dir(self, d: str) -> str | None:
        if d not in self._marcadores_cache:
            try:
                fd = fsseguro.abrir_dir(self.zona, os.path.relpath(d, self.zona)) if d != self.zona else os.open(d, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    nombres = set(os.listdir(fd))
                finally:
                    os.close(fd)
                self._marcadores_cache[d] = self.prot.motivo_marcador(nombres)
            except OSError as exc:
                self._marcadores_cache[d] = f"ruta cambiada: no se puede comprobar el directorio ({exc.strerror or exc})"
        return self._marcadores_cache[d]

    def motivo_proteccion(self, ruta: str) -> str | None:
        base = next((b for b in self.prot._bases if bajo(ruta, b) and ruta != b), None)
        if base is None:
            return "fuera de las bases permitidas"
        m = self.prot.motivo_ruta(ruta) or self.prot.motivo_nombre(os.path.basename(ruta), es_dir=False)
        if m:
            return m
        d = os.path.dirname(ruta)
        while True:
            m = self._motivo_marcador_dir(d)
            if m:
                return m
            if d == base or len(d) <= len(base):
                return None
            d = os.path.dirname(d)

    def regla_del_elemento(self, e: dict) -> tuple[int | None, str | None]:
        """Recalcula con la configuración verificada lo que el plan declara (regla, grupo, riesgo, antigüedad).
        Devuelve (antigüedad mínima en días, None) o (None, motivo de omisión)."""
        regla = self.reglas.get(e["regla"])
        if regla is None:
            return None, f"la regla del plan «{e['regla']}» no existe en la configuración"
        if regla.tipo != "ruta":
            return None, f"la regla «{regla.id}» es de herramienta: no admitida en zona sintética"
        ruta = e["ruta"]
        raiz = next((r for r in self._raices_regla[regla.id] if bajo(ruta, r) and ruta != r), None)
        if raiz is None:
            return None, f"la ruta no está bajo ninguna raíz de la regla «{regla.id}»"
        grupo = ruta[len(raiz):].strip("/").split("/")[0]
        riesgo, motivo = riesgo_de(self.cfg, regla, grupo)
        if riesgo == "alto":
            return None, f"riesgo alto según la configuración ({motivo})"
        if grupo != e["grupo"]:
            return None, f"el grupo del plan ({e['grupo']}) no coincide con el real ({grupo})"
        return max(regla.edad_minima_dias, int(e["edad_minima_dias"])), None

    # ── comprobación de un elemento ──
    def _verificar(self, e: dict, pfd: int, nombre: str, edad_minima_dias: int) -> tuple[os.stat_result | None, str | None]:
        try:
            st = fsseguro.stat_en(pfd, nombre)
        except FileNotFoundError:
            return None, "ya no existe"
        if stat.S_ISLNK(st.st_mode):
            return None, "sustituido por un enlace simbólico"
        if not stat.S_ISREG(st.st_mode):
            return None, "ya no es un fichero regular"
        if (st.st_dev, st.st_ino) != (e["dev"], e["ino"]):
            return None, "identidad distinta (inodo o volumen): ruta sustituida"
        if st.st_uid != self.uid or e["uid"] != self.uid:
            return None, "el propietario no es el usuario"
        if st.st_nlink != 1:
            return None, "tiene enlaces duros"
        if (st.st_size, st.st_mtime_ns, st.st_ctime_ns) != (e["tam"], e["mtime_ns"], e["ctime_ns"]):
            return None, "modificado después del plan (tamaño, mtime o ctime)"
        edad_min = edad_minima_dias * DIA
        if edad_min and ref_antiguedad(st) > self.ahora - edad_min:
            return None, "más reciente que el umbral de antigüedad"
        if self.abiertos.abierto(e["ruta"]):
            return None, "abierto por un proceso"
        if e.get("sha256"):
            try:
                if fsseguro.sha256_en(pfd, nombre, st.st_ino) != e["sha256"]:
                    return None, "contenido distinto del planificado (SHA-256)"
            except OSError as exc:
                return None, f"no se pudo verificar el contenido: {exc.strerror or exc}"
        return st, None

    # ── ejecución ──
    def aplicar(self) -> dict:
        qbase = directorio_cuarentena(self.zona)
        op = dt.datetime.fromtimestamp(time.time()).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
        os.close(fsseguro.asegurar_dir(self.zona, zona_mod.NOMBRE_CUARENTENA, privado=True))
        os.close(fsseguro.asegurar_dir(qbase, op, privado=True))
        qop = os.path.join(qbase, op)
        os.close(fsseguro.asegurar_dir(qop, DIR_ARCHIVOS, privado=True))
        qarch = os.path.join(qop, DIR_ARCHIVOS)
        man = Manifiesto.crear(os.path.join(qop, "manifiesto.jsonl"), op=op, plan_id=self.plan["id"],
                               plan_huella=self.plan["huella"], zona=self.zona, cuarentena=qop,
                               n_elementos=len(self.plan["elementos"]), ahora=self.ahora,
                               lsof={"disponible": self.abiertos.disponible, "n": len(self.abiertos)})
        res = {"op": op, "cuarentena": qop, "manifiesto": man.ruta, "movidos": 0, "omitidos": 0, "errores": 0,
               "bytes_movidos": 0, "abortado": None}
        with man.bloquear():
            return self._aplicar(man, qarch, res)

    def _aplicar(self, man: Manifiesto, qarch: str, res: dict) -> dict:
        try:
            for e in self.plan["elementos"]:
                rel = zona_mod.exigir_dentro(e["ruta"], self.zona)
                rel_dir, nombre = os.path.dirname(rel), os.path.basename(rel)
                motivo = self.motivo_proteccion(e["ruta"])
                if motivo:
                    man.anotar("omitido", id=e["id"], motivo=motivo if motivo.startswith("ruta cambiada") else f"protegido: {motivo}")
                    res["omitidos"] += 1
                    continue
                edad_dias, motivo = self.regla_del_elemento(e)
                if motivo:
                    man.anotar("omitido", id=e["id"], motivo=motivo)
                    res["omitidos"] += 1
                    continue
                try:
                    pfd = fsseguro.abrir_dir(self.zona, rel_dir)
                except OSError as exc:
                    man.anotar("omitido", id=e["id"], motivo=f"ruta cambiada (directorio padre): {exc.strerror or exc}")
                    res["omitidos"] += 1
                    continue
                dfd = None
                try:
                    st, motivo = self._verificar(e, pfd, nombre, edad_dias)
                    if motivo:
                        man.anotar("omitido", id=e["id"], motivo=motivo)
                        res["omitidos"] += 1
                        continue
                    try:
                        dfd = fsseguro.asegurar_dir(qarch, rel_dir, privado=True)
                    except OSError as exc:
                        man.anotar("omitido", id=e["id"], motivo=f"cuarentena no utilizable: {exc.strerror or exc}")
                        res["omitidos"] += 1
                        continue
                    if os.fstat(dfd).st_dev != st.st_dev:
                        man.anotar("omitido", id=e["id"], motivo="la cuarentena está en otro volumen")
                        res["omitidos"] += 1
                        continue
                    destino = os.path.join(qarch, rel)
                    meta = {k: e[k] for k in ("dev", "ino", "uid", "modo", "tam", "mtime_ns", "ctime_ns", "sha256")}
                    meta["birthtime"] = getattr(st, "st_birthtime", None)
                    man.anotar("intento", id=e["id"], origen=e["ruta"], destino=destino, rel=rel, meta=meta)
                    try:
                        self._renombrar(pfd, nombre, dfd, nombre)
                    except OSError as exc:
                        man.anotar("error", id=e["id"], motivo=f"{type(exc).__name__}: {exc.strerror or exc}")
                        res["errores"] += 1
                        res["abortado"] = f"error del sistema al mover {e['ruta']}: {exc.strerror or exc}"
                        man.anotar("abortado", motivo=res["abortado"])
                        break
                    st2 = fsseguro.stat_en(dfd, nombre)
                    if (st2.st_dev, st2.st_ino) != (st.st_dev, st.st_ino):
                        # Se movió otro objeto (sustitución entre la comprobación y el movimiento): devolverlo.
                        try:
                            self._renombrar(dfd, nombre, pfd, nombre)
                        except OSError as exc:
                            # El origen ya está ocupado (o no se puede escribir): el objeto ajeno se queda en la
                            # cuarentena, registrado como «retenido», y se sigue con el resto.
                            man.anotar("sustitucion_no_revertida", id=e["id"], ino_encontrado=st2.st_ino,
                                       destino=destino, motivo=f"objeto ajeno retenido: {exc.strerror or exc}")
                            res["errores"] += 1
                            continue
                        man.anotar("sustitucion_revertida", id=e["id"], ino_encontrado=st2.st_ino)
                        res["omitidos"] += 1
                        continue
                    man.anotar("movido", id=e["id"], ino=st2.st_ino, ctime_ns=st2.st_ctime_ns)
                    res["movidos"] += 1
                    res["bytes_movidos"] += st.st_blocks * 512
                finally:
                    os.close(pfd)
                    if dfd is not None:
                        os.close(dfd)
        except Exception as exc:
            res["abortado"] = f"excepción inesperada: {type(exc).__name__}: {exc}"
            man.anotar("abortado", motivo=res["abortado"])
            man.anotar("cierre", **{k: res[k] for k in ("movidos", "omitidos", "errores", "abortado")})
            raise
        # Una caída real (SIGKILL, corte de luz) no llega aquí: el manifiesto queda sin «cierre» y
        # restore resuelve los «intento» pendientes por inodo; purge no toca operaciones sin cierre.
        man.anotar("cierre", **{k: res[k] for k in ("movidos", "omitidos", "errores", "abortado")})
        return res
