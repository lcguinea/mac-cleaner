"""Escáner de solo lectura.

Garantías de diseño:
  * Solo usa os.scandir y os.lstat: nunca abre ni lee el contenido de los ficheros y nunca
    escribe, renombra ni cambia permisos o fechas.
  * No sigue enlaces simbólicos (ni en la raíz canónica ni dentro del árbol) y no cruza a
    otro volumen (st_dev distinto del de la raíz).
  * Las rutas protegidas se podan antes de listarlas o de hacer lstat.
  * Cada fichero físico se cuenta una vez: las raíces reclamadas por una regla anterior se
    saltan en las siguientes y los enlaces duros se deduplican por (st_dev, st_ino).
  * Memoria acotada: no guarda un registro por fichero, solo agregados por grupo.
"""
from __future__ import annotations

import os
import stat
import time
from dataclasses import asdict, dataclass, field

from . import herramientas as herr
from .config import Config, Regla
from .guards import bajo
from .sistema import FicherosAbiertos

DIA = 86400
MAX_MUESTRA = 300
TRAMOS = ((7, "<7d"), (30, "7-30d"), (90, "30-90d"), (365, "90d-1a"), (None, ">1a"))


def tramo(edad_dias: float) -> str:
    for limite, nombre in TRAMOS:
        if limite is None or edad_dias < limite:
            return nombre
    return TRAMOS[-1][1]


@dataclass
class Grupo:
    nombre: str
    ruta: str
    ficheros: int = 0
    directorios: int = 0
    logico: int = 0
    fisico: int = 0
    candidatos_ficheros: int = 0
    candidatos_fisico: int = 0
    abiertos_ficheros: int = 0
    abiertos_fisico: int = 0
    mtime_max: float = 0.0          # última modificación (mtime) más reciente
    ref_max: float = 0.0            # max(mtime, birthtime) más reciente: base de la antigüedad
    ref_min: float = 0.0
    por_tramo: dict = field(default_factory=dict)   # tramo de antigüedad → bytes físicos
    riesgo: str = "medio"
    motivo_riesgo: str = ""
    estado: str = ""
    recuperable_conservador: int = 0


@dataclass
class Contadores:
    ficheros: int = 0
    directorios: int = 0
    enlaces_omitidos: int = 0
    especiales_omitidos: int = 0
    otro_volumen: int = 0
    ajenos_omitidos: int = 0          # ficheros de otro propietario en temporales
    duplicados_enlace_duro: int = 0
    duplicados_fisico: int = 0


class Escaner:
    def __init__(self, config: Config, abiertos: FicherosAbiertos | None = None, ahora: float | None = None,
                 brew_dry_run: bool = False, herramientas_fijas: dict | None = None,
                 solo_reglas: list[str] | None = None, limite: str | None = None):
        self.cfg = config
        # F2: si se indica, ninguna raíz puede quedar fuera de este directorio (zona sintética).
        self.limite = os.path.realpath(limite) if limite else None
        self.prot = config.proteccion
        self.abiertos = abiertos or FicherosAbiertos()
        self.ahora = ahora or time.time()
        self.brew_dry_run = brew_dry_run
        self.herramientas_fijas = herramientas_fijas  # pruebas: {"pip": {"disponible": True, "ruta": ...}}
        self.solo_reglas = set(solo_reglas or [])
        self.uid = os.getuid()
        # Puntos de inyección para las pruebas (registran qué se ha tocado).
        self._scandir = os.scandir
        self._lstat = os.lstat
        self.cont = Contadores()
        self.exclusiones: list[dict] = []
        self.exclusiones_por_motivo: dict[str, int] = {}
        self.errores: list[dict] = []
        self.n_errores = 0
        self._vistos_inodo: set[tuple[int, int]] = set()
        self._reclamadas: dict[str, str] = {}   # raíz canónica → id de regla

    # ── utilidades de registro ──
    def _excluir(self, ruta: str, motivo: str, regla: str) -> None:
        # Clave de agrupación: el motivo sin la parte variable (lista de marcadores encontrados).
        clave = motivo.split(" (contiene ")[0] if motivo.startswith("proyecto/entorno") else motivo
        self.exclusiones_por_motivo[clave] = self.exclusiones_por_motivo.get(clave, 0) + 1
        if len(self.exclusiones) < MAX_MUESTRA:
            self.exclusiones.append({"ruta": ruta, "motivo": motivo, "regla": regla})

    def _error(self, ruta: str, exc: OSError, regla: str) -> None:
        self.n_errores += 1
        if len(self.errores) < MAX_MUESTRA:
            self.errores.append({"ruta": ruta, "error": f"{type(exc).__name__}: {exc.strerror or exc}", "regla": regla})

    def _riesgo(self, regla: Regla, grupo: str) -> tuple[str, str]:
        riesgo, motivo = regla.riesgo, "riesgo base de la regla"
        orden = {"bajo": 0, "medio": 1, "alto": 2}
        for aj in self.cfg.ajustes:
            if aj.patron.search(grupo) and orden[aj.riesgo] > orden[riesgo]:
                riesgo, motivo = aj.riesgo, aj.motivo
        return riesgo, motivo

    # ── raíces ──
    def _raices(self, regla: Regla) -> tuple[list[str], dict | None]:
        if regla.tipo == "ruta":
            from .guards import expandir
            return [expandir(r, self.cfg.home, self.cfg.tmpdir) for r in regla.rutas], None
        if self.herramientas_fijas is not None:
            info = dict(self.herramientas_fijas.get(regla.herramienta, {"disponible": False, "motivo": "no simulada"}))
        else:
            info = herr.localizar(regla.herramienta, self.cfg.home, brew_dry_run=self.brew_dry_run)
        return ([info["ruta"]] if info.get("disponible") and info.get("ruta") else []), info

    # ── recorrido ──
    def escanear(self) -> dict:
        t0 = time.monotonic()
        reglas_out = []
        for regla in self.cfg.reglas:
            if self.solo_reglas and regla.id not in self.solo_reglas:
                continue
            reglas_out.append(self._escanear_regla(regla))
        return {
            "reglas": reglas_out,
            "contadores": asdict(self.cont),
            "exclusiones": {"por_motivo": self.exclusiones_por_motivo, "muestra": self.exclusiones,
                            "nota": "Las rutas excluidas no se inspeccionan: su tamaño no se conoce ni se suma."},
            "errores": {"n": self.n_errores, "muestra": self.errores},
            "duracion_s": round(time.monotonic() - t0, 2),
        }

    def _escanear_regla(self, regla: Regla) -> dict:
        raices_in, info_herr = self._raices(regla)
        raices_out, grupos = [], {}
        for r in raices_in:
            canon, motivo = self.prot.validar_raiz(r)
            if canon is not None and self.limite and not bajo(canon, self.limite):
                canon, motivo = None, "fuera de la zona sintética"
            if canon is None:
                raices_out.append({"ruta": r, "escaneada": False, "motivo": motivo})
                continue
            duena = next((rid for c, rid in self._reclamadas.items() if bajo(canon, c)), None)
            if duena:
                raices_out.append({"ruta": canon, "escaneada": False, "motivo": f"ya contabilizada por la regla «{duena}»"})
                continue
            self._reclamadas[canon] = regla.id
            raices_out.append({"ruta": canon, "escaneada": True, "solicitada": r})
            self._recorrer(regla, canon, grupos)

        edad_min = regla.edad_minima_dias * DIA
        lista = []
        for g in grupos.values():
            g.riesgo, g.motivo_riesgo = self._riesgo(regla, g.nombre)
            if g.abiertos_ficheros:
                g.estado = "en uso (ficheros abiertos)"
            elif g.ficheros and edad_min == 0:
                g.estado = "regenerable (umbral 0: caché gestionada por su herramienta)"
            elif g.ficheros and (self.ahora - g.ref_max) < edad_min:
                g.estado = "activo (modificado recientemente)"
            elif g.ficheros:
                g.estado = "inactivo"
            else:
                g.estado = "vacío"
            # Recuperable conservador: solo grupos enteros inactivos y que no sean de riesgo alto.
            libre = g.estado == "inactivo" or g.estado.startswith("regenerable")
            g.recuperable_conservador = g.fisico if (libre and g.riesgo != "alto") else 0
            lista.append(g)
        lista.sort(key=lambda g: g.fisico, reverse=True)

        tot = {k: sum(getattr(g, k) for g in lista) for k in
               ("ficheros", "directorios", "logico", "fisico", "candidatos_ficheros", "candidatos_fisico",
                "abiertos_ficheros", "abiertos_fisico", "recuperable_conservador")}
        tot["candidatos_fisico_sin_alto"] = sum(g.candidatos_fisico for g in lista if g.riesgo != "alto")
        out = {
            "id": regla.id, "tipo": regla.tipo, "descripcion": regla.descripcion, "riesgo": regla.riesgo,
            "edad_minima_dias": regla.edad_minima_dias, "limpieza_oficial": regla.limpieza_oficial,
            "raices": raices_out, "totales": tot, "n_grupos": len(lista),
            "grupos": [asdict(g) for g in lista[:200]],
        }
        if info_herr is not None:
            out["herramienta"] = info_herr
        return out

    def _recorrer(self, regla: Regla, raiz: str, grupos: dict) -> None:
        """Agrega por grupo lo que produce _iterar (F1)."""
        edad_min = regla.edad_minima_dias * DIA
        for tipo, ruta, gnombre, dato in self._iterar(regla, raiz):
            g_ruta = os.path.join(raiz, gnombre)
            g = grupos.get(g_ruta) or grupos.setdefault(g_ruta, Grupo(nombre=gnombre, ruta=g_ruta))
            if tipo == "dir":
                # El directorio solo cuenta si se ha podido listar y no es un proyecto.
                g.directorios += 1
                g.fisico += dato
                self.cont.directorios += 1
                continue
            st = dato
            fisico = st.st_blocks * 512
            if st.st_nlink > 1:
                clave = (st.st_dev, st.st_ino)
                if clave in self._vistos_inodo:
                    self.cont.duplicados_enlace_duro += 1
                    self.cont.duplicados_fisico += fisico
                    continue
                self._vistos_inodo.add(clave)
            self.cont.ficheros += 1
            ref = ref_antiguedad(st)
            edad = self.ahora - ref
            g.ficheros += 1
            g.logico += st.st_size
            g.fisico += fisico
            g.mtime_max = max(g.mtime_max, st.st_mtime)
            g.ref_max = max(g.ref_max, ref)
            g.ref_min = ref if not g.ref_min else min(g.ref_min, ref)
            t = tramo(edad / DIA)
            g.por_tramo[t] = g.por_tramo.get(t, 0) + fisico
            if self.abiertos.abierto(ruta):
                g.abiertos_ficheros += 1
                g.abiertos_fisico += fisico
            elif edad >= edad_min:
                g.candidatos_ficheros += 1
                g.candidatos_fisico += fisico

    def _iterar(self, regla: Regla, raiz: str, inicio: str | None = None, grupo_inicial: str | None = None):
        """Recorrido de solo lectura con TODAS las protecciones de F1.

        Genera ("dir", ruta, grupo, bloques_del_directorio) cuando un directorio se ha podido listar y no es
        un proyecto, y ("fichero", ruta, grupo, lstat) por cada fichero regular admitido. Lo comparten
        `scan` (agregados) y `plan` (elementos), de modo que ambos aplican exactamente las mismas reglas.
        """
        try:
            st_raiz = self._lstat(raiz)
        except OSError as exc:
            self._error(raiz, exc, regla.id)
            return
        if not stat.S_ISDIR(st_raiz.st_mode):
            self._excluir(raiz, "la raíz no es un directorio real", regla.id)
            return
        dev = st_raiz.st_dev
        protegidas = self.prot.rutas_protegidas_bajo(raiz)
        reclamadas_bajo = {c for c in self._reclamadas if c != raiz and bajo(c, raiz)}
        # (ruta, nombre de grupo o None en la raíz, bloques físicos del propio directorio)
        pila: list[tuple[str, str | None, int]] = [(inicio or raiz, grupo_inicial, 0)]

        while pila:
            dirpath, gnombre, bloques_dir = pila.pop()
            try:
                with self._scandir(dirpath) as it:
                    entradas = list(it)
            except OSError as exc:
                self._error(dirpath, exc, regla.id)
                continue
            motivo = self.prot.motivo_marcador({e.name for e in entradas})
            if motivo:
                # El directorio entero es un proyecto o entorno: no se cuenta nada de él.
                self._excluir(dirpath, motivo, regla.id)
                continue
            if gnombre is not None:
                yield "dir", dirpath, gnombre, bloques_dir

            for e in entradas:
                ruta = os.path.join(dirpath, e.name)
                g_nombre = gnombre or e.name
                if ruta in protegidas:
                    self._excluir(ruta, "ruta protegida", regla.id)
                    continue
                if ruta in reclamadas_bajo:
                    self._excluir(ruta, f"reclamada por la regla «{self._reclamadas[ruta]}»", regla.id)
                    continue
                try:
                    es_enlace = e.is_symlink()
                    es_dir = (not es_enlace) and e.is_dir(follow_symlinks=False)
                except OSError as exc:
                    self._error(ruta, exc, regla.id)
                    continue
                if es_enlace:
                    self.cont.enlaces_omitidos += 1
                    continue
                motivo = self.prot.motivo_nombre(e.name, es_dir)
                if motivo:
                    self._excluir(ruta, motivo, regla.id)
                    continue
                try:
                    st = self._lstat(ruta)
                except OSError as exc:
                    self._error(ruta, exc, regla.id)
                    continue
                if st.st_dev != dev:
                    self.cont.otro_volumen += 1
                    self._excluir(ruta, "otro volumen o punto de montaje", regla.id)
                    continue
                if regla.solo_propietario and st.st_uid != self.uid:
                    self.cont.ajenos_omitidos += 1
                    continue
                if stat.S_ISDIR(st.st_mode):
                    pila.append((ruta, g_nombre, st.st_blocks * 512))
                    continue
                if not stat.S_ISREG(st.st_mode):
                    self.cont.especiales_omitidos += 1
                    continue
                yield "fichero", ruta, g_nombre, st

    def iterar_grupo(self, regla: Regla, raiz: str, grupo_ruta: str):
        """Vuelve a recorrer AHORA un grupo de un escaneo (lo usa `plan`). Genera (ruta, lstat).

        Revalida la raíz, el límite de zona, la protección de la propia ruta del grupo y los marcadores
        de la raíz antes de descender; lanza ValueError si el grupo ya no es admisible.
        """
        canon, motivo = self.prot.validar_raiz(raiz)
        if canon is None:
            raise ValueError(f"raíz no admisible: {motivo}")
        if self.limite and not bajo(canon, self.limite):
            raise ValueError("raíz fuera de la zona sintética")
        if os.path.dirname(grupo_ruta) != canon:
            raise ValueError("el grupo no cuelga directamente de la raíz")
        nombre = os.path.basename(grupo_ruta)
        motivo = self.prot.motivo_ruta(grupo_ruta)
        try:
            with self._scandir(canon) as it:
                motivo = motivo or self.prot.motivo_marcador({e.name for e in it})
            st = self._lstat(grupo_ruta)
        except OSError as exc:
            raise ValueError(f"no accesible: {exc}") from exc
        if motivo:
            raise ValueError(motivo)
        if stat.S_ISLNK(st.st_mode):
            raise ValueError("el grupo es un enlace simbólico")
        if st.st_dev != self._lstat(canon).st_dev:
            raise ValueError("el grupo está en otro volumen")
        if stat.S_ISREG(st.st_mode):
            m = self.prot.motivo_nombre(nombre, es_dir=False)
            if m:
                raise ValueError(m)
            if not (regla.solo_propietario and st.st_uid != self.uid):
                yield grupo_ruta, st
            return
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError("el grupo no es un fichero ni un directorio")
        for tipo, ruta, _g, dato in self._iterar(regla, canon, inicio=grupo_ruta, grupo_inicial=nombre):
            if tipo == "fichero":
                yield ruta, dato


def ref_antiguedad(st) -> float:
    """Antigüedad de referencia: max(mtime, birthtime). Un fichero recién creado nunca parece viejo."""
    return max(st.st_mtime, getattr(st, "st_birthtime", st.st_mtime))
