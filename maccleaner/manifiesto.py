"""Manifiesto persistente de una operación: JSON Lines con encadenamiento SHA-256 y fsync por registro.

Cada registro lleva `prev` (huella del anterior) y `h` = SHA-256(prev + JSON canónico del registro sin `h`).
Editar, borrar o reordenar un registro rompe la cadena y se detecta al cargar. Truncar el FINAL no se
puede detectar con la cadena sola; por eso existe el registro `cierre`, y `purge` nunca toca
operaciones sin cierre. Es una huella de integridad, NO una firma autenticada: quien pueda escribir el
fichero puede recalcular la cadena entera.

Protocolo de escritura anticipada: antes de mover se escribe `intento`, después `movido`. Si el proceso
muere entre ambos, `restore` localiza el fichero por su inodo (en el origen o en la cuarentena).

Concurrencia (F2.5): apply, restore y purge toman un bloqueo exclusivo (flock) del manifiesto durante toda
la operación y recargan su contenido después de obtenerlo. Además, `anotar` comprueba que el fichero tiene
exactamente el tamaño que este objeto escribió o leyó: si otro proceso añadió registros, se niega a escribir
en lugar de romper la cadena. El manifiesto nunca se abre siguiendo enlaces simbólicos.

Autenticación (F3): si el manifiesto se crea con una clave, el registro `inicio` declara `autenticacion`
(algoritmo e id de clave) y CADA registro lleva `mac` = HMAC-SHA256 ligado a la operación (autenticacion.py).
Al cargar se exige la clave y se verifican todos los MAC; un manifiesto sin autenticación (formato F2) o con
un MAC inválido se rechaza. Solo la recuperación sin clave (restaurar.inventario_recuperacion) lo carga sin
verificar los MAC, y NUNCA escribe en él (F3.5: lleva su propio registro, recuperacion.jsonl).

Registro final incompleto (F3.5): una caída a mitad de escribir deja una última línea sin «\n». Esa cola se
ignora al cargar (equivale a «el registro no llegó a escribirse», que el protocolo de escritura anticipada ya
contempla), no se escribe nada detrás de ella y `reparar_cola()` (con la operación bloqueada) la recorta y
anota `cola_descartada` con su tamaño y SHA-256. purge no toca operaciones con cola incompleta o descartada.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import stat
import time

from . import autenticacion as aut

CERO = "0" * 64


class ManifiestoCorrupto(ValueError):
    pass


class ManifiestoNoAutenticado(ManifiestoCorrupto):
    """Falta la autenticación, la clave no está disponible o un MAC no es válido."""


FORMATO = "mac-cleaner-manifiesto/2"


class ManifiestoOcupado(RuntimeError):
    """Otro proceso tiene bloqueada la operación (apply, restore o purge en curso)."""


def _abrir_lectura(ruta: str) -> int:
    fd = os.open(ruta, os.O_RDONLY | os.O_NOFOLLOW)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(f"el manifiesto no es un fichero regular: {ruta}")
    return fd


def _canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _huella(prev: str, reg: dict) -> str:
    return hashlib.sha256(prev.encode() + _canon(reg)).hexdigest()


class Manifiesto:
    def __init__(self, ruta: str, registros: list[dict] | None = None, tam: int = 0,
                 clave: aut.Clave | None = None, recuperacion: bool = False):
        self.ruta = ruta
        self.registros = registros or []
        self._tam = tam            # bytes del fichero que este objeto conoce (leídos o escritos)
        self.clave = clave
        self.recuperacion = recuperacion
        self._cola = b""           # bytes de una última línea incompleta (caída a mitad de escritura)

    @property
    def ultimo(self) -> str:
        return self.registros[-1]["h"] if self.registros else CERO

    def anotar(self, evento: str, **datos) -> dict:
        if self._cola:
            raise ManifiestoCorrupto("el manifiesto termina en un registro incompleto: hay que repararlo "
                                     "(reparar_cola) antes de escribir")
        if self.recuperacion:
            raise ManifiestoCorrupto("un manifiesto cargado sin verificar los MAC es de solo lectura")
        reg = {"n": len(self.registros), "t": time.time(), "evento": evento, "prev": self.ultimo, **datos}
        if self.recuperacion:
            reg["recuperacion"] = True          # anotado sin clave: no lleva MAC
        reg["h"] = _huella(reg["prev"], {k: v for k, v in reg.items() if k != "h"})
        if self.clave is not None:
            op = reg["op"] if evento == "inicio" else self.inicio["op"]
            reg["mac"] = aut.mac_registro(self.clave, op, reg)
        linea = (json.dumps(reg, ensure_ascii=False, sort_keys=True) + "\n").encode()
        # Ruta absoluta (la guardia la comprueba) y O_NOFOLLOW: un enlace en lugar del manifiesto da ELOOP.
        fd = os.open(self.ruta, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError(f"el manifiesto no es un fichero regular: {self.ruta}")
            if st.st_size != self._tam:
                raise ManifiestoCorrupto("el manifiesto cambió desde que se cargó (¿otro proceso?): "
                                         "no se escribe para no romper la cadena")
            escrito = 0
            while escrito < len(linea):
                escrito += os.write(fd, linea[escrito:])
            os.fsync(fd)
        finally:
            os.close(fd)
        self._tam += len(linea)
        self.registros.append(reg)
        return reg

    @classmethod
    def crear(cls, ruta: str, clave: aut.Clave | None = None, **inicio) -> "Manifiesto":
        fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if clave is not None:
            inicio["autenticacion"] = {"alg": aut.ALG, "id_clave": clave.id, "formato": FORMATO}
        m = cls(ruta, clave=clave)
        m.anotar("inicio", **inicio)
        return m

    @classmethod
    def cargar(cls, ruta: str, *, verificar: bool = True, almacen=None) -> "Manifiesto":
        """verificar=False SOLO para la recuperación sin clave: comprueba la cadena, no los MAC."""
        regs, prev = [], CERO
        try:
            fd = _abrir_lectura(ruta)
            with os.fdopen(fd, "rb") as fh:
                datos = fh.read()
            corte = datos.rfind(b"\n") + 1                 # todo lo posterior es una línea incompleta
            lineas = datos[:corte].decode("utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise ManifiestoCorrupto(f"no se puede leer el manifiesto: {exc}") from exc
        for i, linea in enumerate(lineas):
            try:
                reg = json.loads(linea)
            except json.JSONDecodeError as exc:
                raise ManifiestoCorrupto(f"línea {i + 1} no es JSON válido") from exc
            if reg.get("n") != i or reg.get("prev") != prev:
                raise ManifiestoCorrupto(f"cadena rota en la línea {i + 1} (orden o registro anterior alterado)")
            if _huella(prev, {k: v for k, v in reg.items() if k not in ("h", "mac")}) != reg.get("h"):
                raise ManifiestoCorrupto(f"huella no válida en la línea {i + 1} (registro modificado)")
            regs.append(reg)
            prev = reg["h"]
        if not regs or regs[0]["evento"] != "inicio":
            raise ManifiestoCorrupto("el manifiesto no empieza por un registro de inicio")
        if not verificar:
            m = cls(ruta, regs, tam=len(datos), recuperacion=True)
            m._cola = datos[corte:]
            return m
        a = regs[0].get("autenticacion")
        if not isinstance(a, dict) or a.get("alg") != aut.ALG or a.get("formato") != FORMATO:
            raise ManifiestoNoAutenticado("manifiesto sin autenticación HMAC (formato F2 o alterado): "
                                          "solo se puede restaurar con --recuperacion-sin-clave")
        try:
            clave = (almacen or aut.almacen_actual()).obtener(str(a.get("id_clave")))
        except aut.ClaveNoDisponible as exc:
            raise ManifiestoNoAutenticado(f"{exc}: sin la clave no se puede autenticar el manifiesto; usa "
                                          "`restore --recuperacion-sin-clave` (inventario + confirmación manual, "
                                          "docs/SEGURIDAD-F3.md §3.3)") from exc
        op = regs[0].get("op")
        if not isinstance(op, str):
            raise ManifiestoNoAutenticado("el registro de inicio no identifica la operación")
        for i, reg in enumerate(regs):
            if not aut.verificar_registro(clave, op, reg):
                raise ManifiestoNoAutenticado(f"MAC no válido en la línea {i + 1}: registro alterado, de otra "
                                              "operación o anotado sin clave")
        m = cls(ruta, regs, tam=len(datos), clave=clave)
        m._cola = datos[corte:]
        return m

    @property
    def cola_incompleta(self) -> int:
        return len(self._cola)

    @property
    def cola_descartada(self) -> bool:
        return any(r["evento"] == "cola_descartada" for r in self.registros)

    def reparar_cola(self) -> None:
        """Recorta la línea final incompleta y lo anota (llamar con la operación bloqueada)."""
        if not self._cola:
            return
        fd = os.open(self.ruta, os.O_WRONLY | os.O_NOFOLLOW)
        try:
            if os.fstat(fd).st_size != self._tam:
                raise ManifiestoCorrupto("el manifiesto cambió desde que se cargó: no se repara")
            valido = self._tam - len(self._cola)
            os.ftruncate(fd, valido)
            os.fsync(fd)
        finally:
            os.close(fd)
        cola, self._cola, self._tam = self._cola, b"", valido
        self.anotar("cola_descartada", bytes=len(cola), sha256=hashlib.sha256(cola).hexdigest())

    @contextlib.contextmanager
    def bloquear(self):
        """Bloqueo exclusivo de la operación (no espera: si está ocupada, ManifiestoOcupado). Al obtenerlo
        se recarga el contenido, de modo que las decisiones se toman sobre el estado más reciente."""
        try:
            fd = _abrir_lectura(self.ruta)
        except OSError as exc:
            raise ManifiestoCorrupto(f"no se puede abrir el manifiesto: {exc}") from exc
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ManifiestoOcupado("la operación está ocupada por otro proceso (apply, restore o purge)") from exc
            if os.fstat(fd).st_size != self._tam:
                fresco = Manifiesto.cargar(self.ruta, verificar=not self.recuperacion,
                                           almacen=_AlmacenFijo(self.clave) if self.clave else None)
                self.registros, self._tam, self._cola = fresco.registros, fresco._tam, fresco._cola
            yield self
        finally:
            os.close(fd)                 # cerrar el descriptor libera el flock

    @property
    def autenticado(self) -> bool:
        return self.clave is not None

    # ── consultas ──
    @property
    def inicio(self) -> dict:
        return self.registros[0]

    @property
    def cerrado(self) -> bool:
        return any(r["evento"] == "cierre" for r in self.registros)

    def estados(self) -> dict[str, dict]:
        """Estado actual por elemento: intento | movido | omitido | error | restaurado | purgado | no_movido | retenido."""
        est: dict[str, dict] = {}
        for r in self.registros:
            eid = r.get("id")
            if not eid:
                continue
            e = est.setdefault(eid, {"id": eid})
            if r["evento"] == "intento":
                e.update(estado="intento", origen=r["origen"], destino=r["destino"], meta=r["meta"])
            elif r["evento"] in ("movido", "omitido", "error", "restaurado", "purgado", "no_movido"):
                e["estado"] = r["evento"]
                if r["evento"] in ("omitido", "error"):
                    e["motivo"] = r.get("motivo")
                if r["evento"] == "movido":
                    e["ctime_movido"] = r.get("ctime_ns")   # para detectar cambios en cuarentena sin SHA-256
            elif r["evento"] == "conflicto":
                e["ultimo_conflicto"] = r.get("motivo")   # el fichero sigue en cuarentena (estado movido)
            elif r["evento"] == "restaurar_error":
                e["ultimo_error"] = r.get("motivo")       # sigue en cuarentena: restore se puede reintentar
            elif r["evento"] == "sustitucion_revertida":
                e["estado"] = "omitido"
                e["motivo"] = "sustitución detectada y revertida"
            elif r["evento"] == "sustitucion_no_revertida":
                # Un objeto AJENO quedó en la cuarentena y no se pudo devolver: nunca se restaura ni se purga
                # automáticamente; requiere revisión manual.
                e.update(estado="retenido", retenido_en=r.get("destino"), motivo=r.get("motivo"))
        return est


class _AlmacenFijo:
    """Recarga con la misma clave con la que se cargó el manifiesto."""

    def __init__(self, clave: aut.Clave):
        self.clave = clave

    def obtener(self, cid: str) -> aut.Clave:
        if cid != self.clave.id:
            raise aut.ClaveNoDisponible(f"la clave {cid} no es la del manifiesto")
        return self.clave
