"""F3: autenticación HMAC-SHA256 de planes y manifiestos con clave en el Llavero de macOS.

Diseño
------
* Algoritmo: HMAC-SHA256 (hmac + hashlib de la biblioteca estándar), comparación en tiempo constante.
* Separación de dominios: cada MAC se calcula sobre `DOMINIO + contexto + JSON canónico`, de modo que un MAC
  de plan no sirve como MAC de manifiesto, ni el de una operación para otra:
    - plan:        "mac-cleaner/plan/v2"        + id_clave + JSON canónico del plan (incluye versión, id, zona,
                   creado, caduca, configuración y elementos).
    - manifiesto:  "mac-cleaner/manifiesto/v2"  + id_clave + op + JSON canónico del registro (incluye n y prev).
* Claves: 32 bytes aleatorios (secrets.token_bytes). Cada clave tiene un identificador público (`id_clave`)
  que viaja en el plan o manifiesto; el secreto NUNCA se escribe en ficheros, informes ni registros.
* Almacenes:
    - AlmacenLlavero: Llavero de inicio de sesión (Security.framework vía ctypes, sin dependencias).
      Servicio "mac-cleaner.hmac"; una entrada por clave (cuenta = id_clave) y una entrada «indice» con la
      clave activa y la lista de claves (no secreta).
    - AlmacenSintetico: claves en memoria para pruebas y zonas sintéticas. Sus claves están marcadas como
      sintéticas y NUNCA autentican un plan sobre datos reales.
* Selección del almacén (almacen_actual): el fijado con establecer_almacen() (pruebas); si no, la variable
  MAC_CLEANER_CLAVE_SINTETICA (hex de 64 caracteres, solo zonas sintéticas); si no, el Llavero.
"""
from __future__ import annotations

import ctypes
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
from dataclasses import dataclass

ALG = "HMAC-SHA256"
DOMINIO_PLAN = b"mac-cleaner/plan/v2"
DOMINIO_MANIFIESTO = b"mac-cleaner/manifiesto/v2"
SERVICIO_LLAVERO = "mac-cleaner.hmac"
CUENTA_INDICE = "indice"
ENV_SINTETICA = "MAC_CLEANER_CLAVE_SINTETICA"
_ID_VALIDO = re.compile(r"(k|sintetica)-[0-9a-f]{16}")


class ErrorAutenticacion(ValueError):
    """MAC ausente, inválido o calculado con una clave que no está disponible."""


class ClaveNoDisponible(ErrorAutenticacion):
    pass


@dataclass(frozen=True)
class Clave:
    id: str
    secreto: bytes
    sintetica: bool

    def __repr__(self) -> str:          # nunca mostrar el secreto (logs, trazas, informes)
        return f"Clave(id={self.id!r}, sintetica={self.sintetica})"

    __str__ = __repr__


def _canon(d) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _mac(clave: Clave, dominio: bytes, contexto: list[str], datos) -> str:
    partes = [dominio, clave.id.encode()] + [c.encode() for c in contexto] + [_canon(datos)]
    return hmac.new(clave.secreto, b"\0".join(partes), hashlib.sha256).hexdigest()


def nuevo_id(sintetica: bool = False) -> str:
    return ("sintetica-" if sintetica else "k-") + secrets.token_hex(8)


# ── almacenes ──────────────────────────────────────────────────────────────────

class AlmacenSintetico:
    """Claves en memoria (pruebas y zonas sintéticas). No toca el Llavero."""

    def __init__(self, claves: list[Clave] | None = None):
        self._claves = {c.id: c for c in (claves or [])}
        self._activa = claves[-1].id if claves else None

    @classmethod
    def nuevo(cls) -> "AlmacenSintetico":
        return cls([Clave(nuevo_id(True), secrets.token_bytes(32), True)])

    @classmethod
    def desde_hex(cls, hexa: str) -> "AlmacenSintetico":
        if not re.fullmatch(r"[0-9a-fA-F]{64}", hexa or ""):
            raise ClaveNoDisponible(f"{ENV_SINTETICA} debe tener 64 dígitos hexadecimales")
        secreto = bytes.fromhex(hexa)
        cid = "sintetica-" + hashlib.sha256(b"id:" + secreto).hexdigest()[:16]   # id estable, sin revelar la clave
        return cls([Clave(cid, secreto, True)])

    def activa(self) -> Clave:
        if not self._activa:
            raise ClaveNoDisponible("no hay clave sintética activa")
        return self._claves[self._activa]

    def obtener(self, cid: str) -> Clave:
        if cid not in self._claves:
            raise ClaveNoDisponible(f"la clave {cid} no está disponible")
        return self._claves[cid]

    def rotar(self) -> Clave:
        c = Clave(nuevo_id(True), secrets.token_bytes(32), True)
        self._claves[c.id] = c
        self._activa = c.id
        return c

    def olvidar(self, cid: str) -> None:            # simula la pérdida de una clave
        self._claves.pop(cid, None)
        if self._activa == cid:
            self._activa = None

    def estado(self) -> dict:
        return {"almacen": "sintetico", "activa": self._activa, "claves": sorted(self._claves)}


class _Llavero:
    """Acceso mínimo al Llavero con la API clásica de Security.framework (ctypes; sin subprocesos ni argv)."""
    errSecItemNotFound = -25300
    errSecDuplicateItem = -25299

    def __init__(self):
        self.s = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        self.cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        u32, vp, cp = ctypes.c_uint32, ctypes.c_void_p, ctypes.c_char_p
        self.s.SecKeychainFindGenericPassword.argtypes = [vp, u32, cp, u32, cp, ctypes.POINTER(u32),
                                                           ctypes.POINTER(vp), ctypes.POINTER(vp)]
        self.s.SecKeychainAddGenericPassword.argtypes = [vp, u32, cp, u32, cp, u32, cp, ctypes.POINTER(vp)]
        self.s.SecKeychainItemModifyAttributesAndData.argtypes = [vp, vp, u32, cp]
        self.s.SecKeychainItemFreeContent.argtypes = [vp, vp]
        self.cf.CFRelease.argtypes = [vp]
        for f in (self.s.SecKeychainFindGenericPassword, self.s.SecKeychainAddGenericPassword,
                  self.s.SecKeychainItemModifyAttributesAndData, self.s.SecKeychainItemFreeContent):
            f.restype = ctypes.c_int32

    def leer(self, cuenta: str) -> bytes | None:
        srv, acc = SERVICIO_LLAVERO.encode(), cuenta.encode()
        n, datos, item = ctypes.c_uint32(), ctypes.c_void_p(), ctypes.c_void_p()
        r = self.s.SecKeychainFindGenericPassword(None, len(srv), srv, len(acc), acc, ctypes.byref(n),
                                                  ctypes.byref(datos), ctypes.byref(item))
        if r == self.errSecItemNotFound:
            return None
        if r != 0:
            raise ClaveNoDisponible(f"Llavero: error {r} al leer {cuenta}")
        try:
            return ctypes.string_at(datos, n.value)
        finally:
            self.s.SecKeychainItemFreeContent(None, datos)
            if item:
                self.cf.CFRelease(item)

    def escribir(self, cuenta: str, valor: bytes, reemplazar: bool = False) -> None:
        srv, acc = SERVICIO_LLAVERO.encode(), cuenta.encode()
        r = self.s.SecKeychainAddGenericPassword(None, len(srv), srv, len(acc), acc, len(valor), valor, None)
        if r == self.errSecDuplicateItem and reemplazar:
            n, datos, item = ctypes.c_uint32(), ctypes.c_void_p(), ctypes.c_void_p()
            r = self.s.SecKeychainFindGenericPassword(None, len(srv), srv, len(acc), acc, ctypes.byref(n),
                                                      ctypes.byref(datos), ctypes.byref(item))
            if r == 0:
                self.s.SecKeychainItemFreeContent(None, datos)
                try:
                    r = self.s.SecKeychainItemModifyAttributesAndData(item, None, len(valor), valor)
                finally:
                    self.cf.CFRelease(item)
        if r != 0:
            raise ClaveNoDisponible(f"Llavero: error {r} al guardar {cuenta}")


class AlmacenLlavero:
    """Claves HMAC en el Llavero de inicio de sesión. Crear o rotar exige una orden explícita del usuario."""

    def __init__(self, llavero: _Llavero | None = None):
        self.k = llavero or _Llavero()

    def _indice(self) -> dict:
        raw = self.k.leer(CUENTA_INDICE)
        if raw is None:
            return {"activa": None, "claves": []}
        try:
            ind = json.loads(raw)
            assert isinstance(ind.get("claves"), list)
            return ind
        except (ValueError, AssertionError) as exc:
            raise ClaveNoDisponible("índice de claves del Llavero dañado") from exc

    def activa(self) -> Clave:
        ind = self._indice()
        if not ind.get("activa"):
            raise ClaveNoDisponible("no hay clave HMAC en el Llavero: créala con `mac-cleaner clave crear`")
        return self.obtener(ind["activa"])

    def obtener(self, cid: str) -> Clave:
        if not _ID_VALIDO.fullmatch(cid) or cid.startswith("sintetica-"):
            raise ClaveNoDisponible(f"identificador de clave no válido para el Llavero: {cid!r}")
        sec = self.k.leer(cid)
        if sec is None or len(sec) != 32:
            raise ClaveNoDisponible(f"la clave {cid} no está en el Llavero")
        return Clave(cid, sec, False)

    def crear(self) -> Clave:
        ind = self._indice()
        if ind.get("activa"):
            raise ClaveNoDisponible(f"ya existe la clave activa {ind['activa']}; usa `clave rotar` para sustituirla")
        return self._nueva(ind)

    def rotar(self) -> Clave:
        return self._nueva(self._indice())

    def _nueva(self, ind: dict) -> Clave:
        c = Clave(nuevo_id(False), secrets.token_bytes(32), False)
        self.k.escribir(c.id, c.secreto)
        ind = {"activa": c.id, "claves": ind.get("claves", []) + [
            {"id": c.id, "creada": dt.datetime.now().isoformat(timespec="seconds")}]}
        self.k.escribir(CUENTA_INDICE, json.dumps(ind).encode(), reemplazar=True)
        return c

    def estado(self) -> dict:
        ind = self._indice()
        return {"almacen": "llavero", "servicio": SERVICIO_LLAVERO, "activa": ind.get("activa"),
                "claves": ind.get("claves", [])}


_almacen = None


def establecer_almacen(almacen) -> None:
    """Fija el almacén del proceso (pruebas). None vuelve a la selección automática."""
    global _almacen
    _almacen = almacen


def almacen_actual():
    global _almacen
    if _almacen is None:
        if os.environ.get(ENV_SINTETICA):
            _almacen = AlmacenSintetico.desde_hex(os.environ[ENV_SINTETICA])
        else:
            _almacen = AlmacenLlavero()
    return _almacen


# ── planes ──────────────────────────────────────────────────────────────────────

def _cuerpo_plan(plan: dict) -> dict:
    return {k: v for k, v in plan.items() if k not in ("huella", "autenticacion")}


def firmar_plan(plan: dict, clave: Clave) -> dict:
    plan["autenticacion"] = {"alg": ALG, "id_clave": clave.id, "sintetica": clave.sintetica,
                             "mac": _mac(clave, DOMINIO_PLAN, [], _cuerpo_plan(plan))}
    return plan


def verificar_plan(plan: dict, almacen=None) -> Clave:
    """Comprueba el MAC del plan. Devuelve la clave usada o lanza ErrorAutenticacion."""
    a = plan.get("autenticacion")
    if not isinstance(a, dict) or a.get("alg") != ALG or not isinstance(a.get("mac"), str) \
            or not isinstance(a.get("id_clave"), str):
        raise ErrorAutenticacion("el plan no está autenticado (falta el MAC HMAC-SHA256)")
    clave = (almacen or almacen_actual()).obtener(a["id_clave"])
    if not hmac.compare_digest(_mac(clave, DOMINIO_PLAN, [], _cuerpo_plan(plan)), a["mac"]):
        raise ErrorAutenticacion("MAC del plan no válido: el plan fue modificado o la clave no es la correcta")
    if bool(a.get("sintetica")) != clave.sintetica:
        raise ErrorAutenticacion("el tipo de clave declarado no coincide con el de la clave")
    if clave.sintetica and not plan.get("zona"):
        raise ErrorAutenticacion("una clave sintética no puede autorizar operaciones sobre datos reales")
    return clave


# ── manifiestos ────────────────────────────────────────────────────────────────

def mac_registro(clave: Clave, op: str, registro: dict) -> str:
    return _mac(clave, DOMINIO_MANIFIESTO, [op], {k: v for k, v in registro.items() if k != "mac"})


def verificar_registro(clave: Clave, op: str, registro: dict) -> bool:
    mac = registro.get("mac")
    return isinstance(mac, str) and hmac.compare_digest(mac_registro(clave, op, registro), mac)
