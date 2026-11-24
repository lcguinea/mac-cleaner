"""Pruebas de F5A: orden `autorizacion` (solo lectura) que usa la app de macOS."""
from __future__ import annotations

import datetime as dt
import io
import json
import os
import sys
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from maccleaner import autorizacion  # noqa: E402
from maccleaner.cli import estado_autorizacion, main  # noqa: E402


def _iso(t: float) -> str:
    return dt.datetime.fromtimestamp(t).isoformat(timespec="seconds")


class TestAutorizacion(unittest.TestCase):
    def test_con_ventana_solo_vigente_dentro(self):
        t = time.time()
        with mock.patch.object(autorizacion, "REQUIERE_VENTANA", True), \
                mock.patch.object(autorizacion, "VENTANA", (_iso(t), _iso(t + 3600))):
            self.assertFalse(estado_autorizacion(t - 60)["vigente"])
            self.assertTrue(estado_autorizacion(t + 60)["vigente"])
            with mock.patch.object(autorizacion, "VENTANA", None):
                self.assertFalse(estado_autorizacion(t + 60)["vigente"])

    def test_sin_reglas_nunca_vigente(self):
        with mock.patch.object(autorizacion, "REGLAS", ()):
            self.assertFalse(estado_autorizacion()["vigente"])

    def test_cli_imprime_json_y_no_escribe(self):
        buf = io.StringIO()
        with mock.patch("builtins.open", side_effect=AssertionError("no debe abrir ficheros")), redirect_stdout(buf):
            rc = main(["autorizacion"])
        self.assertEqual(rc, 0)
        d = json.loads(buf.getvalue())
        self.assertEqual(d["id"], autorizacion.ID)
        self.assertEqual(d["reglas"], list(autorizacion.REGLAS))
        self.assertEqual(d["purga_real"], autorizacion.PURGA_REAL)


if __name__ == "__main__":
    unittest.main()
