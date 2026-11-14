# mac-cleaner F3 · Autenticación, lista blanca y modo sombra

Estado (14-11-2026): F3 prepara la limpieza real, pero **no la habilita**. `zona.LIMPIEZA_REAL_HABILITADA = False`
y la puerta de zona de `plan.validar_plan` siguen siendo la primera barrera: `apply`, `restore` y `purge` solo
actúan en zonas sintéticas. Nada de lo descrito aquí es una garantía absoluta; los riesgos abiertos están en §7.

## 1. Qué añade F3

| Pieza | Módulo | Qué hace |
|---|---|---|
| Autenticación HMAC-SHA256 | `maccleaner/autenticacion.py` | Firma y verifica planes (v2) y cada registro del manifiesto. Clave en el Llavero |
| Anti-reproducción | `maccleaner/aplicar.py` | Reserva exclusiva del id del plan antes de mover nada |
| Coherencia origen/destino | `maccleaner/restaurar.py` | `restore` exige `destino == archivos/<ruta relativa del origen>` |
| Lista blanca npm/pip | `maccleaner/listablanca.py` | Define qué podría limpiarse de verdad. Hoy solo la usa el modo sombra |
| Modo sombra | `maccleaner/sombra.py`, `mac-cleaner sombra` | Evalúa qué se limpiaría, sin mover ni borrar nada |
| Gestión de claves | `mac-cleaner clave estado/crear/rotar` | Crear o rotar exige una orden expresa del usuario |

## 2. Autenticación

### 2.1 Diseño

- **Algoritmo**: HMAC-SHA256 (`hmac` y `hashlib` de la biblioteca estándar) y comparación en tiempo constante (`hmac.compare_digest`).
- **Separación de dominios**: cada MAC se calcula sobre `dominio ‖ id_clave ‖ contexto ‖ JSON canónico`:
  - Plan: dominio `mac-cleaner/plan/v2`. El JSON canónico incluye versión, id, zona, `creado`, `caduca`, la huella SHA-256 de la configuración, HOME y TMPDIR ficticios y todos los elementos.
  - Manifiesto: dominio `mac-cleaner/manifiesto/v2`, con el **id de la operación** como contexto. Cada registro incluye su número `n` y el `prev` de la cadena.
- **Consecuencias**:
  - Un MAC de plan no vale como MAC de manifiesto.
  - Un registro no se puede copiar de una operación a otra.
  - Un plan de la zona A no vale para la zona B.
  - Alargar la caducidad, quitar o añadir elementos o cambiar la configuración invalida el MAC.
- **Versiones**: los planes v1 (F2) se rechazan. Los manifiestos sin autenticación (formato F2) solo se pueden restaurar en modo recuperación (§3.3).
- **El MAC no sustituye a la revalidación**: `apply` sigue recalculando protecciones, regla, riesgo, antigüedad, inodo, metadatos y SHA-256. La autenticación prueba que el plan lo generó quien tiene la clave, no que el disco siga igual.

### 2.2 Dónde está la clave

- **Llavero de inicio de sesión**, servicio `mac-cleaner.hmac`:
  - Una entrada por clave, con cuenta = `id_clave` (`k-<16 hex>`) y 32 bytes aleatorios.
  - Una entrada `indice` con la clave activa y la lista de claves con su fecha de creación. Es información no secreta.
- **Acceso**: con la API de Security.framework mediante `ctypes`. No usa subprocesos y el secreto nunca pasa por `argv`, el entorno, ficheros, registros ni informes.
- **Representación**: `Clave.__repr__` no muestra el secreto. Los planes y manifiestos solo guardan `id_clave`.
- **Creación**: ninguna orden crea la clave por su cuenta. La crea el usuario con `mac-cleaner clave crear`. F3 no ha creado ninguna (`clave estado` → `activa: null`).

### 2.3 Claves sintéticas (pruebas y zonas sintéticas)

- **Almacén**: `AlmacenSintetico` guarda las claves en memoria, marcadas como `sintetica`.
- **Origen**:
  - En las pruebas, `establecer_almacen()`.
  - En los procesos de CLI de las pruebas, la variable `MAC_CLEANER_CLAVE_SINTETICA` (64 dígitos hexadecimales).
  - En `demo`, una clave efímera.
- **Límite**: una clave sintética **nunca autoriza un plan sin zona** (`verificar_plan` lo rechaza). Cuando exista el modo real, la variable de entorno no podrá autorizar nada real.
- **Aislamiento del Llavero**: las pruebas no tocan el Llavero real. El almacén del Llavero se prueba con un Llavero simulado en memoria (`TestAlmacenLlavero`).

## 3. Procedimientos de claves

### 3.1 Crear (una vez, por decisión del usuario)

```bash
./mac-cleaner clave crear     # escribe solo en el Llavero; muestra el id, nunca el secreto
./mac-cleaner clave estado
```

### 3.2 Rotar

`clave rotar` crea una clave nueva y la marca como activa. **Las anteriores se conservan** para que las operaciones
que firmaron sigan siendo verificables, restaurables y purgables. Los planes nuevos se firman con la clave nueva.

### 3.3 Pérdida de la clave

Por ejemplo, si se borra la entrada del Llavero o el Llavero se restablece.

- **Planes pendientes**: dejan de ser aplicables. Hay que volver a ejecutar `scan` y `plan` con una clave nueva.
- **Operaciones en cuarentena**: sus manifiestos ya no se pueden autenticar.
  - `purge` **no las toca nunca**: nada se borra sin MAC válidos.
  - `restore --recuperacion-sin-clave` las restaura comprobando la cadena SHA-256, la coherencia origen/destino, el inodo, los metadatos y el SHA-256 o el ctime, sin sobrescribir y solo dentro de la zona. Lo que anota queda marcado como `recuperacion`.
- **Después**: `clave crear` (si no queda índice) o `clave rotar`.

### 3.4 Compromiso de la clave (sospecha de que otro proceso la leyó)

1. `clave rotar`, para que los planes nuevos usen otra clave.
2. Restaurar o revisar las operaciones firmadas con la clave comprometida.
3. Borrar a mano su entrada en «Acceso a Llaveros» (servicio `mac-cleaner.hmac`, cuenta = id). A partir de ahí, esas operaciones solo se pueden recuperar sin clave.

Retirar claves desde la CLI queda pendiente.

### 3.5 Copia de seguridad

La clave vive en el Llavero de inicio de sesión. La API clásica no usa el Llavero de iCloud, así que la clave
**no se sincroniza**. Las copias de Time Machine incluyen el Llavero de inicio de sesión. Si se pierde, se aplica §3.3.

## 4. Reproducción indebida

| Ataque | Defensa | Prueba |
|---|---|---|
| Aplicar dos veces el mismo plan, o dos `apply` simultáneos | Reserva `O_EXCL` de `<cuarentena>/planes-aplicados/<id>` antes de mover nada | `test_un_plan_solo_se_aplica_una_vez_incluso_en_paralelo` |
| Borrar la reserva y repetir | Capa de F2.5: el rename cambió el ctime y `apply` omite los ficheros | `test_reproducir_un_plan_tras_restaurar_no_vuelve_a_mover` |
| Plan de otra zona | La zona está dentro del MAC | `test_plan_de_otra_zona` |
| Registro de otra operación | El id de la operación está en el MAC de cada registro | `test_registro_de_otra_operacion_no_se_acepta` |
| Manifiesto copiado a otra operación | El inicio debe coincidir con la zona y la operación de su directorio | `test_manifiesto_copiado_a_otra_operacion` |
| Plan caducado o con la caducidad alargada | Comprobación de caducidad (≤ 24 h) y MAC | `test_plan_alterado_con_huella_recalculada_se_rechaza` |

## 5. Lista blanca inicial (npm y pip)

Definida en el código (`listablanca.LISTA_BLANCA`), no en el TOML, para que la configuración no pueda ampliarla.

| Regla | Autorizable | Excluido |
|---|---|---|
| npm | `<caché npm>/_cacache` | `_npx` (paquetes ejecutables, p. ej. herramientas MCP; además protegido), `_logs`, `_prebuilds`, `_tuf`, `_update-notifier-*` |
| pip | `<pip cache dir>/http-v2`, `<pip cache dir>/http` | `wheels` (recompilar puede requerir herramientas de compilación), `selfcheck` |

**Comprobaciones adicionales:**

- **Raíz de la caché**: dentro del HOME y fuera de `/opt/homebrew`, `/usr/local`, `/usr`, `/Library`, `/System` y `/Applications`. Su ruta no puede contener componentes de instalación o entorno (`node_modules`, `site-packages`, `dist-packages`, `.venv`/`venv`, `conda-meta`, `Cellar`, `lib`, `bin`…), ni puede haber marcadores de proyecto o entorno (`package.json`, `pyproject.toml`, `pyvenv.cfg`, `.git`, `conda-meta`) en ella o en sus antepasados hasta el HOME.
- **Cada fichero**: dentro de un subárbol permitido y sin componentes de instalación. Un `node_modules` dentro de `_cacache` se rechaza.
- **Protecciones de F1**: siguen delante de todo. Los perfiles y datos de Claude, Codex, Gemini, Argos, REA y AEON, los proyectos, los entornos, las credenciales, la música, los renders y los modelos no llegan a ser candidatos.
- **Sin órdenes oficiales**: no se usa ninguna orden oficial que borre (`npm cache clean`, `npm cache verify`, `pip cache purge`). La operación prevista es mover a cuarentena, que es reversible.

Hoy la lista blanca **solo clasifica**: `apply` no puede operar sobre datos reales. Conectarla a `apply` es parte del procedimiento de §8.

## 6. Modo sombra

```bash
./mac-cleaner sombra                       # escanea ahora (solo lectura) y evalúa
./mac-cleaner sombra --entrada informes/scan-AAAAMMDD-HHMMSS.json
```

- **Funcionamiento**: vuelve a recorrer los grupos candidatos con las protecciones de F1, como `plan`, pero sin firmar y sin SHA-256, y clasifica cada fichero con la lista blanca. La guardia de solo lectura está activa: solo se escribe en la carpeta de resultados (`informes/`, no versionada).
- **Contenido del informe** (`sombra-*.json` y `.md`):
  - candidatos por regla y grupo, con muestra de rutas;
  - exclusiones y motivos, del escaneo y de la revalidación;
  - espacio potencialmente recuperable (físico, sin garantías);
  - riesgos;
  - cambios respecto a la ejecución en sombra anterior (grupos nuevos, desaparecidos o cambiados, y cambio de configuración);
  - operaciones que requerirían autorización y qué falta para cada una.
- **Lo que nunca hace**: generar un plan aplicable, mover, borrar ni programarse. F3 no añade ninguna tarea programada.
- **Verificación**:
  - En zona sintética, `test_sombra_no_modifica_nada_y_detecta_cambios` y `test_cli_sombra_con_guardia_sin_tocar_nada` comprueban el SHA-256, mtime, ctime e inodo de todos los ficheros antes y después.
  - Sobre el Mac real, se ejecutó una vez en solo lectura, con resultados en una carpeta temporal fuera del repositorio. La guardia no bloqueó nada y no cambió ningún fichero de la configuración ni de las cachés.

## 7. Garantías reales y riesgos pendientes

**Garantías, con prueba:**

- **Planes**: un plan modificado sin la clave se rechaza, aunque se recalcule la huella. Lo mismo un plan v1, uno de otra zona, uno firmado con otra clave o uno cuya clave no esté disponible.
- **Manifiestos**: uno alterado sin la clave se rechaza en `restore` y en `purge`.
- **Clave sintética**: no autoriza datos reales.
- **Reproducción**: un plan no se aplica dos veces.
- **Recuperación**: sin clave se puede restaurar, pero nunca purgar.
- **Integración**: las 67 pruebas de F1, F2 y F2.5 pasan con la autenticación activa. 6 tuvieron que adaptarse; están detalladas en §9.

**Riesgos y limitaciones:**

- **Acceso a la clave**: la entrada del Llavero la crea el intérprete de Python que ejecuta mac-cleaner. Cualquier script que corra con **ese mismo intérprete** y tu usuario puede leerla sin aviso; otras aplicaciones verían el diálogo del Llavero. HMAC protege frente a la manipulación de ficheros, no frente a código malicioso ejecutado como tú.
- **API clásica**: el acceso al Llavero usa la API clásica (`SecKeychain*`), obsoleta pero presente en macOS 26. Si desaparece, habrá que migrar a `SecItem*`.
- **Final del manifiesto**: un final truncado sigue sin detectarse con la cadena ni con los MAC. Por eso existe el registro `cierre`, y `purge` no toca operaciones sin él.
- **Recuperación sin clave**: confía en la cadena, que no tiene clave. Un atacante que recalcule la cadena **y** mueva los ficheros dentro de la cuarentena para que origen y destino sigan siendo coherentes podría redirigir una restauración dentro de la zona. Nunca sobrescribe.
- **Lista blanca**: aún no está conectada a `apply` (§5).
- **Sombra**: usa una instantánea de lsof y muestras de rutas, no la lista completa de ficheros.
- **Heredados de F2.5**: los riesgos de `docs/SEGURIDAD-F2.md` §6 y §8.3 siguen vigentes, salvo la falta de autenticación, que F3 resuelve.

## 8. Procedimiento de autorización futura (F4) y criterios para la primera limpieza supervisada

Ningún paso está hecho. Cada uno requiere una decisión expresa del usuario.

1. **Clave**: el usuario ejecuta `mac-cleaner clave crear` y comprueba `clave estado`.
2. **Sombra durante 7 días**: `mac-cleaner sombra` una vez al día, ejecutada **a mano**, sin programarla. Se revisa en cada informe:
   - que solo `npm:_cacache`, `pip:http-v2` y `pip:http` aparecen en la lista blanca;
   - que ninguna exclusión inesperada desaparece y ningún grupo protegido aparece;
   - que los cambios entre días tienen explicación.
3. **Autorización escrita**: indicará reglas (npm, pip o ambas), tope de bytes y de ficheros, ruta de la cuarentena real (`~/.mac-cleaner/cuarentena`, ya protegida en `guards.py` y en el mismo volumen) y retención (14 días).
4. **Cambio de código revisado (F4)**:
   - sustituir la constante por un modo real limitado a la lista blanca;
   - exigir en `apply` una clave no sintética y `listablanca.clasificar` por elemento;
   - mantener la puerta de zona para todo lo demás;
   - añadir pruebas de que cualquier ruta fuera de la lista blanca se rechaza.
5. **Primera limpieza supervisada**, solo si se cumplen todos estos criterios:
   - 7 días de sombra sin sorpresas;
   - pruebas al 100 %;
   - `clave estado` correcto;
   - lsof disponible;
   - npm y pip sin procesos en marcha;
   - espacio en el mismo volumen;
   - el usuario presente.

   El procedimiento: `apply` de **una sola regla** (pip, la más pequeña), luego `restore` completo inmediato como simulacro y verificación de que todo vuelve idéntico, y entonces `apply` definitivo.
6. **Purga real**: requiere una segunda autorización, después de 14 días.
7. **Programación (launchd)**: solo para `scan` y `sombra`, y nunca `apply` desatendido sin otra decisión expresa.

## 9. Pruebas

`tests/test_f3.py`, 25 pruebas:

- planes alterados, MAC ausente o manipulado, clave incorrecta o ausente, planes v1, clave sintética sobre datos reales y plan de otra zona;
- reproducción en serie y en paralelo, registros de otra operación y manifiesto copiado;
- manifiestos alterados sin clave, manifiesto F2 sin autenticación y recuperación sin clave;
- pérdida y rotación de clave e interrupción durante `apply` firmado;
- sustitución tras firmar y fichero grande (70 MB disperso) con intento de «legalizar» un ctime;
- almacén del Llavero simulado y CLI `clave estado`;
- lista blanca: subárboles, `node_modules` en la caché, `_npx`, raíces en entornos o proyectos y rutas protegidas;
- sombra: sin modificar nada, con cambios entre ejecuciones, y por la CLI con la guardia activa.

**Adaptaciones de pruebas anteriores**, por ser F3 incompatible con planes sin firmar:

- `ZonaBase` usa una clave sintética en memoria.
- `retocar` vuelve a firmar el plan, simulando a un atacante **con** la clave para seguir probando las capas internas.
- Las pruebas de CLI pasan la clave sintética por entorno.
- La prueba de reproducción espera ahora el rechazo de la reserva.
- La prueba de manifiesto forjado recalcula también los MAC.
- Dos pruebas excluyen el directorio `planes-aplicados` al buscar la operación.
