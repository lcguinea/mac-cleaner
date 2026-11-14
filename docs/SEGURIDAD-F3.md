# mac-cleaner F3 · Autenticación, lista blanca y modo sombra

Estado (14-11-2026, revisado en la auditoría F3.5, §10): F3 prepara la limpieza real, pero **no la habilita**. `zona.LIMPIEZA_REAL_HABILITADA = False`
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
- **Control de acceso (F3.5)**: cada clave se crea con una lista de aplicaciones de confianza **vacía**. Toda lectura muestra el diálogo del sistema y exige tu confirmación, también para el Python que la creó. mac-cleaner guarda la clave en memoria tras la primera lectura, así que hay un diálogo por proceso y clave. Responde **«Permitir»**, nunca «Permitir siempre»: esa opción añadiría ese Python a la lista y cualquier script ejecutado con él volvería a leer la clave sin preguntar. El índice no es secreto y conserva la ACL por defecto.
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

### 3.3 Pérdida de la clave: recuperación con intervención manual (F3.5)

Por ejemplo, si se borra la entrada del Llavero, el Llavero se restablece o se deniega el acceso.

- **Planes pendientes**: dejan de ser aplicables. Hay que volver a ejecutar `scan` y `plan` con una clave nueva.
- **Operaciones en cuarentena**: sus manifiestos ya no se pueden autenticar. `purge` **no las toca nunca**.

Sin la clave, el manifiesto **no prueba nada**: su cadena SHA-256 no tiene clave y quien pueda escribir en la cuarentena puede recalcularla. Por eso no hay restauración automática:

1. **Inventario, de solo lectura**: `restore --zona ZONA --operacion OP --recuperacion-sin-clave` no mueve ni escribe nada en la cuarentena. Clasifica cada elemento:
   - **restaurable**: solo si todas las fuentes coinciden:
     - la ruta en la cuarentena es `archivos/<ruta relativa del origen>`;
     - el origen está en la zona, normalizado y fuera de la cuarentena;
     - el inodo, el tamaño, la mtime, el modo y el propietario son los del manifiesto;
     - el SHA-256 coincide o, si no lo hay, el ctime;
     - el destino está libre y su directorio padre no es un enlace.
   - **ambiguo**: cualquier discrepancia, con su motivo.

   Lista también los ficheros de la cuarentena que el manifiesto no menciona («huérfanos»). Guarda el inventario en `ZONA/informes/recuperacion-OP-….json`, con el SHA-256 actual de cada fichero y un **código** de 12 caracteres ligado a su contenido.
2. **Revisión humana**: compruebas cada origen restaurable. Que sea restaurable indica coherencia, no autenticidad.
3. **Confirmación**: `restore … --recuperacion-sin-clave --confirmar INVENTARIO --codigo CÓDIGO [--elemento ID]`.
   - **Se rechaza** si el código no corresponde al inventario, si el inventario tiene más de 1 h o si el manifiesto cambió desde que se generó.
   - **Solo mueve lo restaurable**, y antes vuelve a comprobarlo todo y exige que el SHA-256 y el inodo sean los del inventario. Lo que haya cambiado se omite.
   - **Nunca sobrescribe** (`RENAME_EXCL`), y lo ambiguo y lo huérfano se quedan en la cuarentena.
   - **No escribe en el manifiesto**: anota en `<op>/recuperacion.jsonl`. Si la clave reaparece, por ejemplo al restaurar una copia del Llavero, el manifiesto sigue siendo verificable y `restore` normal termina el resto.
4. **Lo ambiguo**: se revisa a mano en `ZONA/.mac-cleaner-cuarentena/<op>/archivos/`, que replica las rutas originales.

**Después**: `clave crear` (si no queda índice) o `clave rotar`.

### 3.4 Compromiso de la clave (sospecha de que otro proceso la leyó)

1. `clave rotar`, para que los planes nuevos usen otra clave.
2. Restaurar o revisar las operaciones firmadas con la clave comprometida.
3. Borrar a mano su entrada en «Acceso a Llaveros» (servicio `mac-cleaner.hmac`, cuenta = id). A partir de ahí, esas operaciones solo se pueden recuperar con el procedimiento manual de §3.3.

### 3.4 bis Llavero bloqueado o sesión cerrada

Con el Llavero bloqueado, o sin sesión gráfica (cierre de sesión, SSH o un trabajo de launchd sin sesión), la lectura falla. Hay tres códigos posibles:

- -25293: denegado o bloqueado;
- -25308: hace falta interacción y no la hay;
- -128: cancelado.

mac-cleaner lo traduce a `ClaveNoDisponible`, de modo que no se puede firmar un plan ni verificar uno, y no hay ninguna operación destructiva. Es coherente con la regla de no ejecutar `apply` desatendido.

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

- **Acceso a la clave (mitigado en F3.5)**: con confirmación obligatoria, ningún proceso la lee sin el diálogo. Pero el diálogo solo identifica al intérprete («python3.15»), no al script. Un script malicioso que lo provoque a la vez que tú usas mac-cleaner es indistinguible. Si se elige «Permitir siempre», se vuelve a la situación de F3. Además, la clave queda en la memoria del proceso: los `bytes` de Python no se pueden borrar de forma fiable.
- **API clásica**: el acceso al Llavero usa la API clásica (`SecKeychain*`), obsoleta pero presente en macOS 26. Si desaparece, habrá que migrar a `SecItem*`.
- **Final del manifiesto**: un final truncado sigue sin detectarse con la cadena ni con los MAC. Por eso existe el registro `cierre`, y `purge` no toca operaciones sin él.
- **Recuperación sin clave (rediseñada en F3.5)**: ya no hay restauración automática. Un atacante que escriba en la cuarentena puede seguir fabricando un elemento «restaurable» coherente, pero solo se moverá si tú lo confirmas tras revisar el inventario. Nunca sobrescribe y nunca sale de la zona.
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

`tests/test_f3.py`, 25 pruebas (F3.5 adaptó 4 a la recuperación en dos pasos y al Llavero simulado; `tests/test_f35.py` añade 19 más, ver §10):

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

## 10. Auditoría F3.5 (14-11-2026)

**Alcance**: `autenticacion.py` (Llavero y HMAC), `manifiesto.py`, `plan.py`, `restaurar.py` (recuperación) y
`purgar.py`.

**Método**: pruebas adversariales con claves sintéticas, almacenes simulados y zonas sintéticas
(`tests/test_f35.py`). Cada defecto se reprodujo sobre el commit de F3 `b31acbe` en un *worktree* temporal. Para el
Llavero se hicieron experimentos con un **Llavero temporal** en un directorio temporal: clave sintética, interacción
desactivada y sin entrar en la lista de búsqueda (comprobado antes y después). No se crearon, rotaron ni borraron
claves reales.

### 10.1 Evidencia del Llavero

| Experimento (Llavero temporal) | Resultado |
|---|---|
| Elemento con ACL por defecto (como F3), leído por el mismo Python sin interacción | `0`: **se lee sin confirmación** |
| ACL de ese elemento (`security dump-keychain -a`) | `decrypt`: solo `…/Cellar/python@3.15/3.15.2/…/Python.app`, ligado a esa versión concreta |
| Otro ejecutable (`/usr/bin/security find-generic-password -w`) | Se queda esperando la confirmación del usuario |
| Elemento con lista de confianza **vacía** (corrección F3.5), leído sin interacción | `-25293`: denegado. ACL `decrypt: applications (0)` |
| Llavero bloqueado, lectura sin interacción | `-25293`: denegado |
| Prueba opcional `test_llavero_temporal_real_exige_confirmacion` (código real de F3.5) | La clave no se lee sin confirmación; el índice no secreto sí |

**Incidencia durante la auditoría**: el experimento con `/usr/bin/security` se lanzó al principio sin desactivar la
interacción y mostró un diálogo del sistema que pedía la contraseña del Llavero temporal. Se canceló y el Llavero
temporal se borró; no afectó al Llavero de inicio de sesión. El resto de experimentos se hicieron solo desde Python
y con la interacción desactivada.

**Conclusiones sobre el Llavero:**

- **Quién puede leer la clave**:
  - Con la ACL por defecto de F3, el Python que la creó, y con él cualquier script ejecutado con ese mismo Python, la leía sin confirmación.
  - Con la de F3.5, nadie la lee sin el diálogo. «Permitir siempre» lo anularía.
- **Restringir a un ejecutable**: es posible (`SecTrustedApplicationCreateFromPath`), pero inútil con un intérprete, porque autorizaría a todos sus scripts.
- **Actualizaciones de Python**: la entrada de confianza apunta a la ruta de Cellar de una versión concreta. Tras `brew upgrade`, una ACL que la incluyera dejaría de coincidir y volvería a preguntar. Con la lista vacía no hay nada que se rompa: siempre pregunta.
- **Alternativas nativas más fuertes**: el Llavero de protección de datos con `kSecAttrAccessControl`, que pide presencia del usuario o Touch ID, exige una aplicación firmada con el *entitlement* `keychain-access-groups`. Un script con el Python de Homebrew no puede usarlo. Para F4 o después, un ayudante firmado mínimo que custodie la clave y firme o verifique.
- **Llavero bloqueado o sesión cerrada**: no se puede leer la clave y no hay operación (§3.4 bis).
- **Ciclo de vida**: creación y rotación con lista vacía y caché por proceso. Las claves antiguas se conservan para verificar. La retirada es manual (§3.4). La pérdida se gestiona con §3.3.

### 10.2 Hallazgos y correcciones

| # | Tipo | Gravedad | Hallazgo y evidencia | Corrección | Prueba |
|---|---|---|---|---|---|
| V1 | Vulnerabilidad | Alta | `--recuperacion-sin-clave` restauraba **automáticamente** según un manifiesto sin autenticar: tomaba una cadena SHA-256 sin clave como prueba de identidad. En F3, `restaurar(…, sin_clave=True)` movió ficheros sin ninguna revisión | Recuperación en dos pasos: inventario de solo lectura, luego confirmación con código, caducidad de 1 h y manifiesto sin cambios. Lo ambiguo se queda en la cuarentena | `test_sin_confirmacion_no_se_mueve_nada`, `test_rutas_manipuladas_quedan_en_cuarentena`, `test_conflicto_y_sustitucion_tras_el_inventario`, `test_inventario_caducado_alterado_o_de_otro_estado`, `test_cli_recuperacion_en_dos_pasos` |
| V2 | Robustez | Media | La recuperación añadía registros **sin MAC** al manifiesto. Si la clave reaparecía, el manifiesto ya no se autenticaba: en F3 dio «MAC no válido en la línea 11» y bloqueó el resto de la operación | La recuperación no escribe en el manifiesto (`recuperacion.jsonl` aparte); los manifiestos cargados sin verificar son de solo lectura | `test_recuperacion_no_contamina_el_manifiesto` |
| V3 | Robustez | Media | Una caída a mitad de escribir un registro dejaba una línea incompleta y el manifiesto entero se rechazaba, también en recuperación: la operación no se podía restaurar con la herramienta | La cola incompleta se ignora al cargar. No se escribe detrás de ella. `restore` la recorta bajo bloqueo y anota `cola_descartada` con su tamaño y SHA-256. `purge` no toca esas operaciones | `test_registro_final_incompleto_no_impide_restaurar`, `test_operacion_con_cola_incompleta_o_descartada_no_se_purga`, `test_no_se_escribe_detras_de_una_linea_incompleta` |
| V4 | Vulnerabilidad | Media-alta | Clave del Llavero legible sin confirmación por el Python que la creó y sus scripts (§10.1) | ACL con lista de confianza vacía, caché por proceso y errores del Llavero explicados | `test_claves_creadas_con_confirmacion_obligatoria_y_cache`, `test_errores_del_llavero_explicados`, `test_llavero_temporal_real_exige_confirmacion` (opcional) |

### 10.3 Verificado sin defecto (con prueba)

- **Canonicalización**:
  - JSON con claves ordenadas y separadores fijos, calculado sobre el objeto ya interpretado: las claves duplicadas o los espacios no cambian la semántica firmada.
  - Separación de dominios plan/manifiesto y contexto de operación.
  - Los identificadores de clave se validan antes de usarse.
- **Tipos y campos**: se validan después del MAC. Un MAC válido no exime de las comprobaciones (pruebas de F2.5 y F3).
- **Registros eliminados o reordenados**: se rechazan. Un MAC inválido impide `restore` y `purge` (`TestRegistrosAlterados`).
- **Truncar el final** con registros completos no se detecta, pero **no habilita nada destructivo**:
  - quitar el `cierre` bloquea la purga;
  - quitar los `restaurado` no permite borrar nada, porque lo restaurado ya no está en la cuarentena (`TestTruncamiento`).
- **Reproducción de planes**, de serie o en paralelo, y **acceso concurrente**: incluida la recuperación con la operación ocupada (`test_recuperacion_con_operacion_ocupada`).
- **Separación sintético/real**: un plan real firmado con una clave **no** sintética es criptográficamente válido, pero la puerta de zona lo rechaza. `restore`, `purge` y la recuperación rechazan el HOME, `/private/tmp` y directorios sin marcador (`TestOperacionesReales`).

### 10.4 Riesgos residuales

- **Diálogo del Llavero**: no distingue mac-cleaner de otro script con el mismo Python, y «Permitir siempre» anula la protección.
- **Clave en memoria**: queda en la memoria del proceso mientras se ejecuta.
- **Truncar el final del manifiesto**: sigue sin detectarse. Su efecto se limita a operaciones no destructivas (analizado arriba).
- **Recuperación sin clave**: depende de la revisión humana del inventario.
- **API clásica del Llavero**: obsoleta.

### 10.5 Condiciones para pasar a F4

1. Las pruebas pasan, incluida la opcional del Llavero temporal ejecutada a mano.
2. El usuario crea la clave (`clave crear`) y comprueba que el diálogo aparece en `plan` y `apply`.
3. Siete días de `sombra` a mano, sin sorpresas (§8).
4. Autorización escrita (reglas, topes, cuarentena y retención) y revisión del cambio de código de F4: lista blanca en `apply`, clave no sintética obligatoria y puerta de zona para todo lo demás.
5. Decisión sobre el ayudante firmado (§10.1) o aceptación expresa del riesgo residual del diálogo.
