#!/bin/bash
# Compila la app con las Command Line Tools (sin Xcode) y monta «Mac Cleaner.app» en app/dist/.
#   ./empaquetar.sh              compila y empaqueta
#   ./empaquetar.sh --instalar   además la copia en ~/Applications
# El motor Python va dentro de la app (Contents/Resources/motor): solo código y config, nunca informes ni docs.
set -euo pipefail
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAIZ="$(dirname "$APP_DIR")"
NOMBRE="Mac Cleaner"
DIST="$APP_DIR/dist"
OUT="$DIST/$NOMBRE.app"
MOTOR="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$RAIZ/maccleaner/__init__.py")"
APP_VERSION="0.5.0"   # F5A

swift build -c release --package-path "$APP_DIR"
BIN="$(swift build -c release --package-path "$APP_DIR" --show-bin-path)/MacCleaner"

rm -rf "$OUT"
mkdir -p "$OUT/Contents/MacOS" "$OUT/Contents/Resources/motor"
cp "$BIN" "$OUT/Contents/MacOS/$NOMBRE"
cp "$RAIZ/mac-cleaner" "$OUT/Contents/Resources/motor/"
rsync -a --exclude '__pycache__' --exclude '*.pyc' "$RAIZ/maccleaner" "$OUT/Contents/Resources/motor/"
rsync -a "$RAIZ/config" "$OUT/Contents/Resources/motor/"

# Icono
ICNS="$DIST/AppIcon.icns"
if [ ! -f "$ICNS" ] || [ "$APP_DIR/recursos/generar_icono.swift" -nt "$ICNS" ]; then
  TMP="$(mktemp -d)"
  swift "$APP_DIR/recursos/generar_icono.swift" "$TMP/1024.png"
  mkdir -p "$TMP/AppIcon.iconset"
  for s in 16 32 128 256 512; do
    sips -z $s $s "$TMP/1024.png" --out "$TMP/AppIcon.iconset/icon_${s}x${s}.png" >/dev/null
    sips -z $((s * 2)) $((s * 2)) "$TMP/1024.png" --out "$TMP/AppIcon.iconset/icon_${s}x${s}@2x.png" >/dev/null
  done
  iconutil -c icns "$TMP/AppIcon.iconset" -o "$ICNS"
  rm -rf "$TMP"
fi
cp "$ICNS" "$OUT/Contents/Resources/AppIcon.icns"

cat > "$OUT/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>$NOMBRE</string>
  <key>CFBundleDisplayName</key><string>$NOMBRE</string>
  <key>CFBundleExecutable</key><string>$NOMBRE</string>
  <key>CFBundleIdentifier</key><string>local.maccleaner.app</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$APP_VERSION</string>
  <key>CFBundleVersion</key><string>$APP_VERSION-motor$MOTOR</string>
  <key>CFBundleDevelopmentRegion</key><string>es</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSDocumentsFolderUsageDescription</key><string>Para buscar archivos grandes en Documentos.</string>
  <key>NSDesktopFolderUsageDescription</key><string>Para buscar archivos grandes en el Escritorio.</string>
  <key>NSDownloadsFolderUsageDescription</key><string>Para buscar archivos grandes en Descargas.</string>
</dict>
</plist>
PLIST

# Firma local (ad hoc): basta para este Mac. macOS puede volver a pedir permisos de carpetas tras cada recompilación.
codesign --force --deep --sign - "$OUT"
codesign --verify --deep --strict "$OUT"
echo "App: $OUT (versión $APP_VERSION, motor $MOTOR)"

if [ "${1:-}" = "--instalar" ]; then
  mkdir -p "$HOME/Applications"
  rm -rf "$HOME/Applications/$NOMBRE.app"
  ditto "$OUT" "$HOME/Applications/$NOMBRE.app"
  echo "Instalada en ~/Applications/$NOMBRE.app"
fi
