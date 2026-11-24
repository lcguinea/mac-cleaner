// Genera el icono de la app (PNG de 1024 px). Uso: swift generar_icono.swift salida.png
import AppKit

let lado: CGFloat = 1024
let salida = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "icono.png"
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(lado), pixelsHigh: Int(lado), bitsPerSample: 8,
                           samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                           bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

// Fondo: cuadrado redondeado con la rejilla de iconos de macOS (824 px de 1024) y degradado.
let marco = NSRect(x: 100, y: 100, width: 824, height: 824)
let forma = NSBezierPath(roundedRect: marco, xRadius: 185, yRadius: 185)
let sombra = NSShadow()
sombra.shadowColor = NSColor.black.withAlphaComponent(0.25)
sombra.shadowOffset = NSSize(width: 0, height: -12)
sombra.shadowBlurRadius = 24
NSGraphicsContext.saveGraphicsState()
sombra.set()
NSColor(calibratedRed: 0.05, green: 0.42, blue: 0.62, alpha: 1).setFill()
forma.fill()
NSGraphicsContext.restoreGraphicsState()
NSGradient(colors: [NSColor(calibratedRed: 0.10, green: 0.78, blue: 0.72, alpha: 1),
                    NSColor(calibratedRed: 0.09, green: 0.45, blue: 0.85, alpha: 1)])!.draw(in: forma, angle: -60)

// Símbolo: destellos en blanco.
let conf = NSImage.SymbolConfiguration(pointSize: 470, weight: .semibold)
    .applying(NSImage.SymbolConfiguration(paletteColors: [.white]))
if let s = NSImage(systemSymbolName: "sparkles", accessibilityDescription: nil)?.withSymbolConfiguration(conf) {
    let t = s.size
    s.draw(in: NSRect(x: (lado - t.width) / 2, y: (lado - t.height) / 2, width: t.width, height: t.height))
}
NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: salida))
