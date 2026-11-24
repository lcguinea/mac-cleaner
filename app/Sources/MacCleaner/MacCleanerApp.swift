import AppKit
import SwiftUI

extension Notification.Name {
    static let abrirLimpiezaParaCaptura = Notification.Name("abrirLimpiezaParaCaptura")
}

enum Seccion: String, CaseIterable, Identifiable {
    case escaneo = "Escaneo rápido"
    case grandes = "Archivos grandes"
    case memoria = "Memoria"
    case cuarentena = "Cuarentena"

    var id: String { rawValue }

    var simbolo: String {
        switch self {
        case .escaneo: return "sparkles"
        case .grandes: return "doc.viewfinder"
        case .memoria: return "memorychip"
        case .cuarentena: return "shippingbox"
        }
    }
}

final class Delegado: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Lanzada desde `swift run` (sin .app) también debe aparecer en el Dock y al frente.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main
struct MacCleanerApp: App {
    @NSApplicationDelegateAdaptor(Delegado.self) private var delegado

    var body: some Scene {
        WindowGroup("Mac Cleaner") {
            Raiz()
                .frame(minWidth: 960, minHeight: 640)
        }
        .windowToolbarStyle(.unified(showsTitle: false))
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }
}

struct Raiz: View {
    @State private var seccion: Seccion? = .escaneo

    var body: some View {
        NavigationSplitView {
            List(Seccion.allCases, selection: $seccion) { s in
                Label(s.rawValue, systemImage: s.simbolo).tag(s)
            }
            .navigationSplitViewColumnWidth(min: 190, ideal: 210)
            .safeAreaInset(edge: .bottom) {
                Text(Motor.lanzador == nil ? "Motor no encontrado" : "Motor mac-cleaner")
                    .font(.caption)
                    .foregroundStyle(Motor.lanzador == nil ? .red : .secondary)
                    .padding(12)
            }
        } detail: {
            detalle
        }
        .task { await capturarSiSePide() }
    }

    /// Solo desarrollo: con MAC_CLEANER_CAPTURA=<carpeta>, la app recorre las secciones, guarda una imagen de su
    /// propia ventana por sección (no necesita el permiso de grabación de pantalla) y se cierra.
    private func capturarSiSePide() async {
        guard let dir = ProcessInfo.processInfo.environment["MAC_CLEANER_CAPTURA"] else { return }
        try? await Task.sleep(for: .seconds(2))
        for s in Seccion.allCases {
            seccion = s
            try? await Task.sleep(for: .seconds(s == .memoria ? 5 : 3))
            guard let v = NSApp.windows.first(where: { $0.isVisible && $0.contentView != nil })?.contentView,
                  let rep = v.bitmapImageRepForCachingDisplay(in: v.bounds) else { continue }
            v.cacheDisplay(in: v.bounds, to: rep)
            let nombre = s.rawValue.folding(options: .diacriticInsensitive, locale: nil).replacingOccurrences(of: " ", with: "-")
            try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: dir).appendingPathComponent("\(nombre).png"))
        }
        // La hoja «Limpiar…» solo hasta la vista previa (solo lectura): nunca se pulsa «Mover a la cuarentena».
        seccion = .escaneo
        try? await Task.sleep(for: .seconds(2))
        NotificationCenter.default.post(name: .abrirLimpiezaParaCaptura, object: nil)
        try? await Task.sleep(for: .seconds(40))
        if let hoja = NSApp.windows.first(where: { $0.isVisible && $0.attachedSheet != nil })?.attachedSheet,
           let v = hoja.contentView, let rep = v.bitmapImageRepForCachingDisplay(in: v.bounds) {
            v.cacheDisplay(in: v.bounds, to: rep)
            try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: dir).appendingPathComponent("Limpiar.png"))
        }
        exit(0)   // con una hoja abierta, terminate() se queda esperando: en modo captura se sale directamente
    }

    @ViewBuilder private var detalle: some View {
        switch seccion ?? .escaneo {
        case .escaneo: EscaneoRapidoView()
        case .grandes: ArchivosGrandesView()
        case .memoria: MemoriaView()
        case .cuarentena: CuarentenaView()
        }
    }
}
