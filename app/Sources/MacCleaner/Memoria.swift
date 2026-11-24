import AppKit
import Darwin
import SwiftUI

struct EstadoMemoria {
    var total: UInt64 = 0
    var apps: UInt64 = 0          // memoria de apps (anónima, sin la purgable)
    var fija: UInt64 = 0          // wired
    var comprimida: UInt64 = 0
    var cache: UInt64 = 0         // archivos en caché (reutilizable)
    var libre: UInt64 = 0
    var swapUsado: UInt64 = 0
    var swapTotal: UInt64 = 0
    var presion: Int32 = 1        // 1 normal, 2 aviso, 4 crítica

    var usada: UInt64 { apps + fija + comprimida }

    static func leer() -> EstadoMemoria {
        var e = EstadoMemoria()
        e.total = ProcessInfo.processInfo.physicalMemory
        var st = vm_statistics64()
        var n = mach_msg_type_number_t(MemoryLayout<vm_statistics64_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &st) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(n)) { host_statistics64(mach_host_self(), HOST_VM_INFO64, $0, &n) }
        }
        if kr == KERN_SUCCESS {
            let pag = UInt64(getpagesize())
            let interna = UInt64(st.internal_page_count), purgable = UInt64(st.purgeable_count)
            e.apps = (interna > purgable ? interna - purgable : 0) * pag
            e.fija = UInt64(st.wire_count) * pag
            e.comprimida = UInt64(st.compressor_page_count) * pag
            e.cache = (UInt64(st.external_page_count) + purgable) * pag
            let libres = UInt64(st.free_count), especulativas = UInt64(st.speculative_count)
            e.libre = (libres > especulativas ? libres - especulativas : libres) * pag
        }
        var sw = xsw_usage()
        var tam = MemoryLayout<xsw_usage>.size
        if sysctlbyname("vm.swapusage", &sw, &tam, nil, 0) == 0 {
            e.swapUsado = sw.xsu_used
            e.swapTotal = sw.xsu_total
        }
        var p: Int32 = 1
        var tp = MemoryLayout<Int32>.size
        if sysctlbyname("kern.memorystatus_vm_pressure_level", &p, &tp, nil, 0) == 0 { e.presion = p }
        return e
    }
}

struct AppEnMemoria: Identifiable {
    var id: pid_t { pid }
    let pid: pid_t
    let nombre: String
    let bundleID: String?
    let icono: NSImage?
    var huella: UInt64
    var procesos: Int
    let app: NSRunningApplication

    /// Apps que no se ofrecen para cerrar: terminales (sesiones de Claude, tmux, Argos), Claude, el Finder y esta app.
    var protegida: Bool {
        let ids: Set<String> = ["com.mitchellh.ghostty", "com.apple.Terminal", "com.googlecode.iterm2", "dev.warp.Warp-Stable",
                                "com.apple.finder", "com.anthropic.claudefordesktop", "com.apple.loginwindow"]
        if let b = bundleID, ids.contains(b) || b == Bundle.main.bundleIdentifier { return true }
        let n = nombre.lowercased()
        return n.contains("claude") || n.contains("argos") || n.contains("aeon") || n.contains("codex")
    }
}

enum LectorProcesos {
    static func huella(_ pid: pid_t) -> UInt64? {
        var info = rusage_info_v4()
        let r = withUnsafeMutablePointer(to: &info) { p in
            p.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(pid, RUSAGE_INFO_V4, $0) }
        }
        return r == 0 ? info.ri_phys_footprint : nil
    }

    static func ruta(_ pid: pid_t) -> String? {
        var buf = [CChar](repeating: 0, count: 4096)
        let n = proc_pidpath(pid, &buf, UInt32(buf.count))
        return n > 0 ? String(cString: buf) : nil
    }

    /// Apps abiertas con la memoria de todos sus procesos (ayudantes incluidos), de mayor a menor.
    static func apps() -> [AppEnMemoria] {
        let abiertas = NSWorkspace.shared.runningApplications.filter { $0.activationPolicy == .regular && $0.bundleURL != nil }
        var porRuta: [String: AppEnMemoria] = [:]
        for a in abiertas {
            guard let b = a.bundleURL?.path else { continue }
            porRuta[b + "/"] = AppEnMemoria(pid: a.processIdentifier, nombre: a.localizedName ?? (b as NSString).lastPathComponent,
                                            bundleID: a.bundleIdentifier, icono: a.icon, huella: 0, procesos: 0, app: a)
        }
        let n = proc_listallpids(nil, 0)
        guard n > 0 else { return Array(porRuta.values) }
        var pids = [pid_t](repeating: 0, count: Int(n) + 128)
        let m = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
        let prefijos = porRuta.keys.sorted { $0.count > $1.count }
        for pid in pids.prefix(Int(max(0, m))) where pid > 0 {
            guard let r = ruta(pid), let pref = prefijos.first(where: { r.hasPrefix($0) }), let h = huella(pid) else { continue }
            porRuta[pref]!.huella += h
            porRuta[pref]!.procesos += 1
        }
        return porRuta.values.sorted { $0.huella > $1.huella }
    }
}

@MainActor
final class MemoriaModelo: ObservableObject {
    @Published var estado = EstadoMemoria.leer()
    @Published var apps: [AppEnMemoria] = []
    @Published var liberando = false
    @Published var resultado: String?
    @Published var cerrando: Set<pid_t> = []
    @Published var resistentes: Set<pid_t> = []
    private var temporizador: Timer?
    private var ciclo = 0

    func empezar() {
        refrescar(apps: true)
        temporizador?.invalidate()
        temporizador = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.ciclo += 1
                self.refrescar(apps: self.ciclo % 3 == 0)
            }
        }
    }

    func parar() {
        temporizador?.invalidate()
        temporizador = nil
    }

    func refrescar(apps conApps: Bool) {
        estado = EstadoMemoria.leer()
        if conApps {
            Task.detached(priority: .utility) {
                let a = LectorProcesos.apps()
                await MainActor.run { self.apps = a }
            }
        }
    }

    func cerrar(_ a: AppEnMemoria) {
        guard !a.protegida else { return }
        cerrando.insert(a.pid)
        _ = a.app.terminate()
        DispatchQueue.main.asyncAfter(deadline: .now() + 6) { [weak self] in
            guard let self else { return }
            self.cerrando.remove(a.pid)
            if !a.app.isTerminated { self.resistentes.insert(a.pid) }
            self.refrescar(apps: true)
        }
    }

    func forzar(_ a: AppEnMemoria) {
        guard !a.protegida else { return }
        _ = a.app.forceTerminate()
        resistentes.remove(a.pid)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in self?.refrescar(apps: true) }
    }

    /// `purge` con contraseña de administrador (la pide macOS). Mide la memoria libre antes y después.
    func liberarRAM() {
        guard !liberando else { return }
        liberando = true
        resultado = nil
        let antes = EstadoMemoria.leer()
        DispatchQueue.global(qos: .userInitiated).async {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            p.arguments = ["-e", "do shell script \"/usr/sbin/purge\" with administrator privileges"]
            let err = Pipe()
            p.standardError = err
            p.standardOutput = FileHandle.nullDevice
            var codigo: Int32 = -1
            var mensaje = ""
            do {
                try p.run()
                p.waitUntilExit()
                codigo = p.terminationStatus
                mensaje = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            } catch {
                mensaje = error.localizedDescription
            }
            Thread.sleep(forTimeInterval: 1)
            let despues = EstadoMemoria.leer()
            DispatchQueue.main.async {
                self.liberando = false
                self.estado = despues
                if codigo == 0 {
                    let ganada = despues.libre > antes.libre ? despues.libre - antes.libre : 0
                    self.resultado = "Memoria libre: \(Formato.memoria(antes.libre)) → \(Formato.memoria(despues.libre))" +
                        (ganada > 0 ? " (+\(Formato.memoria(ganada))). macOS volverá a usarla como caché según la necesite." : ".")
                } else if mensaje.contains("-128") {
                    self.resultado = "Cancelado: no se ha liberado nada."
                } else {
                    self.resultado = "No se pudo liberar la memoria: \(mensaje.trimmingCharacters(in: .whitespacesAndNewlines))"
                }
            }
        }
    }
}

struct MemoriaView: View {
    @StateObject private var m = MemoriaModelo()
    @State private var confirmarForzar: AppEnMemoria?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Memoria").font(.largeTitle.bold())
                        Text("Uso de RAM en tiempo real y apps que más ocupan.").foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        m.liberarRAM()
                    } label: {
                        Label(m.liberando ? "Liberando…" : "Liberar RAM", systemImage: "memorychip").padding(.horizontal, 8)
                    }
                    .controlSize(.large)
                    .buttonStyle(.borderedProminent)
                    .disabled(m.liberando)
                    .help("Ejecuta `purge` (vacía la caché de archivos). macOS te pedirá la contraseña de administrador.")
                }
                if let r = m.resultado {
                    Label(r, systemImage: "info.circle")
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
                }
                tarjetaRAM
                listaApps
            }
            .padding(24)
            .frame(maxWidth: 900, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .onAppear { m.empezar() }
        .onDisappear { m.parar() }
        .confirmationDialog("¿Forzar la salida de \(confirmarForzar?.nombre ?? "")?", isPresented: Binding(
            get: { confirmarForzar != nil }, set: { if !$0 { confirmarForzar = nil } }
        )) {
            Button("Forzar salida", role: .destructive) { if let a = confirmarForzar { m.forzar(a) } }
            Button("Cancelar", role: .cancel) {}
        } message: {
            Text("La app no se ha cerrado por las buenas. Si la fuerzas, perderás lo que no esté guardado.")
        }
    }

    private var presion: (String, Color) {
        switch m.estado.presion {
        case 4: return ("Crítica", .red)
        case 2: return ("Alta", .orange)
        default: return ("Normal", .green)
        }
    }

    private var tarjetaRAM: some View {
        let e = m.estado
        return GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .firstTextBaseline) {
                    Text(Formato.memoria(e.usada)).font(.system(size: 34, weight: .bold)).monospacedDigit()
                    Text("usados de \(Formato.memoria(e.total))").foregroundStyle(.secondary)
                    Spacer()
                    Label("Presión \(presion.0.lowercased())", systemImage: "gauge.with.dots.needle.33percent")
                        .foregroundStyle(presion.1)
                        .font(.headline)
                }
                BarraSegmentos(segmentos: [
                    .init(valor: Double(e.apps), color: .blue),
                    .init(valor: Double(e.fija), color: .orange),
                    .init(valor: Double(e.comprimida), color: .purple),
                    .init(valor: Double(e.cache), color: .teal.opacity(0.5)),
                ], total: Double(e.total), alto: 16)
                HStack(spacing: 16) {
                    Leyenda(color: .blue, titulo: "Apps", valor: Formato.memoria(e.apps))
                    Leyenda(color: .orange, titulo: "Fija", valor: Formato.memoria(e.fija))
                    Leyenda(color: .purple, titulo: "Comprimida", valor: Formato.memoria(e.comprimida))
                    Leyenda(color: .teal.opacity(0.5), titulo: "Caché de archivos", valor: Formato.memoria(e.cache))
                    Leyenda(color: .secondary.opacity(0.3), titulo: "Libre", valor: Formato.memoria(e.libre))
                }
                if e.swapTotal > 0 {
                    Text("Intercambio (swap): \(Formato.memoria(e.swapUsado)) de \(Formato.memoria(e.swapTotal))")
                        .font(.callout).foregroundStyle(.secondary)
                }
                Text("La caché de archivos no es memoria perdida: macOS la cede al instante cuando una app la necesita. Lo que importa es la presión.")
                    .font(.caption).foregroundStyle(.tertiary)
            }
            .padding(6)
        } label: {
            Label("RAM", systemImage: "memorychip")
        }
    }

    private var listaApps: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Apps que más memoria usan").font(.title2.bold())
            ForEach(m.apps.prefix(15)) { a in
                HStack(spacing: 10) {
                    if let i = a.icono { Image(nsImage: i).resizable().frame(width: 26, height: 26) }
                    VStack(alignment: .leading, spacing: 1) {
                        Text(a.nombre)
                        if a.procesos > 1 {
                            Text("\(a.procesos) procesos").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    Text(Formato.memoria(a.huella)).monospacedDigit().frame(width: 90, alignment: .trailing)
                    Group {
                        if a.protegida {
                            Image(systemName: "lock").foregroundStyle(.tertiary)
                                .help("Protegida: cerrarla cortaría sesiones de terminal, Claude o el Finder.")
                        } else if m.resistentes.contains(a.pid) {
                            Button("Forzar…") { confirmarForzar = a }.tint(.red)
                        } else if m.cerrando.contains(a.pid) {
                            ProgressView().controlSize(.small)
                        } else {
                            Button("Salir") { m.cerrar(a) }
                                .help("Cierra la app como con ⌘Q: si tiene cambios sin guardar, te preguntará.")
                        }
                    }
                    .frame(width: 80)
                }
                .padding(.vertical, 6)
                .padding(.horizontal, 10)
                .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }
}
