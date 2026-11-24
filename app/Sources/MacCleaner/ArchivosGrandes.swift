import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// Archivos grandes de la carpeta de inicio. Nunca se selecciona nada automáticamente: cada archivo lo marca el
/// usuario y solo va a la Papelera de macOS (se recupera con «Devolver» en el Finder).
struct ArchivoGrande: Identifiable, Hashable {
    var id: URL { url }
    let url: URL
    let tamano: Int64
    let modificado: Date?
    let ultimoUso: Date?
    let tipo: TipoArchivo
    var enGit = false
    var produccion = false

    var nombre: String { url.lastPathComponent }
    var carpeta: String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let p = url.deletingLastPathComponent().path
        return p.hasPrefix(home) ? "~" + p.dropFirst(home.count) : p
    }
}

enum TipoArchivo: String, CaseIterable, Identifiable {
    case video = "Vídeo", audio = "Audio", imagen = "Imágenes", disco = "Discos y comprimidos", otros = "Otros"
    var id: String { rawValue }

    var simbolo: String {
        switch self {
        case .video: return "film"
        case .audio: return "waveform"
        case .imagen: return "photo"
        case .disco: return "archivebox"
        case .otros: return "doc"
        }
    }

    static func de(_ url: URL) -> TipoArchivo {
        guard let t = UTType(filenameExtension: url.pathExtension.lowercased()) else { return .otros }
        if t.conforms(to: .movie) || t.conforms(to: .video) { return .video }
        if t.conforms(to: .audio) { return .audio }
        if t.conforms(to: .image) { return .imagen }
        if t.conforms(to: .diskImage) || t.conforms(to: .archive) { return .disco }
        return .otros
    }
}

enum ProteccionGrandes {
    /// Mismos nombres protegidos que el motor (maccleaner/guards.py, PROTECCION_FIJA_NOMBRES).
    static let nombres = try! NSRegularExpression(
        pattern: "(claude|anthropic)|argos|^rea($|[-_. ])|codex|(gemini|antigravity)|aeon|^\\.?venv$|(keychain|\\.ssh$|gnupg)|^\\.mac-cleaner",
        options: [.caseInsensitive])
    /// Carpetas que no aportan archivos «del usuario» y cuestan mucho de recorrer.
    static let saltar: Set<String> = ["node_modules", ".git", ".Trash", ".hg", ".svn", "__pycache__", "site-packages"]
    /// Producción musical y de vídeo, modelos: se muestran, pero con aviso.
    static let extensionesProduccion: Set<String> = [
        "als", "alp", "logicx", "band", "ptx", "ptf", "flp", "cpr", "rpp", "aup3", "sesx", "wav", "aif", "aiff", "flac",
        "mid", "midi", "mov", "mxf", "braw", "r3d", "prproj", "fcpbundle", "drp", "aep",
        "gguf", "safetensors", "ckpt", "pt", "pth", "onnx", "mlmodel",
    ]

    static func protegido(_ nombre: String) -> Bool {
        nombres.firstMatch(in: nombre, range: NSRange(nombre.startIndex..., in: nombre)) != nil
    }
}

@MainActor
final class ArchivosGrandesModelo: ObservableObject {
    @Published var archivos: [ArchivoGrande] = []
    @Published var seleccion: Set<URL> = []
    @Published var escaneando = false
    @Published var recorridos = 0
    @Published var carpetaActual = ""
    @Published var mensaje: String?
    @Published var umbralMB: Int = 100
    @Published var incluirOcultos = false
    @Published var filtroTipo: TipoArchivo?
    @Published var filtroAntiguedad: Int = 0   // días sin usar (0 = cualquiera)
    @Published var hecho = false
    private var tarea: Task<Void, Never>?

    var visibles: [ArchivoGrande] {
        let limite = filtroAntiguedad > 0 ? Date().addingTimeInterval(-Double(filtroAntiguedad) * 86400) : nil
        return archivos.filter { a in
            (filtroTipo == nil || a.tipo == filtroTipo) &&
                (limite == nil || (a.ultimoUso ?? .distantPast) < limite!)
        }
    }

    var bytesSeleccion: Int64 { archivos.filter { seleccion.contains($0.url) }.reduce(0) { $0 + $1.tamano } }

    func escanear() {
        tarea?.cancel()
        archivos = []
        seleccion = []
        recorridos = 0
        mensaje = nil
        hecho = false
        escaneando = true
        let umbral = Int64(umbralMB) * 1_000_000
        let ocultos = incluirOcultos
        tarea = Task(priority: .utility) { [weak self] in
            let informar: @MainActor (Int, String) -> Void = { n, carpeta in
                self?.recorridos = n
                self?.carpetaActual = carpeta
            }
            // recorrer es nonisolated: se ejecuta fuera del hilo principal y respeta la cancelación de esta tarea.
            let encontrados = await Self.recorrer(umbral: umbral, ocultos: ocultos, progreso: informar)
            guard let self, !Task.isCancelled else { return }
            self.archivos = encontrados.sorted { $0.tamano > $1.tamano }
            self.escaneando = false
            self.hecho = true
        }
    }

    func cancelar() {
        tarea?.cancel()
        escaneando = false
    }

    nonisolated static func recorrer(umbral: Int64, ocultos: Bool,
                                     progreso: @escaping @MainActor (Int, String) -> Void) async -> [ArchivoGrande] {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.standardizedFileURL
        let claves: [URLResourceKey] = [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey, .isPackageKey, .isHiddenKey,
                                        .totalFileAllocatedSizeKey, .fileAllocatedSizeKey, .fileSizeKey,
                                        .contentModificationDateKey, .contentAccessDateKey]
        guard let e = fm.enumerator(at: home, includingPropertiesForKeys: claves,
                                    options: [.skipsPackageDescendants], errorHandler: { _, _ in true }) else { return [] }
        var res: [ArchivoGrande] = []
        var n = 0
        let library = home.appendingPathComponent("Library").path
        while let obj = e.nextObject() {
            guard let url = obj as? URL else { continue }
            if Task.isCancelled { break }
            n += 1
            let nombre = url.lastPathComponent
            guard let v = try? url.resourceValues(forKeys: Set(claves)) else { continue }
            if v.isDirectory == true {
                if url.path == library || ProteccionGrandes.saltar.contains(nombre) || ProteccionGrandes.protegido(nombre) ||
                    (!ocultos && nombre.hasPrefix(".")) || v.isPackage == true {
                    e.skipDescendants()
                }
                if n % 1500 == 0 { await progreso(n, url.path) }
                continue
            }
            guard v.isRegularFile == true, v.isSymbolicLink != true, v.isPackage != true else { continue }
            if !ocultos && nombre.hasPrefix(".") { continue }
            let tam = Int64(v.totalFileAllocatedSize ?? v.fileAllocatedSize ?? v.fileSize ?? 0)
            guard tam >= umbral, !ProteccionGrandes.protegido(nombre) else { continue }
            let mod = v.contentModificationDate
            let uso = [mod, v.contentAccessDate].compactMap { $0 }.max()
            var a = ArchivoGrande(url: url, tamano: tam, modificado: mod, ultimoUso: uso, tipo: TipoArchivo.de(url))
            a.produccion = ProteccionGrandes.extensionesProduccion.contains(url.pathExtension.lowercased())
            res.append(a)
        }
        await progreso(n, "")
        // ¿Está dentro de un repositorio git? (pocas comprobaciones: solo para los encontrados)
        var cache: [String: Bool] = [:]
        func enGit(_ dir: URL) -> Bool {
            var d = dir.standardizedFileURL
            var visitados: [String] = []
            var r = false
            while d.path.hasPrefix(home.path) && d.path != home.path {
                if let c = cache[d.path] { r = c; break }
                visitados.append(d.path)
                if fm.fileExists(atPath: d.appendingPathComponent(".git").path) { r = true; break }
                d = d.deletingLastPathComponent()
            }
            for p in visitados { cache[p] = r }
            return r
        }
        for i in res.indices { res[i].enGit = enGit(res[i].url.deletingLastPathComponent()) }
        return res
    }

    /// Mueve a la Papelera lo seleccionado, comprobando de nuevo cada archivo justo antes.
    func moverSeleccionAPapelera() {
        let fm = FileManager.default
        var movidos = 0
        var liberable: Int64 = 0
        var fallos: [String] = []
        for a in archivos where seleccion.contains(a.url) {
            let v = try? a.url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard v?.isRegularFile == true, v?.isSymbolicLink != true, !ProteccionGrandes.protegido(a.nombre) else {
                fallos.append("\(a.nombre): ya no es un archivo normal")
                continue
            }
            do {
                try fm.trashItem(at: a.url, resultingItemURL: nil)
                movidos += 1
                liberable += a.tamano
            } catch {
                fallos.append("\(a.nombre): \(error.localizedDescription)")
            }
        }
        let quitados = seleccion
        archivos.removeAll { quitados.contains($0.url) && !fm.fileExists(atPath: $0.url.path) }
        seleccion = []
        var t = "\(movidos) archivo\(movidos == 1 ? "" : "s") en la Papelera (\(Formato.bytes(liberable))). " +
            "El espacio se libera al vaciarla; hasta entonces puedes recuperarlos con «Devolver» en el Finder."
        if !fallos.isEmpty { t += "\nNo se movieron: " + fallos.prefix(3).joined(separator: "; ") }
        mensaje = t
    }
}

struct ArchivosGrandesView: View {
    @StateObject private var m = ArchivosGrandesModelo()
    @State private var confirmar = false
    @State private var orden = [KeyPathComparator(\ArchivoGrande.tamano, order: .reverse)]

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Archivos grandes").font(.largeTitle.bold())
                        Text("Archivos grandes de tu carpeta de inicio (sin la Biblioteca ni los perfiles de Claude, Codex, Argos o AEON). Tú eliges qué va a la Papelera.")
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if m.escaneando {
                        Button("Detener") { m.cancelar() }.controlSize(.large)
                    } else {
                        Button {
                            m.escanear()
                        } label: {
                            Label("Buscar", systemImage: "magnifyingglass").padding(.horizontal, 8)
                        }
                        .controlSize(.large)
                        .buttonStyle(.borderedProminent)
                    }
                }
                HStack(spacing: 16) {
                    Picker("Mínimo", selection: $m.umbralMB) {
                        Text("50 MB").tag(50)
                        Text("100 MB").tag(100)
                        Text("250 MB").tag(250)
                        Text("500 MB").tag(500)
                        Text("1 GB").tag(1000)
                    }
                    .fixedSize()
                    .disabled(m.escaneando)
                    Toggle("Incluir carpetas ocultas", isOn: $m.incluirOcultos)
                        .fixedSize()
                        .disabled(m.escaneando)
                    Spacer()
                }
                HStack(spacing: 16) {
                    Text("Filtrar:").foregroundStyle(.secondary)
                    Picker("Tipo", selection: $m.filtroTipo) {
                        Text("Todos").tag(TipoArchivo?.none)
                        ForEach(TipoArchivo.allCases) { t in Text(t.rawValue).tag(TipoArchivo?.some(t)) }
                    }
                    .fixedSize()
                    Picker("Sin usar", selection: $m.filtroAntiguedad) {
                        Text("Cualquiera").tag(0)
                        Text("Más de 30 días").tag(30)
                        Text("Más de 90 días").tag(90)
                        Text("Más de 1 año").tag(365)
                    }
                    .fixedSize()
                    Spacer()
                }
                if m.escaneando {
                    HStack(spacing: 10) {
                        ProgressView().controlSize(.small)
                        Text("\(Formato.numero(m.recorridos)) elementos revisados").monospacedDigit()
                        Text(m.carpetaActual).lineLimit(1).truncationMode(.middle).foregroundStyle(.secondary)
                    }
                    .font(.callout)
                }
                if let t = m.mensaje {
                    Label(t, systemImage: "trash")
                        .font(.callout)
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.green.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
                }
            }
            .padding(24)

            if m.archivos.isEmpty && !m.escaneando {
                VStack(spacing: 10) {
                    Image(systemName: m.hecho ? "checkmark.circle" : "doc.viewfinder").font(.system(size: 40)).foregroundStyle(.tint)
                    Text(m.hecho ? "No hay archivos de más de \(m.umbralMB) MB" : "Pulsa «Buscar» para encontrar archivos grandes")
                        .foregroundStyle(.secondary)
                    if !m.hecho {
                        Text("La primera vez, macOS te pedirá permiso para acceder a Documentos, Escritorio y Descargas.")
                            .font(.caption).foregroundStyle(.tertiary)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                tabla
            }
            Divider()
            HStack {
                Text("\(m.visibles.count) archivos · \(Formato.bytes(m.visibles.reduce(0) { $0 + $1.tamano }))")
                    .foregroundStyle(.secondary)
                Spacer()
                if !m.seleccion.isEmpty {
                    Text("\(m.seleccion.count) seleccionados · \(Formato.bytes(m.bytesSeleccion))").monospacedDigit()
                    Button("Quitar selección") { m.seleccion = [] }
                }
                Button {
                    confirmar = true
                } label: {
                    Label("Mover a la Papelera", systemImage: "trash")
                }
                .buttonStyle(.borderedProminent)
                .tint(.red)
                .disabled(m.seleccion.isEmpty || m.escaneando)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
            .background(.bar)
        }
        .confirmationDialog("¿Mover \(m.seleccion.count) archivo\(m.seleccion.count == 1 ? "" : "s") a la Papelera?",
                            isPresented: $confirmar) {
            Button("Mover a la Papelera (\(Formato.bytes(m.bytesSeleccion)))", role: .destructive) { m.moverSeleccionAPapelera() }
            Button("Cancelar", role: .cancel) {}
        } message: {
            let avisos = m.archivos.filter { m.seleccion.contains($0.url) && ($0.enGit || $0.produccion) }.count
            Text(avisos > 0
                 ? "\(avisos) de ellos están en un proyecto git o son de producción musical, vídeo o modelos. Podrás recuperarlos desde la Papelera mientras no la vacíes."
                 : "Podrás recuperarlos desde la Papelera mientras no la vacíes.")
        }
    }

    private var tabla: some View {
        Table(of: ArchivoGrande.self, selection: $m.seleccion, sortOrder: $orden) {
            TableColumn("Nombre", value: \.nombre) { a in
                HStack(spacing: 8) {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: a.url.path)).resizable().frame(width: 20, height: 20)
                    VStack(alignment: .leading, spacing: 1) {
                        HStack(spacing: 4) {
                            Text(a.nombre).lineLimit(1).truncationMode(.middle)
                            if a.enGit { Etiqueta(texto: "git", color: .orange).help("Está dentro de un repositorio git") }
                            if a.produccion { Etiqueta(texto: "producción", color: .purple).help("Producción musical o de vídeo, o modelo de IA") }
                        }
                        Text(a.carpeta).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.head)
                    }
                }
            }
            .width(min: 280, ideal: 420)
            TableColumn("Tamaño", value: \.tamano) { a in
                Text(Formato.bytes(a.tamano)).monospacedDigit()
            }
            .width(90)
            TableColumn("Tipo", value: \.tipo.rawValue) { a in
                Label(a.tipo.rawValue, systemImage: a.tipo.simbolo).lineLimit(1)
            }
            .width(min: 90, ideal: 120)
            TableColumn("Último uso") { a in
                Text(a.ultimoUso.map { Formato.fecha.string(from: $0) } ?? "—").foregroundStyle(.secondary)
            }
            .width(110)
        } rows: {
            ForEach(m.visibles.sorted(using: orden)) { a in
                TableRow(a).contextMenu {
                    Button("Mostrar en el Finder") { NSWorkspace.shared.activateFileViewerSelecting([a.url]) }
                    Button("Abrir") { NSWorkspace.shared.open(a.url) }
                }
            }
        }
    }
}
