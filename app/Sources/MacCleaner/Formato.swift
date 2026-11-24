import Foundation
import SwiftUI

enum Formato {
    static func bytes(_ n: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: n, countStyle: .file)
    }

    static func bytes(_ n: UInt64) -> String { bytes(Int64(clamping: n)) }

    /// RAM en unidades binarias, como el Monitor de Actividad (16 GB y no 17,18 GB).
    static func memoria(_ n: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: n), countStyle: .memory)
    }

    static let fechaHora: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    static let fecha: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .none
        return f
    }()

    static func relativa(_ d: Date) -> String {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f.localizedString(for: d, relativeTo: Date())
    }

    static func numero(_ n: Int) -> String {
        NumberFormatter.localizedString(from: NSNumber(value: n), number: .decimal)
    }
}

/// Barra de proporción simple (disco, memoria).
struct BarraSegmentos: View {
    struct Segmento: Identifiable {
        let id = UUID()
        let valor: Double
        let color: Color
    }

    let segmentos: [Segmento]
    let total: Double
    var alto: CGFloat = 12

    var body: some View {
        GeometryReader { g in
            HStack(spacing: 1) {
                ForEach(segmentos) { s in
                    Rectangle()
                        .fill(s.color)
                        .frame(width: max(0, g.size.width * CGFloat(total > 0 ? s.valor / total : 0)))
                }
                Spacer(minLength: 0)
            }
            .background(Color.secondary.opacity(0.15))
            .clipShape(RoundedRectangle(cornerRadius: alto / 2))
        }
        .frame(height: alto)
    }
}

struct Leyenda: View {
    let color: Color
    let titulo: String
    let valor: String

    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(titulo).foregroundStyle(.secondary)
            Text(valor).monospacedDigit()
        }
        .font(.callout)
    }
}

struct Etiqueta: View {
    let texto: String
    var color: Color = .secondary

    var body: some View {
        Text(texto)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }
}
