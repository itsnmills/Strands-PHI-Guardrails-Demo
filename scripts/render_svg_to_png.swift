import AppKit
import Foundation

guard CommandLine.arguments.count == 3 else {
    fatalError("usage: render_svg_to_png.swift input.svg output.png")
}

let input = CommandLine.arguments[1]
let output = CommandLine.arguments[2]

guard let image = NSImage(contentsOfFile: input),
      let tiff = image.tiffRepresentation,
      let bitmap = NSBitmapImageRep(data: tiff),
      let png = bitmap.representation(using: .png, properties: [:]) else {
    fatalError("could not render SVG: \(input)")
}

try png.write(to: URL(fileURLWithPath: output))
