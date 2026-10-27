package oidc

import (
	"bytes"
	"encoding/binary"
	"image"
)

// jpegOrientation returns the EXIF Orientation (1–8) of a JPEG file. Phones
// store photos sideways and set this tag instead of rotating the pixels;
// since re-encoding drops EXIF, the rotation has to be applied first.
//
// Only what is needed is parsed: the APP segments before the image data,
// the TIFF header and IFD0. Every offset is bounds-checked, and anything
// missing, malformed or out of range yields 1 (as stored), never an error.
func jpegOrientation(data []byte) int {
	if len(data) < 2 || data[0] != 0xff || data[1] != 0xd8 {
		return 1
	}
	i := 2
	for {
		// Markers may be preceded by any number of 0xff fill bytes.
		for i+1 < len(data) && data[i] == 0xff && data[i+1] == 0xff {
			i++
		}
		if i+4 > len(data) || data[i] != 0xff {
			return 1
		}
		marker := data[i+1]
		if marker == 0xda || marker == 0xd9 { // start of scan, end of image
			return 1
		}
		if marker == 0x01 || (marker >= 0xd0 && marker <= 0xd7) { // no length
			i += 2
			continue
		}
		n := int(binary.BigEndian.Uint16(data[i+2:]))
		if n < 2 || i+2+n > len(data) {
			return 1
		}
		payload := data[i+4 : i+2+n]
		if marker == 0xe1 && bytes.HasPrefix(payload, []byte("Exif\x00\x00")) {
			return tiffOrientation(payload[6:])
		}
		i += 2 + n
	}
}

// tiffOrientation reads tag 0x0112 from IFD0 of a TIFF structure.
func tiffOrientation(t []byte) int {
	if len(t) < 8 {
		return 1
	}
	var order binary.ByteOrder
	switch string(t[:2]) {
	case "II":
		order = binary.LittleEndian
	case "MM":
		order = binary.BigEndian
	default:
		return 1
	}
	if order.Uint16(t[2:]) != 42 {
		return 1
	}
	// uint64 so that a huge offset cannot overflow the bounds checks.
	ifd := uint64(order.Uint32(t[4:]))
	if ifd+2 > uint64(len(t)) {
		return 1
	}
	count := uint64(order.Uint16(t[ifd:]))
	entries := ifd + 2
	if entries+count*12 > uint64(len(t)) {
		return 1
	}
	for k := range count {
		e := t[entries+k*12 : entries+k*12+12]
		if order.Uint16(e) != 0x0112 {
			continue
		}
		// type SHORT (3), count 1; the value sits in the first two bytes.
		if order.Uint16(e[2:]) != 3 || order.Uint32(e[4:]) != 1 {
			return 1
		}
		if v := int(order.Uint16(e[8:])); v >= 1 && v <= 8 {
			return v
		}
		return 1
	}
	return 1
}

// applyOrientation returns the image as a viewer shows it for the given
// EXIF Orientation. Values outside 2–8 return src unchanged.
func applyOrientation(src *image.RGBA, orientation int) *image.RGBA {
	if orientation < 2 || orientation > 8 {
		return src
	}
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	dw, dh := w, h
	if orientation >= 5 { // the four that swap the axes
		dw, dh = h, w
	}
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for y := range dh {
		for x := range dw {
			// (sx, sy) is the stored pixel shown at (x, y).
			var sx, sy int
			switch orientation {
			case 2: // mirrored horizontally
				sx, sy = w-1-x, y
			case 3: // rotated 180°
				sx, sy = w-1-x, h-1-y
			case 4: // mirrored vertically
				sx, sy = x, h-1-y
			case 5: // transposed
				sx, sy = y, x
			case 6: // rotate 90° clockwise to show
				sx, sy = y, h-1-x
			case 7: // transversed
				sx, sy = w-1-y, h-1-x
			case 8: // rotate 90° counter-clockwise to show
				sx, sy = w-1-y, x
			}
			dst.SetRGBA(x, y, src.RGBAAt(b.Min.X+sx, b.Min.Y+sy))
		}
	}
	return dst
}
