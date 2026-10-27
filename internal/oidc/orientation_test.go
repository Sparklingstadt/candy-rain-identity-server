package oidc

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/jpeg"
	"math/rand/v2"
	"testing"
)

// labelled returns a w×h image whose pixels hold their row-major index, so
// a transformed image can be compared label by label.
func labelled(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.SetRGBA(x, y, color.RGBA{uint8(y*w + x), 0, 0, 0xff})
		}
	}
	return img
}

func labels(img *image.RGBA) (w, h int, out []uint8) {
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			out = append(out, img.RGBAAt(x, y).R)
		}
	}
	return b.Dx(), b.Dy(), out
}

func TestApplyOrientation(t *testing.T) {
	// The stored image is
	//   a b c      0 1 2
	//   d e f  =   3 4 5
	// and each case is what a viewer shows for that EXIF Orientation.
	const a, b, c, d, e, f = 0, 1, 2, 3, 4, 5
	for _, tc := range []struct {
		orientation int
		w, h        int
		want        []uint8
	}{
		{1, 3, 2, []uint8{a, b, c, d, e, f}},
		{2, 3, 2, []uint8{c, b, a, f, e, d}}, // mirrored horizontally
		{3, 3, 2, []uint8{f, e, d, c, b, a}}, // rotated 180°
		{4, 3, 2, []uint8{d, e, f, a, b, c}}, // mirrored vertically
		{5, 2, 3, []uint8{a, d, b, e, c, f}}, // transposed
		{6, 2, 3, []uint8{d, a, e, b, f, c}}, // rotated 90° clockwise
		{7, 2, 3, []uint8{f, c, e, b, d, a}}, // transversed
		{8, 2, 3, []uint8{c, f, b, e, a, d}}, // rotated 90° counter-clockwise
		{0, 3, 2, []uint8{a, b, c, d, e, f}}, // out of range: unchanged
		{9, 3, 2, []uint8{a, b, c, d, e, f}},
	} {
		w, h, got := labels(applyOrientation(labelled(3, 2), tc.orientation))
		if w != tc.w || h != tc.h || !bytes.Equal(got, tc.want) {
			t.Errorf("orientation %d: %dx%d %v, want %dx%d %v", tc.orientation, w, h, got, tc.w, tc.h, tc.want)
		}
	}
}

// exifSegment builds an APP1 segment with an IFD0 holding one entry.
func exifSegment(order binary.ByteOrder, tag, typ uint16, count uint32, value uint16) []byte {
	tiff := make([]byte, 8+2+12+4)
	if order == binary.LittleEndian {
		copy(tiff, "II")
	} else {
		copy(tiff, "MM")
	}
	order.PutUint16(tiff[2:], 42)
	order.PutUint32(tiff[4:], 8)
	order.PutUint16(tiff[8:], 1)
	order.PutUint16(tiff[10:], tag)
	order.PutUint16(tiff[12:], typ)
	order.PutUint32(tiff[14:], count)
	order.PutUint16(tiff[18:], value)
	return app1(append([]byte("Exif\x00\x00"), tiff...))
}

func app1(payload []byte) []byte {
	seg := []byte{0xff, 0xe1, 0, 0}
	binary.BigEndian.PutUint16(seg[2:], uint16(len(payload)+2))
	return append(seg, payload...)
}

// withSegments inserts segments right after SOI.
func withSegments(jpg []byte, segs ...[]byte) []byte {
	out := append([]byte{}, jpg[:2]...)
	for _, s := range segs {
		out = append(out, s...)
	}
	return append(out, jpg[2:]...)
}

func TestJPEGOrientation(t *testing.T) {
	base := jpegOf(8, 8)
	be, le := binary.BigEndian, binary.LittleEndian
	valid := withSegments(base, exifSegment(be, 0x0112, 3, 1, 6))
	for _, tc := range []struct {
		name string
		data []byte
		want int
	}{
		{"no EXIF", base, 1},
		{"big endian 6", valid, 6},
		{"little endian 8", withSegments(base, exifSegment(le, 0x0112, 3, 1, 8)), 8},
		{"all values", withSegments(base, exifSegment(le, 0x0112, 3, 1, 3)), 3},
		{"value 0", withSegments(base, exifSegment(be, 0x0112, 3, 1, 0)), 1},
		{"value 9", withSegments(base, exifSegment(be, 0x0112, 3, 1, 9)), 1},
		{"value 0xffff", withSegments(base, exifSegment(be, 0x0112, 3, 1, 0xffff)), 1},
		{"wrong type (LONG)", withSegments(base, exifSegment(be, 0x0112, 4, 1, 6)), 1},
		{"wrong count", withSegments(base, exifSegment(be, 0x0112, 3, 2, 6)), 1},
		{"other tag", withSegments(base, exifSegment(be, 0x0110, 3, 1, 6)), 1},
		{"after a non-EXIF APP1", withSegments(base, app1([]byte("http://ns.adobe.com/xap/1.0/\x00<x/>")), exifSegment(be, 0x0112, 3, 1, 6)), 6},
		{"bad byte order", withSegments(base, app1([]byte("Exif\x00\x00XX\x00\x2a\x00\x00\x00\x08\x00\x00"))), 1},
		{"bad magic", withSegments(base, app1([]byte("Exif\x00\x00MM\x00\x2b\x00\x00\x00\x08\x00\x00"))), 1},
		{"IFD offset past the end", withSegments(base, app1([]byte("Exif\x00\x00MM\x00\x2a\x7f\xff\xff\xff"))), 1},
		{"IFD offset overflows", withSegments(base, app1([]byte("Exif\x00\x00MM\x00\x2a\xff\xff\xff\xff"))), 1},
		{"entry count past the end", withSegments(base, app1([]byte("Exif\x00\x00MM\x00\x2a\x00\x00\x00\x08\xff\xff\x01\x12\x00\x03"))), 1},
		{"EXIF header only", withSegments(base, app1([]byte("Exif\x00\x00"))), 1},
		{"segment length below 2", append([]byte{0xff, 0xd8, 0xff, 0xe1, 0x00, 0x01}, valid[2:]...), 1},
		{"segment length past the end", []byte{0xff, 0xd8, 0xff, 0xe1, 0xff, 0xff, 'E', 'x', 'i', 'f'}, 1},
		{"not a JPEG", []byte("\x89PNG\r\n\x1a\n"), 1},
		{"empty", nil, 1},
		{"SOI only", []byte{0xff, 0xd8}, 1},
		{"fill bytes before the marker", withSegments(base, append([]byte{0xff, 0xff}, exifSegment(be, 0x0112, 3, 1, 5)...)), 5},
	} {
		if got := jpegOrientation(tc.data); got != tc.want {
			t.Errorf("%s: orientation %d, want %d", tc.name, got, tc.want)
		}
	}

	// Every truncation of a valid file is handled without a panic.
	for n := range len(valid) {
		if got := jpegOrientation(valid[:n]); got != 1 && got != 6 {
			t.Fatalf("truncated to %d bytes: %d", n, got)
		}
	}
	// Random garbage after SOI never panics and never yields an invalid value.
	rng := rand.New(rand.NewPCG(1, 2))
	for range 5000 {
		junk := make([]byte, rng.IntN(64))
		for i := range junk {
			junk[i] = byte(rng.UintN(256))
		}
		data := append([]byte{0xff, 0xd8, 0xff, 0xe1, 0x00, byte(len(junk) + 2)}, junk...)
		copy(data[6:], "Exif\x00\x00")
		if got := jpegOrientation(data); got < 1 || got > 8 {
			t.Fatalf("garbage %x: %d", data, got)
		}
	}
}

// quadrants is 40×20 with a distinct colour in each quadrant, as a viewer
// should show it.
func quadrants() *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, 40, 20))
	for y := range 20 {
		for x := range 40 {
			c := color.RGBA{0xff, 0, 0, 0xff} // top left: red
			switch {
			case x >= 20 && y < 10:
				c = color.RGBA{0, 0xff, 0, 0xff} // top right: green
			case x < 20 && y >= 10:
				c = color.RGBA{0, 0, 0xff, 0xff} // bottom left: blue
			case x >= 20 && y >= 10:
				c = color.RGBA{0xff, 0xff, 0xff, 0xff} // bottom right: white
			}
			img.SetRGBA(x, y, c)
		}
	}
	return img
}

func near(a, b color.Color) bool {
	r1, g1, b1, _ := a.RGBA()
	r2, g2, b2, _ := b.RGBA()
	d := func(p, q uint32) bool { return max(p, q)-min(p, q) < 0x3000 }
	return d(r1, r2) && d(g1, g2) && d(b1, b2)
}

// A phone photo is stored sideways with Orientation 6; the avatar must come
// out upright and without the EXIF data.
func TestProcessAvatarAppliesOrientation(t *testing.T) {
	upright := quadrants()
	inverse := map[int]int{1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 8, 7: 7, 8: 6}
	for o := 1; o <= 8; o++ {
		var buf bytes.Buffer
		jpeg.Encode(&buf, applyOrientation(upright, inverse[o]), &jpeg.Options{Quality: 95})
		src := withSegments(buf.Bytes(), exifSegment(binary.BigEndian, 0x0112, 3, 1, uint16(o)))
		out, contentType, code := processAvatar(src)
		if code != "" || contentType != "image/jpeg" {
			t.Fatalf("orientation %d: %q %q", o, contentType, code)
		}
		if bytes.Contains(out, []byte("Exif\x00")) {
			t.Fatalf("orientation %d: EXIF survived", o)
		}
		img, err := jpeg.Decode(bytes.NewReader(out))
		if err != nil {
			t.Fatal(err)
		}
		if b := img.Bounds(); b.Dx() != 40 || b.Dy() != 20 {
			t.Fatalf("orientation %d: %dx%d", o, b.Dx(), b.Dy())
		}
		for _, p := range []image.Point{{5, 5}, {35, 5}, {5, 15}, {35, 15}} {
			if got, want := img.At(p.X, p.Y), upright.At(p.X, p.Y); !near(got, want) {
				t.Errorf("orientation %d at %v: %v, want %v", o, p, got, want)
			}
		}
	}
}
