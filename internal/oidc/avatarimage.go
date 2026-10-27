package oidc

import (
	"bytes"
	"image"
	"image/jpeg"
	"image/png"

	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp" // registers the WebP decoder
)

const (
	// maxAvatarSide rejects larger images before they are decoded, so a
	// small file that declares a huge canvas cannot exhaust memory.
	maxAvatarSide = 4096
	// avatarSide is the box the stored image is scaled down to fit.
	avatarSide  = 512
	jpegQuality = 85
)

// avatarError codes are put in /account?error=<code> and mapped back to a
// fixed message there.
type avatarError string

const (
	errAvatarType       avatarError = "type"
	errAvatarSize       avatarError = "size"
	errAvatarDimensions avatarError = "dimensions"
	errAvatarDecode     avatarError = "decode"
	errAvatarMissing    avatarError = "missing"
	errAvatarMultiple   avatarError = "multiple"
)

var avatarErrorMessages = map[string]string{
	string(errAvatarType):       "画像は PNG・JPEG・WebP のいずれかにしてください",
	string(errAvatarSize):       "画像は 1MB 以下にしてください",
	string(errAvatarDimensions): "画像は 4096×4096 ピクセル以下にしてください",
	string(errAvatarDecode):     "画像を読み込めませんでした",
	string(errAvatarMissing):    "画像を選択してください",
	string(errAvatarMultiple):   "画像は 1 枚だけ選択してください",
}

// detectAvatarType judges the image by its magic bytes, never by the file
// name or the Content-Type the browser sent, and returns the image package's
// format name, or "" for anything else (SVG and HTML in particular).
func detectAvatarType(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return "png"
	case bytes.HasPrefix(b, []byte("\xff\xd8\xff")):
		return "jpeg"
	case len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		return "webp"
	}
	return ""
}

// processAvatar decodes the upload and re-encodes it, scaled down to fit
// avatarSide×avatarSide. Only the re-encoded pixels are kept, so EXIF (GPS
// position, device, capture time) and every other piece of metadata or
// trailing data is dropped, and what is served is always a well-formed
// image. A JPEG's EXIF Orientation is applied to the pixels first, so phone
// photos stay upright. JPEG stays JPEG (quality 85); PNG and WebP become PNG.
func processAvatar(data []byte) (out []byte, contentType string, code avatarError) {
	format := detectAvatarType(data)
	if format == "" {
		return nil, "", errAvatarType
	}
	cfg, decoded, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || decoded != format || cfg.Width <= 0 || cfg.Height <= 0 {
		return nil, "", errAvatarDecode
	}
	if cfg.Width > maxAvatarSide || cfg.Height > maxAvatarSide {
		return nil, "", errAvatarDimensions
	}
	src, decoded, err := image.Decode(bytes.NewReader(data))
	if err != nil || decoded != format {
		return nil, "", errAvatarDecode
	}

	b := src.Bounds()
	w, h := fitWithin(b.Dx(), b.Dy(), avatarSide)
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	if w == b.Dx() && h == b.Dy() {
		draw.Draw(dst, dst.Bounds(), src, b.Min, draw.Src)
	} else {
		draw.CatmullRom.Scale(dst, dst.Bounds(), src, b, draw.Src, nil)
	}
	if format == "jpeg" {
		// The EXIF Orientation is lost with the rest of EXIF, so turn the
		// pixels upright now. (The box is square, so scaling first is fine.)
		dst = applyOrientation(dst, jpegOrientation(data))
	}

	var buf bytes.Buffer
	if format == "jpeg" {
		err = jpeg.Encode(&buf, dst, &jpeg.Options{Quality: jpegQuality})
		contentType = "image/jpeg"
	} else {
		err = png.Encode(&buf, dst)
		contentType = "image/png"
	}
	if err != nil {
		return nil, "", errAvatarDecode
	}
	return buf.Bytes(), contentType, ""
}

// fitWithin scales w×h down, keeping the aspect ratio, so that neither side
// exceeds limit. Images that already fit are left as they are.
func fitWithin(w, h, limit int) (int, int) {
	if w <= limit && h <= limit {
		return w, h
	}
	if w >= h {
		return limit, max(1, (h*limit+w/2)/w)
	}
	return max(1, (w*limit+h/2)/h), limit
}
