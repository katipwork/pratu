package server

import (
	"embed"
	"io/fs"
	"net/http"
)

// The reference login UI: a zero-build single page driving the browser
// flow API — login, registration, verification, MFA, recovery, social
// sign-in, and the OAuth2 login/consent handshake. It exists so a new
// tenant has a working login experience before building its own UI, and
// as copyable example code; the server stays headless by default
// (public.reference_ui enables it).
//
//go:embed ui
var uiFS embed.FS

func mountReferenceUI(mux *http.ServeMux) {
	sub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		panic(err) // embedded tree is fixed at build time
	}
	mux.Handle("GET /ui/", http.StripPrefix("/ui/", http.FileServerFS(sub)))
	mux.Handle("GET /ui", http.RedirectHandler("/ui/", http.StatusMovedPermanently))
}
