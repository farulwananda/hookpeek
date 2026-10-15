package web

import _ "embed"

// IndexHTML is bundled with the CLI so /ui works from any working directory.
//
//go:embed index.html
var IndexHTML []byte
