// Isolated module for the documentation site build tool.
//
// This tool compiles the Markdown user manuals under docs/user-manuals/ into
// the JavaScript "bags" consumed by the static website (site/). It lives in a
// separate module on purpose so its Markdown/YAML dependencies never leak into
// the main Leakwatch module (which deliberately stays dependency-light).
module leakwatch-site-build

go 1.25

require (
	github.com/yuin/goldmark v1.8.4
	gopkg.in/yaml.v3 v3.0.1
)
