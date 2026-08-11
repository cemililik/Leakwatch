package meta

const (
	// ReleaseVersion is the latest stable release published to users. Release
	// tooling still injects the running binary's exact build version; this value
	// owns static product surfaces such as the website footer and roadmap guards.
	ReleaseVersion = "v1.8.0"

	// ReleaseDate is the publication date of ReleaseVersion (ISO 8601).
	ReleaseDate = "2026-08-11"
)
