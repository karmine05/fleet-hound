// Package catalog ports src/shadow_it_filter.py and src/software_catalog.py.
// The scaffold ported the source sets, env readers, source predicates and
// ComputePerPlatformThresholds; agent H ported IsSystemPackage and the
// curated catalog.
package catalog

import (
	"context"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/karmine05/fleet-hound/internal/graphdb"
)

func set(xs ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		m[x] = struct{}{}
	}
	return m
}

// Source sets (python frozensets). Treat as read-only.
var (
	DevLanguageSources      = set("npm_packages", "python_packages", "gem_packages", "cargo_packages", "pkg_packages", "portage_packages", "go_binaries")
	LinuxPackageSources     = set("deb_packages", "rpm_packages")
	ExtensionSources        = set("chrome_extensions", "firefox_addons", "safari_extensions", "ie_extensions", "vscode_extensions", "atom_packages", "jetbrains_plugins")
	BrowserExtensionSources = set("chrome_extensions", "firefox_addons", "safari_extensions", "ie_extensions")
	IDEExtensionSources     = set("vscode_extensions", "atom_packages", "jetbrains_plugins")
	UserAppSources          = set("apps", "programs", "homebrew_packages", "chocolatey_packages")
	// ShadowITSources = USER_APP_SOURCES | EXTENSION_SOURCES.
	ShadowITSources = func() map[string]struct{} {
		m := set()
		for k := range UserAppSources {
			m[k] = struct{}{}
		}
		for k := range ExtensionSources {
			m[k] = struct{}{}
		}
		return m
	}()
)

// ShadowITSourceList is list(SHADOW_IT_SOURCES) for Cypher parameters,
// sorted for determinism (python set order was arbitrary).
func ShadowITSourceList() []string {
	out := make([]string, 0, len(ShadowITSources))
	for k := range ShadowITSources {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Outlier threshold constants.
const (
	DefaultOutlierPct = 0.03
	MinOutlierHosts   = 2
)

// GetOutlierPct replaces get_outlier_pct("SHADOW_IT_OUTLIER_PCT"): trimmed,
// inline "#..." comment stripped, parsed as float; missing/unparseable/out of
// (0,1) falls back to 0.03.
func GetOutlierPct() float64 { return outlierPctFrom(os.Getenv("SHADOW_IT_OUTLIER_PCT")) }

func outlierPctFrom(raw string) float64 {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "#"); i >= 0 {
		raw = strings.TrimSpace(raw[:i])
	}
	if raw == "" {
		return DefaultOutlierPct
	}
	pct, err := strconv.ParseFloat(raw, 64)
	if err != nil || pct <= 0 || pct >= 1 {
		return DefaultOutlierPct
	}
	return pct
}

// IncludeLinuxPackages replaces include_linux_packages(): env
// SHADOW_IT_INCLUDE_LINUX_PACKAGES (comment-stripped, lowercased) in
// {1,true,yes,on,y,t}.
func IncludeLinuxPackages() bool {
	raw := strings.TrimSpace(os.Getenv("SHADOW_IT_INCLUDE_LINUX_PACKAGES"))
	if i := strings.Index(raw, "#"); i >= 0 {
		raw = strings.TrimSpace(raw[:i])
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on", "y", "t":
		return true
	}
	return false
}

// normSources is {s.lower().strip() for s in sources if isinstance(s,str) and s.strip()}.
func normSources(sources []string) map[string]struct{} {
	m := make(map[string]struct{}, len(sources))
	for _, s := range sources {
		if strings.TrimSpace(s) == "" {
			continue
		}
		m[strings.TrimSpace(strings.ToLower(s))] = struct{}{}
	}
	return m
}

func subset(a, b map[string]struct{}) bool {
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func intersects(a, b map[string]struct{}) bool {
	for k := range a {
		if _, ok := b[k]; ok {
			return true
		}
	}
	return false
}

// SourcesFrom converts a record value (python list of maybe-strings) to
// []string, dropping non-strings, for the predicates below.
func SourcesFrom(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// IsNonAppSource replaces is_non_app_source: every source is a dev-language
// package manager (false for empty).
func IsNonAppSource(sources []string) bool {
	s := normSources(sources)
	return len(s) > 0 && subset(s, DevLanguageSources)
}

// IsLinuxPackageOnly replaces is_linux_package_only.
func IsLinuxPackageOnly(sources []string) bool {
	s := normSources(sources)
	return len(s) > 0 && subset(s, LinuxPackageSources)
}

// ClassifyExtensionType replaces classify_extension_type: "Browser
// Extension", "VSCode Extension", or "" (python None). Browser wins.
func ClassifyExtensionType(sources []string) string {
	s := normSources(sources)
	if intersects(s, BrowserExtensionSources) {
		return "Browser Extension"
	}
	if intersects(s, IDEExtensionSources) {
		return "VSCode Extension"
	}
	return ""
}

// ComputePerPlatformThresholds replaces compute_per_platform_thresholds(session,
// pct): {platform: max(2, int(hosts*pct))} for every non-empty Host.platform.
// pct <= 0 means GetOutlierPct() (python pct=None).
func ComputePerPlatformThresholds(ctx context.Context, db graphdb.Runner, pct float64) (map[string]int, error) {
	if pct <= 0 {
		pct = GetOutlierPct()
	}
	rows, err := db.Query(ctx, "MATCH (h:Host) "+
		"WHERE h.platform IS NOT NULL AND h.platform <> '' "+
		"RETURN h.platform AS platform, count(h) AS total", nil)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int, len(rows))
	for _, r := range rows {
		p, _ := r["platform"].(string)
		total, _ := graphdb.AsInt64(r["total"])
		out[p] = max(MinOutlierHosts, int(float64(total)*pct))
	}
	return out, nil
}

// pyWS is the body of a character class matching python str-pattern `\s`
// (unicode whitespace incl. \v and \x1c-\x1f). Go RE2 `\s` is ASCII-only
// [\t\n\f\r ], so python patterns are rewritten with pyRegexp.
const pyWS = `\t-\r\x{1c}-\x{20}\x{85}\p{Z}`

// pyRegexp compiles a python `re` pattern after mapping `\s` to python's
// unicode whitespace set. Every `\s` inside a class in these patterns opens
// the class (`[\s...`), which keeps the rewrite a plain string replace.
// Remaining difference: `\b` is ASCII word boundary in RE2, unicode in
// python (only matters next to non-ASCII letters).
func pyRegexp(flags, pattern string) *regexp.Regexp {
	p := strings.ReplaceAll(pattern, `[\s`, "["+pyWS)
	p = strings.ReplaceAll(p, `\s`, "["+pyWS+"]")
	return regexp.MustCompile(flags + p)
}

// systemPackagePattern is SYSTEM_PACKAGE_RE.pattern verbatim (python
// re.IGNORECASE). Names almost always installed by the OS package manager as
// transitive deps or platform components — never user-chosen Shadow IT.
const systemPackagePattern = `^(` +
	// Library packages (lib*, *-dev, *-doc, *-data, *-common, *-headers, *-dbg, *-dbgsym)
	`lib[a-z0-9].*` +
	`|.*-(dev|dbg|dbgsym|doc|docs|data|common|headers|src|source|locale|locales|man|examples|utils|runtime|core|base|tiny|minimal)` +
	// Linux kernel / firmware / boot
	`|linux-(image|headers|libc|modules|tools|cloud|generic|signed|firmware|base|hwe|aws|azure|gcp|oracle|kvm|raspi|ibm|nvidia)([-.].*)?` +
	`|kernel(-.*)?|firmware-.*|grub[-.].*|systemd([-.].*)?|initramfs.*|initrd.*` +
	// Package manager / distro plumbing
	`|debconf.*|dpkg.*|apt(-.*)?|aptitude.*|yum.*|dnf.*|rpm(-.*)?|alien.*|snapd.*|flatpak.*` +
	// Locale / timezone / console
	`|tzdata(-.*)?|locales(-.*)?|language-pack(-.*)?|console-(setup|data)(-.*)?` +
	// Language runtimes shipped as distro packages
	`|python3?(-.*|\.[0-9]+(-.*)?)?` +
	`|perl(-.*|-base|-modules.*)?` +
	`|ruby[0-9.]*(-.*)?|gem-.*` +
	`|golang(-.*)?` +
	// Toolchain
	`|gcc(-.*)?|g\+\+(-.*)?|clang(-.*)?|llvm(-.*)?|binutils(-.*)?|make.*|cmake.*` +
	`|automake.*|autoconf.*|libtool.*|pkg-config.*` +
	// Desktop / X11 / fonts
	`|gnome-.*|kde-.*|xfce4-.*|cinnamon-.*|mate-.*|x11-.*|xorg-.*|xserver-.*` +
	`|fonts-.*|gtk[0-9.-]*|qt[0-9.-]*` +
	// Crypto / certs / shells
	`|openssl.*|ca-certificates.*|gnupg.*|gpg.*|gpgv.*|gnupg2.*` +
	// Core utils
	`|ucf|sensible-utils|lsb-.*|base-(files|passwd)|coreutils|util-linux.*` +
	`|findutils|grep|sed|gawk|tar|gzip|xz-utils|bzip2|zstd|file|less|nano` +
	`|vim-(common|tiny|runtime)|bash|dash|zsh|tmux|screen` +
	// Network plumbing
	`|cups(-.*)?|samba.*|smbclient.*|nfs-.*|rpcbind.*|netbase|iproute2|iputils-.*` +
	// CUDA / NVIDIA / GPU dev stacks (added 2026-05-07 — these flooded the
	// enrichment queue with non-Shadow-IT candidates that Wikidata never has).
	// Match space-separated names too: "NVIDIA Container", "CUDART Runtime",
	// "CUDA Profiler Tools" — the boundary is `[\s\-_.]` so we catch every
	// variant osquery surfaces.
	`|cuda([\s\-_.].*)?|cudart([\s\-_.].*)?|cccl([\s\-_.].*)?` +
	`|cupti([\s\-_.].*)?|nccl([\s\-_.].*)?|cusparse([\s\-_.].*)?` +
	`|cusolver([\s\-_.].*)?|cublas([\s\-_.].*)?|cudnn([\s\-_.].*)?` +
	`|nvjpeg([\s\-_.].*)?|nvrtc([\s\-_.].*)?|nvprune([\s\-_.].*)?` +
	`|nvidia([\s\-_.].*)?` +
	`|nvvm([\s\-_.].*)?|nvcc|npp([\s\-_.].*)?|visual profiler.*|nsight.*` +
	`|libnv(idia|jpeg|cu.*|nccl.*|rtc.*|pti.*|blas.*|toolkit.*)?(-.*)?` +
	`|libcu(blas.*|dnn.*|fft.*|rand.*|solver.*|sparse.*|pti.*|tensor.*|nvrtc.*)(-.*)?` +
	`|libnpp.*|libnvrtc.*` +
	// Windows OS-plumbing names that aren't user apps
	`|microsoft visual c\+\+ [0-9]+.*` +
	`|microsoft \.net.*` +
	`|update for microsoft .*` +
	`|security update for microsoft .*` +
	`|definition update for microsoft .*` +
	`|microsoft\.(aad.*|bingsearch|bingweather|bioenrollment|webpimageextension|` +
	`|windowscalculator|skydrive.*|onedrive.*|content.*|asyncfile.*|heif.*|` +
	`|outlook.*|webp.*|xaml.*|ui\..*|xboxgamebar.*|gamebar.*|xbox.*|cortana|` +
	`|wallet.*|getstarted.*|getstarted|store.*|edge.*|edgecore.*|onenote.*)` +
	`|windows sdk.*|windows .*sdk.*|application verifier.*|wdagutilityaccount|defaultaccount` +
	`|game bar|xbox game bar|mecab-.*` +
	// Hardware drivers that appear with vendor-prefix + underscore variants
	`|mlnx_.*|mellanox.*|msi development tools.*|msi dev.*` +
	// Python distribution components — "Python 3.X.Y Standard Library (64-bit)",
	// "Python 3.X.Y Test Suite (64-bit)", "Python 3.X.Y Documentation (64-bit)",
	// "Python 3.X.Y Utility Scripts (64-bit)", "Python 3.X.Y pip Bootstrap (64-bit)",
	// "Python 3.X.Y Tcl/Tk Support (64-bit)", "Python 3.X.Y Core Interpreter (64-bit)",
	// "Python 3.X.Y Executables (64-bit)", "Python 3.X.Y Development Libraries (64-bit)"
	`|python\s+[0-9][\s.0-9].*` +
	// Windows SDK variants (long-tail names that don't match the simpler 'windows sdk.*')
	`|windows software development kit.*|windows app certification kit.*` +
	`|wptx?(64|86)?(\s|\-|_).*|wpt(x64|x86).*|application verifier.*` +
	`|winrt intellisense.*|winrt[\s\-_].*` +
	// Microsoft platform components / store-app projections
	`|microsoft\.(ppiprojection|.*projection|mpeg[0-9]+.*|.*videoextension|` +
	`|cloud.*|content.*|ngc.*|powerautomatedesktop.*|paint|xboxapp.*|copilot.*|` +
	`|todo.*|whiteboard.*|skype.*|teams.*|stickynotes.*|alarmclock.*|` +
	`|maps.*|messaging.*|people.*|moviesandtv|getstarted.*|getstarted)` +
	// Microsoft Visual C++ all version variants (v14, v17, etc)
	`|microsoft visual c\+\+ v?[0-9]+.*` +
	// Visual Studio variants (Community, Enterprise, Professional, BuildTools)
	`|visual studio (community|enterprise|professional|build tools|installer|tools).*` +
	`|visual studio [0-9]+.*` +
	// WD / SSD / hardware vendor SKUs that appear in inventory but never in Wikidata
	`|wd[\s\-_].*|seagate[\s\-_].*|verbatim[\s\-_].*` +
	// Placeholder display names from broken installers
	`|\$\{\{?arpdisplayname\}?\}\$?|\$\{\{[^}]+\}\}.*` +
	// Generic Windows Store app prefixes
	`|windowsstore.*|appsforwindows10.*|microsoftstore.*` +
	// Generic SDK / redistributables (catch-all for the long tail)
	`|.*\bsdk\b.*redistributables?.*|sdk\s+(arm|x86|x64).*` +
	`|.*redistributables?(\s|\-).*|.*\bredistributable\b.*` +
	`|microsoft update health tools|microsoft msi development tools|microsoft msi development tools.*` +
	`|microsoft .net native runtime package.*|universal crt redistributable` +
	`|outlook for windows|microsoft office shared.*|microsoft yourphone` +
	`|microsoft\.zune.*|microsoft\.mspaint|microsoft msync.*` +
	`|microsoft 365 - en-us|cortana` +
	// Visual Studio / SDK installer artifacts
	`|vs_.*|virtio-win-driver-installer.*` +
	// Other obviously-not-Shadow-IT
	`|udk package|verbatim_.*|wd_.*|wd p[0-9]+ .*|m-audio .*|` +
	`|ene_.*|ctadvisor|realtek.*|intel\(r\) .*|amd .*|c5e2524a-.*` +
	`|microsoft\.windows\..*` +
	`)$`

// nonUserFacingPattern is NON_USER_FACING_RE.pattern verbatim (python
// re.IGNORECASE): subprocess bundles, auto-updaters, crash reporters,
// build/test binaries and OS-runtime redistributables surfaced under
// user-app sources. Deliberately conservative: no bare agent/service/host/
// daemon tokens.
const nonUserFacingPattern = `^(` +
	// Chromium/Electron subprocess bundles: "X Helper", "X Helper (GPU|Renderer|Plugin|Alerts)"
	`.* helper( \(.*\))?$|.*helper \((gpu|renderer|plugin|alerts)\)$` +
	// Login / crash / update companions
	`|.*loginhelper$|.*crashpad.*|.* crash ?reporter$|.*crashreporter$` +
	`|.* updater$|.*autoupdater$|.*[ _]update helper$` +
	// macOS system placeholders / launch jobs
	`|.*placeholder$|.*launchagent$|.*launchdaemon$` +
	// Build / unit-test binaries (e.g. OpenSSL checkout artifacts)
	`|buildtest[_ ].*|.*[_ ]test\.exe$|.*test\.exe$|.*_test$` +
	// Microsoft runtime/redistributable/locale plumbing the OS-regex misses
	`|microsoft 365 - .*|microsoft windows desktop runtime.*` +
	`|microsoft \.net.*|microsoft visual c\+\+.*|microsoft edgewebview2.*` +
	`)$`

var (
	systemPackageRE = pyRegexp("(?i)", systemPackagePattern)
	nonUserFacingRE = pyRegexp("(?i)", nonUserFacingPattern)
)

// SystemCategoryTokens is SYSTEM_CATEGORY_TOKENS: Wikidata category tokens
// that indicate OS plumbing, not an app.
var SystemCategoryTokens = []string{
	"software library", "shared library", "system library",
	"free software library", "kernel module", "device driver",
	"header file", "package manager package", "metapackage",
	"init system", "system component", "operating system component",
}

// pyIsSpace is python str.isspace for one rune.
func pyIsSpace(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) }

// pyStrip is python str.strip().
func pyStrip(s string) string { return strings.TrimFunc(s, pyIsSpace) }

// IsSystemPackage replaces is_system_package(name, db_categories, sources):
// true when the software is OS plumbing, a dev-language transitive dep, a
// Linux-package-only install (unless SHADOW_IT_INCLUDE_LINUX_PACKAGES), a
// junk name with no letter/digit, a non-user-facing bundle, or carries a
// system Wikidata category. Extension-only sources never suppress on their
// own.
func IsSystemPackage(name string, dbCategories []string, sources []string) bool {
	if name == "" {
		return false
	}
	if IsNonAppSource(sources) {
		return true
	}
	if IsLinuxPackageOnly(sources) && !IncludeLinuxPackages() {
		return true
	}
	nm := pyStrip(strings.ToLower(name))
	// python: not any(c.isalnum() for c in nm)
	if !strings.ContainsFunc(nm, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsNumber(r) }) {
		return true
	}
	if systemPackageRE.MatchString(nm) || nonUserFacingRE.MatchString(nm) {
		return true
	}
	if len(dbCategories) > 0 {
		lowered := make([]string, len(dbCategories))
		for i, c := range dbCategories {
			lowered[i] = strings.ToLower(c)
		}
		catText := strings.Join(lowered, " ")
		for _, tok := range SystemCategoryTokens {
			if strings.Contains(catText, tok) {
				return true
			}
		}
	}
	return false
}
