// Package remediate builds the one-off Fleet scripts that remove a browser
// extension from a host, and tracks the runs.
//
// There are two generic scripts (POSIX sh for macOS and Linux, PowerShell for
// Windows). Each takes three parameters: extension ID, store and whether to
// block reinstall. The script discovers users, browsers and profiles on the
// host, so no per-extension script exists and nothing is saved in Fleet.
package remediate

import (
	_ "embed"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

//go:embed scripts/uninstall_extension.sh
var posixScript string

//go:embed scripts/uninstall_extension.ps1
var windowsScript string

// Host operating systems a script exists for.
const (
	OSMac     = "macos"
	OSLinux   = "linux"
	OSWindows = "windows"
)

// maxAdHocRunes is Fleet's size limit for a one-off script_contents.
const maxAdHocRunes = 10000

// nonScriptPlatforms are Fleet host platforms with no script runner.
var nonScriptPlatforms = map[string]bool{"ios": true, "ipados": true, "android": true, "chrome": true}

// OSFor maps a Fleet host platform to a script OS. Fleet reports each Linux
// distribution by name (ubuntu, rhel, ...), so every platform that is not
// macOS, Windows or a mobile/ChromeOS platform is Linux.
func OSFor(platform string) (string, bool) {
	p := strings.ToLower(strings.TrimSpace(platform))
	switch {
	case p == "":
		return "", false
	case p == "darwin":
		return OSMac, true
	case p == "windows":
		return OSWindows, true
	case nonScriptPlatforms[p]:
		return "", false
	}
	return OSLinux, true
}

var chromiumStores = map[string]bool{
	"chrome": true, "edge": true, "brave": true, "chromium": true, "opera": true, "vivaldi": true,
}

// The ID is written into a single-quoted script literal and used as a path
// leaf, so both patterns exclude quotes, slashes and whitespace.
var (
	chromiumIDRe = regexp.MustCompile(`^[a-p]{32}$`)
	firefoxIDRe  = regexp.MustCompile(`^(\{[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}|[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9._-]{1,64})$`)
)

// Check reports why an extension cannot be removed by script, or nil.
func Check(store, extID string) error {
	store = strings.ToLower(store)
	switch {
	case store == "safari":
		return fmt.Errorf("extensions for Safari ship inside an app; remove the containing app instead")
	case store == "firefox":
		if !firefoxIDRe.MatchString(extID) {
			return fmt.Errorf("no usable Firefox add-on ID is recorded for this extension")
		}
	case chromiumStores[store]:
		if !chromiumIDRe.MatchString(extID) {
			return fmt.Errorf("no usable extension ID is recorded for this extension")
		}
	default:
		return fmt.Errorf("removal is not supported for store %q", store)
	}
	return nil
}

// blockStores lists, per OS, the stores whose reinstall the script can block
// with a machine policy. macOS needs a configuration profile, so it has none.
var blockStores = map[string]map[string]bool{
	OSLinux:   {"chrome": true, "edge": true, "brave": true, "chromium": true, "firefox": true},
	OSWindows: {"chrome": true, "edge": true, "brave": true, "chromium": true},
}

// CanBlock reports whether the script can also block reinstall.
func CanBlock(osName, store string) bool {
	return blockStores[osName][strings.ToLower(store)]
}

// BuildScript returns the script that removes extID (from store) on a host
// running osName.
func BuildScript(osName, store, extID string, block bool) (string, error) {
	store = strings.ToLower(store)
	if err := Check(store, extID); err != nil {
		return "", err
	}
	var tmpl string
	switch osName {
	case OSMac, OSLinux:
		tmpl = posixScript
	case OSWindows:
		tmpl = windowsScript
	default:
		return "", fmt.Errorf("no removal script for OS %q", osName)
	}
	flag := "0"
	if block {
		flag = "1"
	}
	out := strings.NewReplacer("__EXT_ID__", extID, "__EXT_STORE__", store, "__BLOCK__", flag).Replace(tmpl)
	if n := utf8.RuneCountInString(out); n > maxAdHocRunes {
		return "", fmt.Errorf("script is %d characters; Fleet accepts at most %d", n, maxAdHocRunes)
	}
	return out, nil
}

// Outcome is what a finished script reported on its FH_* lines.
type Outcome struct {
	Result  string // "removed", "not_found", "error" or "" when absent
	Removed int    // paths deleted
	Block   string // block state, e.g. "written", "unsupported_on_macos"
}

// ParseOutput reads the FH_RESULT / FH_REMOVED / FH_BLOCK lines.
func ParseOutput(output string) Outcome {
	var o Outcome
	for _, line := range strings.Split(output, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "FH_RESULT":
			o.Result = val
		case "FH_REMOVED":
			if n, err := strconv.Atoi(val); err == nil {
				o.Removed = n
			}
		case "FH_BLOCK":
			o.Block = val
		}
	}
	return o
}
