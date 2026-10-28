package catalog

import (
	"regexp"
	"strings"
)

// Curated catalog of common Shadow IT applications (src/software_catalog.py).
// First stop in enrichment so the most common apps resolve without network
// calls. Keys are lowercase, no version, no parenthetical platform tags.
type catalogEntry struct {
	categories  []string
	description string
}

var softwareCatalog = map[string]catalogEntry{
	"slack":                   {[]string{"Communication", "Team Chat"}, "Workplace messaging and collaboration platform."},
	"discord":                 {[]string{"Communication", "Voice Chat"}, "Voice, video, and text chat for communities."},
	"zoom":                    {[]string{"Communication", "Video Conferencing"}, "Video conferencing and online meeting platform."},
	"microsoft teams":         {[]string{"Communication", "Team Chat"}, "Microsoft's workplace chat and meetings platform."},
	"telegram desktop":        {[]string{"Communication", "Messaging"}, "Cloud-based instant messaging app."},
	"signal":                  {[]string{"Communication", "Messaging"}, "End-to-end encrypted messaging app."},
	"whatsapp":                {[]string{"Communication", "Messaging"}, "End-to-end encrypted messaging app."},
	"skype":                   {[]string{"Communication", "Video Conferencing"}, "Voice, video, and instant messaging."},
	"notion":                  {[]string{"Productivity", "Notes"}, "All-in-one workspace for notes, docs, and project management."},
	"obsidian":                {[]string{"Productivity", "Notes"}, "Markdown-based knowledge base and note-taking app."},
	"evernote":                {[]string{"Productivity", "Notes"}, "Note-taking and organization app."},
	"trello":                  {[]string{"Productivity", "Project Management"}, "Kanban-style project management."},
	"todoist":                 {[]string{"Productivity", "Task Management"}, "Personal and team task manager."},
	"1password":               {[]string{"Security Tool", "Password Manager"}, "Cross-platform password manager."},
	"bitwarden":               {[]string{"Security Tool", "Password Manager"}, "Open-source password manager."},
	"keepassxc":               {[]string{"Security Tool", "Password Manager"}, "Cross-platform community port of KeePass."},
	"keepass":                 {[]string{"Security Tool", "Password Manager"}, "Free open-source password manager."},
	"lastpass":                {[]string{"Security Tool", "Password Manager"}, "Cloud password manager."},
	"dashlane":                {[]string{"Security Tool", "Password Manager"}, "Password manager and digital wallet."},
	"nordpass":                {[]string{"Security Tool", "Password Manager"}, "NordVPN's password manager."},
	"anydesk":                 {[]string{"Remote Access", "Remote Desktop"}, "Remote desktop software."},
	"teamviewer":              {[]string{"Remote Access", "Remote Desktop"}, "Remote control and desktop sharing."},
	"putty":                   {[]string{"Remote Access", "SSH Client"}, "Free SSH and telnet client for Windows."},
	"windows terminal":        {[]string{"Developer Tool", "Terminal"}, "Microsoft's modern terminal app."},
	"tabby":                   {[]string{"Remote Access", "Terminal"}, "Modern terminal with SSH support."},
	"mremoteng":               {[]string{"Remote Access", "Connection Manager"}, "Multi-protocol remote connection manager."},
	"google chrome":           {[]string{"Browser"}, "Google's web browser based on Chromium."},
	"mozilla firefox":         {[]string{"Browser"}, "Open-source web browser by Mozilla."},
	"firefox":                 {[]string{"Browser"}, "Open-source web browser by Mozilla."},
	"brave browser":           {[]string{"Browser", "Privacy Tool"}, "Privacy-focused browser based on Chromium."},
	"brave":                   {[]string{"Browser", "Privacy Tool"}, "Privacy-focused browser based on Chromium."},
	"vivaldi":                 {[]string{"Browser"}, "Customizable web browser."},
	"opera":                   {[]string{"Browser"}, "Web browser developed by Opera Software."},
	"visual studio code":      {[]string{"Developer Tool", "IDE"}, "Microsoft's free source-code editor."},
	"sublime text":            {[]string{"Developer Tool", "Editor"}, "Sophisticated text editor for code."},
	"atom":                    {[]string{"Developer Tool", "Editor"}, "Hackable text editor (deprecated by GitHub)."},
	"intellij idea":           {[]string{"Developer Tool", "IDE"}, "JetBrains IDE for Java and JVM languages."},
	"pycharm":                 {[]string{"Developer Tool", "IDE"}, "JetBrains IDE for Python."},
	"webstorm":                {[]string{"Developer Tool", "IDE"}, "JetBrains IDE for JavaScript/TypeScript."},
	"goland":                  {[]string{"Developer Tool", "IDE"}, "JetBrains IDE for Go."},
	"android studio":          {[]string{"Developer Tool", "IDE"}, "Google's IDE for Android app development."},
	"xcode":                   {[]string{"Developer Tool", "IDE"}, "Apple's IDE for macOS/iOS development."},
	"github desktop":          {[]string{"Developer Tool", "Git Client"}, "GitHub's desktop Git client."},
	"sourcetree":              {[]string{"Developer Tool", "Git Client"}, "Atlassian's free Git GUI client."},
	"gitkraken":               {[]string{"Developer Tool", "Git Client"}, "Cross-platform Git GUI."},
	"postman":                 {[]string{"Developer Tool", "API Client"}, "API development and testing platform."},
	"insomnia":                {[]string{"Developer Tool", "API Client"}, "Open-source API design and testing tool."},
	"docker desktop":          {[]string{"Developer Tool", "Container Runtime"}, "Docker container runtime for desktop OSes."},
	"podman desktop":          {[]string{"Developer Tool", "Container Runtime"}, "Container runtime alternative to Docker."},
	"nodejs":                  {[]string{"Developer Tool", "Runtime"}, "JavaScript runtime built on Chrome's V8 engine."},
	"node.js":                 {[]string{"Developer Tool", "Runtime"}, "JavaScript runtime built on Chrome's V8 engine."},
	"git":                     {[]string{"Developer Tool", "Version Control"}, "Distributed version control system."},
	"7-zip":                   {[]string{"Utility", "Archive Manager"}, "Open-source file archiver."},
	"winrar":                  {[]string{"Utility", "Archive Manager"}, "Windows archive manager."},
	"the unarchiver":          {[]string{"Utility", "Archive Manager"}, "macOS archive utility."},
	"rectangle":               {[]string{"Utility", "Window Manager"}, "macOS window manager (free)."},
	"magnet":                  {[]string{"Utility", "Window Manager"}, "macOS window manager (paid)."},
	"alfred":                  {[]string{"Utility", "Launcher"}, "macOS productivity launcher."},
	"raycast":                 {[]string{"Utility", "Launcher"}, "Modern macOS launcher with extensions."},
	"powertoys":               {[]string{"Utility", "Productivity"}, "Microsoft's free productivity utilities for Windows."},
	"ditto":                   {[]string{"Utility", "Clipboard"}, "Windows clipboard manager."},
	"dropbox":                 {[]string{"Cloud Storage"}, "File hosting and synchronization service."},
	"google drive":            {[]string{"Cloud Storage"}, "Google's cloud file storage."},
	"onedrive":                {[]string{"Cloud Storage"}, "Microsoft's cloud file storage."},
	"icloud drive":            {[]string{"Cloud Storage"}, "Apple's cloud file storage."},
	"box":                     {[]string{"Cloud Storage"}, "Enterprise cloud storage and collaboration."},
	"vlc media player":        {[]string{"Media Player"}, "Free open-source cross-platform media player."},
	"vlc":                     {[]string{"Media Player"}, "Free open-source cross-platform media player."},
	"spotify":                 {[]string{"Media", "Music Streaming"}, "Music streaming service."},
	"obs studio":              {[]string{"Media", "Streaming"}, "Free open-source streaming and recording software."},
	"obs":                     {[]string{"Media", "Streaming"}, "Free open-source streaming and recording software."},
	"audacity":                {[]string{"Media", "Audio Editor"}, "Free open-source audio editor."},
	"handbrake":               {[]string{"Media", "Video Encoder"}, "Open-source video transcoder."},
	"figma":                   {[]string{"Design", "UI Design"}, "Collaborative interface design tool."},
	"sketch":                  {[]string{"Design", "UI Design"}, "macOS interface design app."},
	"adobe photoshop":         {[]string{"Design", "Image Editor"}, "Adobe's raster graphics editor."},
	"adobe illustrator":       {[]string{"Design", "Vector Editor"}, "Adobe's vector graphics editor."},
	"gimp":                    {[]string{"Design", "Image Editor"}, "Free open-source raster graphics editor."},
	"inkscape":                {[]string{"Design", "Vector Editor"}, "Free open-source vector graphics editor."},
	"blender":                 {[]string{"Design", "3D Modeling"}, "Free open-source 3D creation suite."},
	"krita":                   {[]string{"Design", "Image Editor"}, "Free open-source digital painting app."},
	"nordvpn":                 {[]string{"Privacy Tool", "VPN"}, "Commercial VPN service."},
	"expressvpn":              {[]string{"Privacy Tool", "VPN"}, "Commercial VPN service."},
	"protonvpn":               {[]string{"Privacy Tool", "VPN"}, "Privacy-focused VPN by Proton."},
	"mullvad vpn":             {[]string{"Privacy Tool", "VPN"}, "Privacy-focused VPN."},
	"tunnelblick":             {[]string{"Privacy Tool", "VPN"}, "Free OpenVPN client for macOS."},
	"openvpn connect":         {[]string{"Privacy Tool", "VPN"}, "OpenVPN's official client."},
	"wireguard":               {[]string{"Privacy Tool", "VPN"}, "Modern open-source VPN protocol."},
	"tor browser":             {[]string{"Privacy Tool", "Browser"}, "Browser routing traffic through the Tor network."},
	"exodus":                  {[]string{"Crypto", "Wallet"}, "Multi-cryptocurrency wallet."},
	"ledger live":             {[]string{"Crypto", "Wallet"}, "Companion app for Ledger hardware wallets."},
	"metamask":                {[]string{"Crypto", "Wallet"}, "Ethereum-compatible browser wallet."},
	"libreoffice":             {[]string{"Productivity", "Office Suite"}, "Free open-source office suite."},
	"openoffice":              {[]string{"Productivity", "Office Suite"}, "Apache's open-source office suite."},
	"adobe acrobat reader":    {[]string{"Productivity", "PDF Reader"}, "Adobe's free PDF reader."},
	"adobe acrobat reader dc": {[]string{"Productivity", "PDF Reader"}, "Adobe's free PDF reader."},
	"foxit reader":            {[]string{"Productivity", "PDF Reader"}, "PDF reader and editor."},
	"filezilla":               {[]string{"Utility", "FTP Client"}, "Free FTP/SFTP client."},
	"cyberduck":               {[]string{"Utility", "FTP Client"}, "Free FTP/SFTP/cloud-storage browser for macOS/Windows."},
	"transmission":            {[]string{"Utility", "BitTorrent"}, "Free open-source BitTorrent client."},
	"qbittorrent":             {[]string{"Utility", "BitTorrent"}, "Free open-source BitTorrent client."},
	"dbeaver":                 {[]string{"Developer Tool", "Database Client"}, "Universal database manager."},
	"tableplus":               {[]string{"Developer Tool", "Database Client"}, "Modern native GUI tool for relational databases."},
	"datagrip":                {[]string{"Developer Tool", "Database Client"}, "JetBrains database IDE."},
}

// normalizePatterns strip version / platform suffixes before lookup. Order
// matters: more specific patterns first (python _NORMALIZE_PATTERNS).
var normalizePatterns = []*regexp.Regexp{
	pyRegexp("(?i)", `\s+release\s+[0-9.]+.*$`),
	pyRegexp("", `\s+[0-9]+\.[0-9.]+.*$`),
	pyRegexp("", `\s*\([^)]*\)\s*$`),
	pyRegexp("(?i)", `\s+(x64|x86|arm64|amd64|i386|i686).*$`),
	pyRegexp("(?i)", `\s+(64|32)-bit.*$`),
	pyRegexp("", `\s+v?[0-9]+(\.[0-9]+)+.*$`),
}

// normalize replaces _normalize: lowercase + strip, then apply every pattern
// (each followed by strip) until the name stops changing.
func normalize(name string) string {
	n := pyStrip(strings.ToLower(name))
	for prev := ""; n != prev; {
		prev = n
		for _, re := range normalizePatterns {
			n = pyStrip(re.ReplaceAllString(n, ""))
		}
	}
	return n
}

// Lookup replaces software_catalog.lookup(name): (categories, description,
// true) for a curated app after normalize, else (nil, "", false). The
// returned slice is a copy. Python's description may be None; Go uses "".
func Lookup(softwareName string) (categories []string, description string, ok bool) {
	if softwareName == "" {
		return nil, "", false
	}
	e, ok := softwareCatalog[normalize(softwareName)]
	if !ok {
		return nil, "", false
	}
	return append([]string(nil), e.categories...), e.description, true
}

// CatalogSize replaces catalog_size(): number of curated entries.
func CatalogSize() int { return len(softwareCatalog) }
