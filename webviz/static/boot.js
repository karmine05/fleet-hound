(function () {
    try {
        var t = localStorage.getItem('theme');
        if (t === 'light' || t === 'dark') {
            document.documentElement.setAttribute('data-theme', t);
            var m = document.querySelector('meta[name="theme-color"]');
            if (m) m.setAttribute('content', t === 'light' ? '#f8f9fa' : '#0c0d10');
        }
    } catch (e) { /* private mode / disabled storage */ }

    // Surface any boot failure on the page. Without this, a single
    // throw before switchView() leaves an empty shell and nothing to
    // report. Runs before the app script so it catches parse-time and
    // DOMContentLoaded errors too.
    function showBootError(message) {
        try {
            var bar = document.getElementById('boot-error');
            if (!bar) return;
            bar.hidden = false;
            bar.textContent = String(message || 'Unknown script error');
        } catch (e) { /* banner itself failed; nothing else to do */ }
    }
    window.addEventListener('error', function (e) {
        if (!e) return;
        var file = String(e.filename || '').split('/').pop() || 'inline script';
        var where = e.lineno ? ' — ' + file + ':' + e.lineno : '';
        showBootError('Script error: ' + (e.message || 'failed to load a resource') + where);
    });
    window.addEventListener('unhandledrejection', function (e) {
        var r = e && e.reason;
        showBootError('Unhandled error: ' + ((r && (r.stack || r.message)) || r));
    });
})();
