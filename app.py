# app.py - WebScanner Flask entrypoint
from flask import Flask, render_template, request, jsonify, redirect, url_for
import scanner, database, os

def create_app():
    app = Flask(__name__, static_folder='app/static', template_folder='app/templates')
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-in-prod')
    database.init_db()

    @app.route('/', methods=['GET', 'POST'])
    def index():
        error = None
        if request.method == 'POST':
            url = request.form.get('url', '').strip()
            if not url:
                error = "Please enter a URL to scan."
            else:
                result = scanner.scan_url(url)
                scan_id = database.save_scan(
                    result['url'],
                    result.get('issues', []),
                    result.get('score', 0),
                    result.get('status_code'),
                )
                return redirect(url_for('results', scan_id=scan_id))
        return render_template('index.html', error=error)

    @app.route('/results/<int:scan_id>')
    def results(scan_id):
        scan = database.get_scan(scan_id)
        if not scan:
            return render_template('index.html', error="Scan not found."), 404
        # Group issues by severity
        grouped = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for issue in scan['issues']:
            sev = issue.get('severity', 'info')
            grouped.setdefault(sev, []).append(issue)
        return render_template('results.html', scan=scan, grouped=grouped)

    @app.route('/history')
    def history():
        scans = database.get_history()
        return render_template('history.html', scans=scans)

    @app.route('/api/scan', methods=['POST'])
    def api_scan():
        data = request.get_json(force=True)
        url = (data or {}).get('url', '').strip()
        if not url:
            return jsonify({"error": "url is required"}), 400
        result = scanner.scan_url(url)
        scan_id = database.save_scan(
            result['url'],
            result.get('issues', []),
            result.get('score', 0),
            result.get('status_code'),
        )
        result['scan_id'] = scan_id
        return jsonify(result)

    @app.route('/api/stats')
    def api_stats():
        return jsonify(database.get_stats())

    @app.route('/api/history')
    def api_history():
        return jsonify(database.get_history())

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=True)
