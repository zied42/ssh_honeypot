"""Flask Web Dashboard for SSH Honeypot Analytics"""

import json
from pathlib import Path
from flask import Flask, render_template
from analyzer.analyzer import HoneypotLogAnalyzer
from config.settings import WEB_HOST, WEB_PORT

app = Flask(__name__, template_folder=".")

ANALYTICS_FILE = Path(__file__).parent.parent / "analytics_report.json"


@app.route("/")
def dashboard():
    try:
        if not ANALYTICS_FILE.exists():
            analyzer = HoneypotLogAnalyzer()
            analyzer.export_to_json(output_file=ANALYTICS_FILE, time_range_hours=720)

        with open(ANALYTICS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        return render_template("s.html", data=data)

    except FileNotFoundError:
        return "<h1>⚠️ Notice: Analytics report generating</h1><p>Please refresh in a moment.</p>", 404
    except Exception:
        return "<h1>⚠️ Error loading dashboard</h1><p>An error occurred while loading analytics data.</p>", 500


if __name__ == "__main__":
    app.run(debug=False, host=WEB_HOST, port=WEB_PORT)
