from pathlib import Path
from flask import Flask, render_template
import json

app = Flask(__name__, template_folder=".")  # templates are in "web"

# Correct path to your JSON file
from pathlib import Path

ANALYTICS_FILE = Path(__file__).parent.parent / "analyzer" / "analytics_report.json"

print("Analytics file:", ANALYTICS_FILE)
print("File exists:", ANALYTICS_FILE.exists())

@app.route('/')
def dashboard():
    try:
        with open(ANALYTICS_FILE, 'r') as f:
            data = json.load(f)
        return render_template('s.html', data=data)
    except FileNotFoundError:
        return f"<h1>⚠️ Error: Analytics file not found</h1><p>Looking for: {ANALYTICS_FILE.absolute()}</p>", 404
    except Exception as e:
        return f"<h1>Error loading data:</h1><p>{e}</p>", 500

if __name__ == '__main__':
    print(f"Analytics file: {ANALYTICS_FILE.absolute()}")
    print(f"File exists: {ANALYTICS_FILE.exists()}")
    app.run(debug=True, host='0.0.0.0', port=5000)
