from __future__ import annotations

import html

from flask import Flask, jsonify, render_template, request

from waf import SimulatedWAF

app = Flask(__name__)
waf = SimulatedWAF()


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/submit")
def submit():
    data = request.get_json(silent=True) or {}
    user_input = str(data.get("input", ""))

    blocked, reason = waf.inspect(user_input)

    # Deliberately weak output handling to illustrate defensive testing outcomes.
    weak_render = user_input
    safe_render = html.escape(user_input)

    return jsonify(
        {
            "blocked": blocked,
            "reason": reason,
            "weak_render_preview": weak_render,
            "safe_render_preview": safe_render,
        }
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
