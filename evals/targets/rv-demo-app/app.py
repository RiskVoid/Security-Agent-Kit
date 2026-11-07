"""RiskVoid benchmark target: small Flask service. Deliberately insecure test fixture. Never deploy."""
import sqlite3, subprocess, yaml
from flask import Flask, request

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-123"


@app.route("/user")
def user():
    name = request.args.get("name", "")
    db = sqlite3.connect("app.db")
    return str(db.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/config", methods=["POST"])
def config():
    return str(yaml.load(request.data, Loader=yaml.Loader))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
