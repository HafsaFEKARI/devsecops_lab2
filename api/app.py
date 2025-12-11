from flask import Flask, request
import sqlite3
import subprocess
import hashlib
import os

app = Flask(__name__)

# Hardcoded secret (vulnérabilité)
SECRET_KEY = "dev-secret-key-12345"

# -----------------------------------------------------
# LOGIN (SQL INJECTION)
# -----------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # SQL Injection volontaire
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)

    result = cursor.fetchone()

    if result:
        return {"status": "success", "user": username}

    return {"status": "error", "message": "Invalid credentials"}

# -----------------------------------------------------
# COMMAND INJECTION (ping)
# -----------------------------------------------------
@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host", "")
    cmd = f"ping -c 1 {host}"   # vulnérable
    output = subprocess.check_output(cmd, shell=True)

    return {"output": output.decode()}

# -----------------------------------------------------
# EVAL (Remote Code Execution)
# -----------------------------------------------------
@app.route("/compute", methods=["POST"])
def compute():
    expression = request.json.get("expression", "1+1")
    result = eval(expression)  # CRITIQUE
    return {"result": result}

# -----------------------------------------------------
# MD5 (hashing faible)
# -----------------------------------------------------
@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password", "admin")
    hashed = hashlib.md5(pwd.encode()).hexdigest()
    return {"md5": hashed}

# -----------------------------------------------------
# FILE READ (Directory traversal)
# -----------------------------------------------------
@app.route("/readfile", methods=["POST"])
def readfile():
    filename = request.json.get("filename", "test.txt")
    with open(filename, "r") as f:
        content = f.read()
    return {"content": content}

# -----------------------------------------------------
# DEBUG ENDPOINT (expose secrets)
# -----------------------------------------------------
@app.route("/debug", methods=["GET"])
def debug():
    return {
        "debug": True,
        "secret_key": SECRET_KEY,
        "environment": dict(os.environ)
    }

# -----------------------------------------------------
# HELLO ENDPOINT
# -----------------------------------------------------
@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Welcome to the DevSecOps vulnerable API"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
