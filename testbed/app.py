"""Deliberately vulnerable Flask application for testing scanners and defenses."""

import sqlite3
import os

from flask import Flask, g, jsonify, make_response, render_template, request

app = Flask(__name__)
app.config["SECRET_KEY"] = "insecure-dev-key-12345"

DATABASE = os.path.join(os.path.dirname(__file__), "test.db")


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


# ── Home ────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── SQL Injection vulnerabilities ───────────────────────────────────

@app.route("/search")
def search():
    """VULNERABLE: Error-based SQLi via GET parameter 'q'."""
    query = request.args.get("q", "")
    db = get_db()
    sql = f"SELECT * FROM users WHERE username LIKE '%{query}%'"
    try:
        cur = db.execute(sql)
        results = cur.fetchall()
    except Exception as e:
        return f"<pre>Database Error: {e}\n\nQuery: {sql}</pre>", 500
    html = f"<h2>Search results for: {query}</h2><ul>"
    for row in results:
        html += f"<li>{row[1]} — {row[2]}</li>"
    html += "</ul><p><a href='/'>Back</a></p>"
    return html


@app.route("/login", methods=["GET", "POST"])
def login():
    """VULNERABLE: Boolean-based SQLi in login form."""
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        sql = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            cur = db.execute(sql)
            user = cur.fetchone()
            if user:
                resp = make_response(
                    f"<h2>Welcome, {user[1]}!</h2><p><a href='/'>Back</a></p>"
                )
                resp.set_cookie("session", f"user={username}", httponly=False, secure=False)
                return resp
            else:
                error = "Invalid credentials"
        except Exception as e:
            error = f"Error: {e}"
    return render_template("login.html", error=error)


@app.route("/users/<user_id>")
def user_profile(user_id):
    """VULNERABLE: SQLi via URL path parameter."""
    db = get_db()
    sql = f"SELECT * FROM users WHERE id = {user_id}"
    try:
        cur = db.execute(sql)
        user = cur.fetchone()
        if user:
            return f"<h2>Profile: {user[1]}</h2><p>Email: {user[2]}</p><p><a href='/'>Back</a></p>"
        return "<h2>User not found</h2>", 404
    except Exception as e:
        return f"<pre>Error: {e}</pre>", 500


# ── XSS vulnerabilities ─────────────────────────────────────────────

@app.route("/greet")
def greet():
    """VULNERABLE: Reflected XSS via GET parameter 'name'."""
    name = request.args.get("name", "Guest")
    return f"<h2>Hello, {name}!</h2><p><a href='/'>Back</a></p>"


@app.route("/comment", methods=["GET", "POST"])
def comment():
    """VULNERABLE: Stored XSS — comments are rendered without escaping."""
    db = get_db()
    if request.method == "POST":
        author = request.form.get("author", "Anonymous")
        content = request.form.get("content", "")
        db.execute(
            f"INSERT INTO comments (author, content) VALUES ('{author}', '{content}')"
        )
        db.commit()
    comments = db.execute("SELECT * FROM comments ORDER BY id DESC").fetchall()
    html = "<h2>Comments</h2>"
    for c in comments:
        html += f"""
        <div style='border:1px solid #ccc;margin:10px;padding:10px'>
            <strong>{c[1]}</strong>
            <p>{c[2]}</p>
        </div>
        """
    html += f"""
    <h3>Add Comment</h3>
    <form method='post'>
        <input name='author' placeholder='Name'><br>
        <textarea name='content' placeholder='Comment'></textarea><br>
        <button type='submit'>Post</button>
    </form>
    <p><a href='/'>Back</a></p>
    """
    return html


@app.route("/redirect")
def unsafe_redirect():
    """VULNERABLE: Open redirect with XSS via javascript: URL."""
    target = request.args.get("to", "/")
    return f'<p>Redirecting...</p><script>location.href="{target}";</script>'


@app.route("/profile")
def profile_form():
    """DOM-based XSS via URL hash used in client-side script."""
    return """
    <h2>User Settings</h2>
    <div id="message"></div>
    <script>
        var name = location.hash.substring(1) || 'Guest';
        document.getElementById('message').innerHTML = '<p>Hello, ' + name + '!</p>';
    </script>
    <p><a href='/'>Back</a></p>
    """


# ── API ─────────────────────────────────────────────────────────────

@app.route("/api/data")
def api_data():
    """JSON API endpoint for scanner to discover."""
    return jsonify({"status": "ok", "users": 5, "comments": 10})


# ── Init / run ──────────────────────────────────────────────────────

def init_db():
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    db = sqlite3.connect(DATABASE)
    db.execute("DROP TABLE IF EXISTS users")
    db.execute("DROP TABLE IF EXISTS comments")
    db.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT)"
    )
    db.execute(
        "CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, author TEXT, content TEXT)"
    )
    db.execute("INSERT INTO users VALUES (1, 'admin', 'admin@test.local', 'admin123')")
    db.execute("INSERT INTO users VALUES (2, 'alice', 'alice@test.local', 'pass1')")
    db.execute("INSERT INTO users VALUES (3, 'bob', 'bob@test.local', 'pass2')")
    db.execute("INSERT INTO comments VALUES (1, 'Alice', 'Great site!')")
    db.commit()
    db.close()
    print("[+] Test database initialized with sample data.")


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
