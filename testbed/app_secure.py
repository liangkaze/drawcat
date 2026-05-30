"""Secured Flask application — same functionality with defense modules applied."""

import sqlite3
import os

from flask import Flask, g, jsonify, make_response, render_template, request

from defense.input_filter import InputFilter
from defense.waf import SimpleWAF

app = Flask(__name__)
app.config["SECRET_KEY"] = "insecure-dev-key-12345"

DATABASE = os.path.join(os.path.dirname(__file__), "secure.db")
waf = SimpleWAF()


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


@app.before_request
def apply_waf():
    """Inspect every request through the WAF before processing."""
    client_ip = request.remote_addr or "127.0.0.1"
    query_params = {k: v for k, v in request.args.items()}
    if request.method in ("POST", "PUT", "PATCH"):
        raw_form = request.form.to_dict()
    else:
        raw_form = {}

    allowed, cleaned, alerts = waf.inspect_request(
        method=request.method,
        path=request.path,
        query_params=query_params,
        body=raw_form,
        headers=dict(request.headers),
        client_ip=client_ip,
    )
    if not allowed:
        from flask import abort
        abort(403)
    # Store cleaned data for route handlers
    g.cleaned_form = cleaned
    g.waf_alerts = alerts


@app.after_request
def security_headers(response):
    """Inject security headers into every response."""
    for header, value in SimpleWAF.security_headers().items():
        response.headers.setdefault(header, value)
    return response


# ── Home ──

@app.route("/")
def index():
    return render_template("index.html")


# ── Secured SQL endpoints ───────────────────────────────────────────

@app.route("/search")
def search():
    """SECURED: Parameterized query prevents SQLi."""
    raw_query = request.args.get("q", "")
    cleaned, alerts = InputFilter.filter_request_data({"q": raw_query})
    query = cleaned.get("q", "")

    db = get_db()
    sql = "SELECT * FROM users WHERE username LIKE ?"
    try:
        cur = db.execute(sql, (f"%{query}%",))
        results = cur.fetchall()
    except Exception as e:
        return f"<pre>Error: {e}</pre>", 500

    safe_query = InputFilter.sanitize_html(query)
    html = f"<h2>Search results for: {safe_query}</h2><ul>"
    for row in results:
        html += f"<li>{InputFilter.sanitize_html(str(row[1]))} — {InputFilter.sanitize_html(str(row[2]))}</li>"
    html += "</ul><p><a href='/'>Back</a></p>"
    return html


@app.route("/login", methods=["GET", "POST"])
def login():
    """SECURED: Parameterized query + input validation."""
    error = ""
    if request.method == "POST":
        raw_username = request.form.get("username", "")
        raw_password = request.form.get("password", "")

        if InputFilter.detect_sqli(raw_username) or InputFilter.detect_sqli(raw_password):
            error = "Invalid input detected"
        else:
            username = InputFilter.sanitize_sql(raw_username)
            password = InputFilter.sanitize_sql(raw_password)

            db = get_db()
            sql = "SELECT * FROM users WHERE username=? AND password=?"
            try:
                cur = db.execute(sql, (username, password))
                user = cur.fetchone()
                if user:
                    resp = make_response(
                        f"<h2>Welcome, {InputFilter.sanitize_html(user[1])}!</h2>"
                        f"<p><a href='/'>Back</a></p>"
                    )
                    resp.set_cookie(
                        "session",
                        f"user={username}",
                        httponly=True,
                        secure=True,
                        samesite="Lax",
                    )
                    return resp
                else:
                    error = "Invalid credentials"
            except Exception as e:
                error = f"Error: {e}"
    return render_template("login.html", error=error)


@app.route("/users/<user_id>")
def user_profile(user_id):
    """SECURED: Validates integer + parameterized query."""
    if not InputFilter.validate_integer(user_id):
        return "<h2>Invalid user ID</h2>", 400

    db = get_db()
    sql = "SELECT * FROM users WHERE id = ?"
    try:
        cur = db.execute(sql, (int(user_id),))
        user = cur.fetchone()
        if user:
            return (
                f"<h2>Profile: {InputFilter.sanitize_html(str(user[1]))}</h2>"
                f"<p>Email: {InputFilter.sanitize_html(str(user[2]))}</p>"
                f"<p><a href='/'>Back</a></p>"
            )
        return "<h2>User not found</h2>", 404
    except Exception as e:
        return f"<pre>Error: {e}</pre>", 500


# ── Secured XSS endpoints ───────────────────────────────────────────

@app.route("/greet")
def greet():
    """SECURED: HTML-escaped output prevents XSS."""
    name = request.args.get("name", "Guest")
    safe_name = InputFilter.sanitize_html(name)
    return f"<h2>Hello, {safe_name}!</h2><p><a href='/'>Back</a></p>"


@app.route("/comment", methods=["GET", "POST"])
def comment():
    """SECURED: Parameterized insert + output encoding."""
    db = get_db()
    if request.method == "POST":
        raw_author = request.form.get("author", "Anonymous")
        raw_content = request.form.get("content", "")

        # Sanitize for XSS, validate for SQLi
        author = InputFilter.sanitize_html(raw_author)
        content = InputFilter.sanitize_html(raw_content)

        if InputFilter.detect_sqli(raw_content) or InputFilter.detect_sqli(raw_author):
            return "<h2>Invalid input</h2>", 400

        db.execute(
            "INSERT INTO comments (author, content) VALUES (?, ?)",
            (author, content),
        )
        db.commit()

    comments = db.execute("SELECT * FROM comments ORDER BY id DESC").fetchall()
    html = "<h2>Comments (Secured)</h2>"
    for c in comments:
        html += """
        <div style='border:1px solid #ccc;margin:10px;padding:10px'>
            <strong>{author}</strong>
            <p>{content}</p>
        </div>
        """.format(author=c[1], content=c[2])
    html += """
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
    """SECURED: Whitelist-based redirect validation."""
    target = request.args.get("to", "/")
    # Only allow relative paths
    if target.startswith("/") and "javascript:" not in target.lower():
        return f'<p>Redirecting...</p><script>location.href="{InputFilter.sanitize_html(target)}";</script>'
    return "<p>Invalid redirect target</p>", 400


@app.route("/profile")
def profile_form():
    """SECURED: Uses textContent instead of innerHTML."""
    return """
    <h2>User Settings (Secured)</h2>
    <div id="message"></div>
    <script>
        var name = location.hash.substring(1) || 'Guest';
        var sanitized = name.replace(/[<>]/g, '');
        document.getElementById('message').textContent = 'Hello, ' + sanitized + '!';
    </script>
    <p><a href='/'>Back</a></p>
    """


@app.route("/api/data")
def api_data():
    return jsonify({"status": "ok", "secured": True})


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
    db.commit()
    db.close()
    print("[+] Secure database initialized.")


if __name__ == "__main__":
    init_db()
    print("[+] Starting secured testbed on http://127.0.0.1:5001")
    app.run(host="127.0.0.1", port=5001, debug=False)
