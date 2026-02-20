import os
import time
from flask import Flask, redirect, render_template, request, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from db import init_db, get_db

app = Flask(__name__)
app.secret_key = "IGIVEUP"  # keep your secret in env for production

UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# short-lived unlocked keys cache removed (server no longer stores private keys)
UNLOCK_TTL_SECONDS = 300


# -------------------------
# Utility decorators
# -------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT is_admin FROM users WHERE id = ?", (session["user_id"],))
        user = cur.fetchone()
        conn.close()
        if not user or user["is_admin"] == 0:
            return "Access denied: admin only", 403
        return f(*args, **kwargs)
    return decorated_function


# -------------------------
# Home / Search / Pagination
# -------------------------
@app.route("/")
def home():
    query = request.args.get("q", "").strip()
    page = int(request.args.get("page", 1) or 1)
    ads_per_page = 4
    offset = (page - 1) * ads_per_page

    conn = get_db()
    cur = conn.cursor()

    if query:
        cur.execute("SELECT COUNT(*) FROM ads WHERE LOWER(title) LIKE ?", (f"%{query.lower()}%",))
    else:
        cur.execute("SELECT COUNT(*) FROM ads")
    total_ads = cur.fetchone()[0]
    total_pages = (total_ads + ads_per_page - 1) // ads_per_page

    if query:
        cur.execute(
            """
            SELECT ads.*, users.username
            FROM ads
            JOIN users ON ads.user_id = users.id
            WHERE LOWER(ads.title) LIKE ?
            ORDER BY ads.id DESC
            LIMIT ? OFFSET ?
            """,
            (f"%{query.lower()}%", ads_per_page, offset),
        )
    else:
        cur.execute(
            """
            SELECT ads.*, users.username
            FROM ads
            JOIN users ON ads.user_id = users.id
            ORDER BY ads.id DESC
            LIMIT ? OFFSET ?
            """,
            (ads_per_page, offset),
        )

    ads = cur.fetchall()
    conn.close()

    return render_template("index.html", ads=ads, query=query, page=page, total_pages=total_pages)


# -------------------------
# Profile / Account
# -------------------------
@app.route("/profile")
@login_required
def profile():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ads WHERE user_id = ? ORDER BY id DESC", (session["user_id"],))
    user_ads = cur.fetchall()

    cur.execute("SELECT about FROM users WHERE id = ?", (session["user_id"],))
    row = cur.fetchone()
    about = row["about"] if row and "about" in row.keys() else None
    conn.close()

    return render_template("profile.html", ads=user_ads, about=about)


@app.route("/edit_profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    conn = get_db()
    cur = conn.cursor()

    if request.method == "POST":
        about = request.form.get("about")
        cur.execute("UPDATE users SET about = ? WHERE id = ?", (about, session["user_id"]))
        conn.commit()
        conn.close()
        return redirect(url_for("profile"))

    cur.execute("SELECT about FROM users WHERE id = ?", (session["user_id"],))
    user = cur.fetchone()
    conn.close()
    return render_template("edit_profile.html", about=user["about"] if user and "about" in user.keys() else "")


# -------------------------
# Admin dashboard and actions
# -------------------------
@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_db()
    cur = conn.cursor()
    # users with their average rating and review count
    cur.execute(
        """
        SELECT u.id, u.username, u.is_admin, u.about,
               IFNULL(ROUND(AVG(r.rating), 1), 'No ratings') AS avg_rating,
               COUNT(r.id) AS review_count
        FROM users u
        LEFT JOIN ratings r ON u.id = r.seller_id
        GROUP BY u.id
        ORDER BY u.id ASC
        """
    )
    users = cur.fetchall()

    # all ads
    cur.execute("SELECT ads.*, users.username FROM ads JOIN users ON ads.user_id = users.id ORDER BY ads.id DESC")
    ads = cur.fetchall()
    conn.close()
    return render_template("admin_dashboard.html", users=users, ads=ads)


@app.route("/admin/delete_reviews/<int:user_id>", methods=["POST"])
@admin_required
def delete_user_reviews(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM ratings WHERE seller_id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete_about/<int:user_id>", methods=["POST"])
@admin_required
def delete_user_about(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET about = NULL WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_dashboard"))


# -------------------------
# Ads CRUD
# -------------------------
@app.route("/create_ad", methods=["GET", "POST"])
@login_required
def create_ad():
    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        image_file = request.files.get("image")

        filename = None
        if image_file and image_file.filename:
            filename = image_file.filename
            image_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            image_file.save(image_path)

        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO ads (title, description, image, user_id) VALUES (?, ?, ?, ?)",
                    (title, description, filename, session["user_id"]))
        conn.commit()
        conn.close()
        return redirect(url_for("home"))
    return render_template("create_ad.html")


@app.route("/edit_ad/<int:ad_id>", methods=["GET", "POST"])
@login_required
def edit_ad(ad_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ads WHERE id = ? AND user_id = ?", (ad_id, session["user_id"]))
    ad = cur.fetchone()

    if ad is None:
        conn.close()
        return "Ad not found or not authorized", 404

    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        remove_image = request.form.get("remove_image")
        image_file = request.files.get("image")

        filename = ad["image"]
        if remove_image:
            if filename:
                try:
                    os.remove(os.path.join(app.config["UPLOAD_FOLDER"], filename))
                except FileNotFoundError:
                    pass
            filename = None
        elif image_file and image_file.filename:
            filename = image_file.filename
            image_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            image_file.save(image_path)

        cur.execute("UPDATE ads SET title = ?, description = ?, image = ? WHERE id = ?",
                    (title, description, filename, ad_id))
        conn.commit()
        conn.close()
        return redirect(url_for("profile"))

    conn.close()
    return render_template("edit_ad.html", ad=ad)


@app.route("/delete_ad/<int:ad_id>", methods=["POST"])
@login_required
def delete_ad(ad_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM ads WHERE id = ? AND user_id = ?", (ad_id, session["user_id"]))
    conn.commit()
    conn.close()
    return redirect(url_for("profile"))


@app.route("/admin/delete_ad/<int:ad_id>", methods=["POST"])
@admin_required
def delete_ad_m(ad_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM ads WHERE id = ?", (ad_id,))
    if cur.rowcount == 0:
        conn.close()
        return "Item not found or already deleted", 404
    conn.commit()
    conn.close()
    return redirect(url_for("admin_dashboard"))


# -------------------------
# Registration / Login / Logout
# -------------------------
@app.route("/create_account", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        password_hash = generate_password_hash(password)

        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
            conn.commit()
        except Exception:
            conn.close()
            return render_template("create_account.html", error="Username exists already")
        conn.close()
        return redirect(url_for("login"))
    return render_template("create_account.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        conn.close()

        if user is None or not check_password_hash(user["password_hash"], password):
            return render_template("login.html", error="Invalid username or password.")

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("home"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# -------------------------
# Static informational pages
# -------------------------
@app.route("/about")
def about():
    return render_template("about.html")


# -------------------------
# Chats & Messages
# -------------------------
@app.route("/my_chats")
@login_required
def my_chats():
    # Show list of ads and other users you've had messages with
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT DISTINCT
          CASE WHEN m.sender_id = ? THEN m.recipient_id ELSE m.sender_id END AS other_id,
          u.username AS other_user,
          a.id AS ad_id,
          a.title AS ad_title
        FROM messages m
        LEFT JOIN ads a ON m.ad_id = a.id
        LEFT JOIN users u ON u.id = CASE WHEN m.sender_id = ? THEN m.recipient_id ELSE m.sender_id END
        WHERE ? IN (m.sender_id, m.recipient_id)
        ORDER BY a.id DESC
        """,
        (session["user_id"], session["user_id"], session["user_id"]),
    )
    chats = cur.fetchall()
    conn.close()
    return render_template("my_chats.html", chats=chats)


@app.route("/message", methods=["GET", "POST"])
@app.route("/message/<int:ad_id>", methods=["GET", "POST"])
@login_required
def message(ad_id=None):
    conn = get_db()
    cur = conn.cursor()

    ad = None
    recipient_id = None
    ad_title = "Direct Message"

    # case 1 - message from ad listing
    if ad_id is not None:
        cur.execute("SELECT ads.*, users.username FROM ads JOIN users ON ads.user_id = users.id WHERE ads.id = ?", (ad_id,))
        ad = cur.fetchone()
        if ad:
            recipient_id = ad["user_id"]
            ad_title = ad["title"]

    # case 2 - message from user profile
    user_id_param = request.args.get("user_id")
    if user_id_param and not recipient_id:
        cur.execute("SELECT id, username FROM users WHERE id = ?", (user_id_param,))
        user = cur.fetchone()
        if user:
            recipient_id = user["id"]
            ad_title = f"Chat with {user['username']}"

    if request.method == "POST":
        content = request.form.get("message")
        if recipient_id is None:
            conn.close()
            return "Error: recipient not found", 400
        if ad_id is None:
            ad_id = 0
        cur.execute("INSERT INTO messages (ad_id, sender_id, recipient_id, content) VALUES (?, ?, ?, ?)",
                    (ad_id, session["user_id"], recipient_id, content))
        conn.commit()

    # fetch messages
    if recipient_id is not None:
        cur.execute(
            """
            SELECT m.*, u.username AS sender_name
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id = ? AND m.recipient_id = ?)
               OR (m.sender_id = ? AND m.recipient_id = ?)
            ORDER BY m.created_at ASC
            """,
            (session["user_id"], recipient_id, recipient_id, session["user_id"]),
        )
        messages = cur.fetchall()
    else:
        messages = []

    conn.close()
    return render_template("messages.html", ad={"title": ad_title}, messages=messages)


@app.route("/contact_user/<int:user_id>", methods=["GET", "POST"])
@login_required
def contact_user(user_id):
    # prevent messaging yourself
    if user_id == session["user_id"]:
        return redirect(url_for("profile"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    recipient = cur.fetchone()
    if not recipient:
        conn.close()
        return "User not found", 404

    if request.method == "POST":
        content = request.form.get("message")
        cur.execute("INSERT INTO messages (ad_id, sender_id, recipient_id, content) VALUES (NULL, ?, ?, ?)",
                    (session["user_id"], user_id, content))
        conn.commit()

    cur.execute(
        """
        SELECT m.*, u.username AS sender_name
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? AND m.recipient_id = ?)
           OR (m.sender_id = ? AND m.recipient_id = ?)
        ORDER BY m.created_at ASC
        """,
        (session["user_id"], user_id, user_id, session["user_id"]),
    )
    messages = cur.fetchall()
    conn.close()
    return render_template("messages.html", ad=None, messages=messages, recipient=recipient)


# -------------------------
# Secure messaging (client-side encryption/decryption)
# -------------------------
@app.route("/secure_message/<int:recipient_id>", methods=["GET", "POST"])
@login_required
def secure_message(recipient_id):
    """
    Server no longer decrypts messages. This route:
      - ensures recipient exists and has a public key
      - returns the encrypted messages (is_encrypted=1) between the users so the client can decrypt locally
      - supplies recipient public key to the client so they can encrypt a new message
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT username, pgp_public_key FROM users WHERE id = ?", (recipient_id,))
    recipient = cur.fetchone()
    if not recipient:
        conn.close()
        return "Recipient not found", 404

    # get encrypted messages between the two users (is_encrypted flagged)
    cur.execute(
        """
        SELECT m.id, m.content, m.is_encrypted, m.sender_id, u.username AS sender_name, m.created_at
        FROM messages m JOIN users u ON m.sender_id = u.id
        WHERE ((m.sender_id = ? AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = ?))
          AND m.is_encrypted = 1
        ORDER BY m.created_at ASC
        """,
        (session["user_id"], recipient_id, recipient_id, session["user_id"]),
    )
    msgs = cur.fetchall()
    conn.close()

    # Pass encrypted messages and recipient public key to template � client handles decryption and encryption
    return render_template("secure_message.html", recipient=recipient, messages=msgs)


@app.route("/download_public_key/<int:user_id>")
def download_public_key(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT pgp_public_key FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row or not row["pgp_public_key"]:
        return "No public key available", 404
    pub = row["pgp_public_key"]
    return (pub, 200, {
        "Content-Type": "application/pgp-keys",
        "Content-Disposition": f'attachment; filename="user_{user_id}_public.asc"'
    })


@app.route("/upload_pubkey", methods=["POST"])
@login_required
def upload_pubkey():
    # accepts 'pubkey' form field (armored)
    pubkey = request.form.get("pubkey") or (request.json and request.json.get("pubkey"))
    if not pubkey:
        return jsonify({"error": "no pubkey"}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET pgp_public_key = ? WHERE id = ?", (pubkey, session["user_id"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/send_encrypted", methods=["POST"])
@login_required
def send_encrypted():
    recipient_id = request.form.get("recipient_id") or (request.json and request.json.get("recipient_id"))
    content = request.form.get("content") or (request.json and request.json.get("content"))
    ad_id = request.form.get("ad_id") or (request.json and request.json.get("ad_id")) or None

    if not recipient_id or not content:
        return jsonify({"error": "missing fields"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO messages (ad_id, sender_id, recipient_id, content, is_encrypted)
        VALUES (?, ?, ?, ?, 1)
        """,
        (ad_id, session["user_id"], int(recipient_id), content),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/fetch_messages", methods=["GET"])
@login_required
def fetch_messages():
    other = request.args.get("other_id")
    if not other:
        return jsonify({"error": "other_id required"}), 400
    user_id = session["user_id"]
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT m.id, m.content, m.is_encrypted, m.sender_id, u.username AS sender_name, m.created_at
        FROM messages m JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = ?)
        ORDER BY m.created_at ASC
        """,
        (user_id, other, other, user_id),
    )
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append({
            "id": r["id"],
            "content": r["content"],
            "is_encrypted": r["is_encrypted"],
            "sender_id": r["sender_id"],
            "sender_name": r["sender_name"],
            "created_at": r["created_at"]
        })
    return jsonify(out)


# -------------------------
# Ad view and user profile view
# -------------------------
@app.route("/ad/<int:ad_id>")
def view_ad(ad_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT ads.*, users.username, users.about,
               IFNULL(ROUND(AVG(ratings.rating), 1), 'No ratings') AS avg_rating
        FROM ads
        JOIN users ON ads.user_id = users.id
        LEFT JOIN ratings ON ads.user_id = ratings.seller_id
        WHERE ads.id = ?
        GROUP BY ads.id
        """,
        (ad_id,),
    )
    ad = cur.fetchone()

    cur.execute(
        """
        SELECT r.rating, r.review, u.username AS reviewer
        FROM ratings r
        JOIN users u ON r.rater_id = u.id
        WHERE r.seller_id = (SELECT user_id FROM ads WHERE id = ?)
        ORDER BY r.id DESC
        """,
        (ad_id,),
    )
    reviews = cur.fetchall()
    conn.close()

    if ad is None:
        return "Ad not found", 404
    return render_template("view_ad.html", ad=ad, reviews=reviews)


@app.route("/user/<int:user_id>")
def view_user(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT users.id, users.username, users.about,
               IFNULL(ROUND(AVG(r.rating), 1), 'No ratings') AS avg_rating
        FROM users
        LEFT JOIN ratings r ON users.id = r.seller_id
        WHERE users.id = ?
        GROUP BY users.id
        """,
        (user_id,),
    )
    user = cur.fetchone()
    if not user:
        conn.close()
        return "User not found", 404

    cur.execute(
        """
        SELECT r.rating, r.review, u.username AS reviewer
        FROM ratings r
        JOIN users u ON r.rater_id = u.id
        WHERE r.seller_id = ?
        ORDER BY r.id DESC
        """,
        (user_id,),
    )
    reviews = cur.fetchall()
    conn.close()
    return render_template("user_profile.html", user=user, reviews=reviews)


# -------------------------
# Rating a seller
# -------------------------
@app.route("/rate/<int:seller_id>", methods=["GET", "POST"])
@login_required
def rate_seller(seller_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (seller_id,))
    seller = cur.fetchone()
    if not seller:
        conn.close()
        return "User not found", 404

    if request.method == "POST":
        rating = int(request.form.get("rating"))
        review = (request.form.get("review") or "")[:50]
        cur.execute("INSERT INTO ratings (seller_id, rater_id, rating, review) VALUES (?, ?, ?, ?)",
                    (seller_id, session["user_id"], rating, review))
        conn.commit()
        conn.close()
        ad_id = request.args.get("ad_id")
        if ad_id:
            return redirect(url_for("view_ad", ad_id=ad_id))
        else:
            return redirect(url_for("view_user", user_id=seller_id))

    conn.close()
    return render_template("rate.html", seller_id=seller_id, seller=seller)


# -------------------------
# Start app
# -------------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
