import os
import time
from enc_utils import encrypt_bytes, decrypt_bytes
from db import ensure_pgp_columns, init_db, get_db
from pgp_utils import decrypt_message_with_priv, encrypt_message_with_pub, generate_ecc_keypair, parse_privkey, parse_pubkey
from flask import Flask, redirect, render_template, request, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

app.secret_key = "IGIVEUP" # this signs 'user_id' which is created at login

_unlocked_keys = {}

UNLOCK_TTL_SECONDS = 300 # 5 min session

UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER # setting 


@app.route("/")
def home():
    query = request.args.get("q", "") # if user visits - ?q=guitar then query == 'guitar'
    page = int(request.args.get("page", 1))
    ads_per_page = 4
    offset = (page - 1) * ads_per_page

    conn = get_db()
    cur = conn.cursor()

    if query:
        cur.execute("SELECT COUNT(*) FROM ads WHERE title LIKE ?", # 'get all ads where the title is LIKE something' 'something' is query==
                    (f"%{query.lower()}%",)) # if 'query' is 'guitar' this becomes '%guitar%' sql - % means anything

    else:
        cur.execute("SELECT COUNT(*) FROM ads") # read rows from 'ads sheet'

    total_ads = cur.fetchone()[0]
    total_pages = (total_ads + ads_per_page - 1) // ads_per_page

    if query:
        search_term = f"%{query.lower()}%"
        cur.execute("""
        SELECT ads.*, users.username
        FROM ads
        JOIN users ON ads.user_id = users.id
        WHERE LOWER (ads.title) LIKE ?
        ORDER BY ads.id DESC
        LIMIT ? OFFSET ?
    """, (f"%{query}%", ads_per_page, offset))
    else:
        cur.execute("""
        SELECT ads.*, users.username
        FROM ads
        JOIN users ON ads.user_id = users.id
        ORDER BY ads.id DESC
        LIMIT ? OFFSET ?
    """, (ads_per_page, offset))

    ads = cur.fetchall()
    conn.close()

    return render_template(
        "index.html",
        ads=ads,
        query=query,
        page=page,
        total_pages=total_pages
    )

    return render_template("index.html", ads=ads, query=query)

@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ads WHERE user_id = ? ORDER BY id DESC", (session["user_id"],))
    user_ads = cur.fetchall()

    cur.execute("SELECT about FROM users WHERE id = ?", (session["user_id"],))
    about = cur.fetchone()["about"]
    conn.close()

    return render_template("profile.html", ads=user_ads, about=about)

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

@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""SELECT u.id, u.username, u.is_admin, u.about, IFNULL(ROUND(AVG(r.rating), 1), 'No ratings') 
    AS avg_rating, COUNT(r.id) AS review_count
    FROM users u
    LEFT JOIN ratings r ON u.id = r.seller_id
    GROUP BY u.id
    ORDER BY u.id ASC""")
    users = cur.fetchall()

    cur.execute("SELECT ads.*, users.username FROM ads JOIN users ON ads.user_id = users.id ORDER BY ads.id DESC")
    ads = cur.fetchall()
    conn.close()
    return render_template("admin_dashboard.html", users=users, ads=ads)

@app.route("/admin/delete_reviews/<int:user_id>", methods=["POST"])
@admin_required
def delete_user_reviews(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM ratings WHERE seller_id = ?", (user_id))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/delete_about/<int:user_id>", methods=["POST"])
@admin_required
def delete_user_about(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET about = NULL WHERE id = ?", (user_id))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_dashboard"))

@app.route("/edit_ad/<int:ad_id>", methods=["GET", "POST"])
def edit_ad(ad_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

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
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                except FileNotFoundError:
                    pass
            filename = None

        elif image_file and image_file.filename:
            filename = image_file.filename
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)


        cur.execute("UPDATE ads SET title = ?, description = ?, image = ? WHERE id = ?", (title, description, filename, ad_id))
        conn.commit()
        conn.close()
        return redirect(url_for("profile"))

    conn.close()
    return render_template("edit_ad.html", ad=ad)

@app.route("/delete_ad/<int:ad_id>", methods=["POST"])
def delete_ad(ad_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

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
            return render_template("create_account.html", error="Username exists already") # route 'error' linked to register function - any value after /register

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

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/my_chats")
def my_chats():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""SELECT DISTINCT ads.id AS ad_id, ads.title AS ad_title, u.username AS other_user FROM messages m JOIN ads ON m.ad_id = ads.id JOIN
    users u ON (CASE WHEN m.sender_id = ? THEN m.recipient_id = u.id ELSE m.sender_id = u.id NED) WHERE ? IN (m.sender_id, m.recipient_id) ORDER BY
    ads.id DESC""", (session["user_id"], session["user_id"]))
    chats = cur.fetchall()
    conn.close()

    return render_template("my_chats.html", chats=chats)

@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    if "user_id" not in session:
        return redirect(url_for("login"))

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

    return render_template("edit_profile.html", about=user["about"] if user else "")

@app.route("/ad/<int:ad_id>")
def view_ad(ad_id):
    conn = get_db()
    cur = conn.cursor()

    cur.execute(""" SELECT ads.*, users.username, users.about,
        IFNULL(ROUND(AVG(ratings.rating), 1), 'No ratings') AS avg_rating
        FROM ads
        JOIN users ON ads.user_id = users.id
        LEFT JOIN ratings ON ads.user_id = ratings.seller_id
        WHERE ads.id = ?
        GROUP BY ads.id
   """, (ad_id,))
    ad = cur.fetchone()

    cur.execute(""" SELECT r.rating, r.review, u.username AS reviewer
        FROM ratings r
        JOIN users u ON r.rater_id = u.id
        WHERE r.seller_id = (SELECT user_id FROM ads WHERE id = ?)
        ORDER BY r.id DESC""", (ad_id,))
    reviews = cur.fetchall()
    conn.close()

    if ad is None:
        return "Ad not found", 404

    return render_template("view_ad.html", ad=ad, reviews=reviews)

@app.route("/user/<int:user_id>")
def view_user(user_id):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT users.id, users.username, users.about,
               IFNULL(ROUND(AVG(r.rating), 1), 'No ratings') AS avg_rating
        FROM users
        LEFT JOIN ratings r ON users.id = r.seller_id
        WHERE users.id = ?
        GROUP BY users.id
    """, (user_id,))
    user = cur.fetchone()

    if not user:
        conn.close()
        return "User not found", 404

 # get reviews
    cur.execute("""
        SELECT r.rating, r.review, u.username AS reviewer
        FROM ratings r
        JOIN users u ON r.rater_id = u.id
        WHERE r.seller_id = ?
        ORDER BY r.id DESC
    """, (user_id,))
    reviews = cur.fetchall()
    conn.close()

    return render_template("user_profile.html", user=user, reviews=reviews)


@app.route("/message/<int:ad_id>", methods=["GET", "POST"])
@app.route("/message", methods=["GET", "POST"])
def message(ad_id=None):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()

    ad = None
    recipient_id = None
    ad_title = "Direct Message"

    # case 1 - message from ad listing
    if ad_id is not None:
        cur.execute("SELECT ads.*, users.username FROM ads JOIN users ON ads.user_id = users.id WHERE ads.id = ?", (ad_id,))
        ad = cur.fetchone() # chooses next row available from result set
        if ad:
            recipient_id = ad["user_id"] # author
            ad_title = ad["title"]

    # case 2 - message from user profile
    user_id = request.args.get("user_id")
    if user_id and not recipient_id:
        cur.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
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

        cur.execute(""" INSERT INTO messages (ad_id, sender_id, recipient_id, content) VALUES (?, ?, ?, ?)""", (ad_id, session["user_id"], recipient_id, content))
        conn.commit()

    if recipient_id is not None:
        cur.execute("""
            SELECT m.*, u.username AS sender_name
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id = ? AND m.recipient_id = ?)
               OR (m.sender_id = ? AND m.recipient_id = ?)
            ORDER BY m.created_at ASC
        """, (session["user_id"], recipient_id, recipient_id, session["user_id"]))
        messages = cur.fetchall()
    else:
        messages = []

    conn.close()
    return render_template("messages.html", ad={"title": ad_title}, messages=messages)

@app.route("/secure_message/<int:recipient_id>", methods=["GET", "POST"])
def secure_message(recipient_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()

    # fetch recipient username and public key (armored)
    cur.execute("SELECT username, pgp_public_key FROM users WHERE id=?", (recipient_id,))
    recipient = cur.fetchone()
    if not recipient or not recipient["pgp_public_key"]:
        conn.close()
        return "Recipient not found or no PGP key available", 404

    # fetch current user's encrypted private key pieces
    cur.execute("SELECT pgp_private_key_encrypted, pgp_key_salt, pgp_key_nonce FROM users WHERE id=?", (session["user_id"],))
    row = cur.fetchone()
    if not row or not row["pgp_private_key_encrypted"]:
        conn.close()
        return "You must generate and store your key first (go to settings)", 400

    user_id = session["user_id"]

    # cleanup expired unlocked cache entry if present
    now = time.time()
    entry = _unlocked_keys.get(user_id)
    if entry and entry.get("expires", 0) < now:
        del _unlocked_keys[user_id]
        entry = None

    error = None
    unlocked_privkey_obj = None

    # If user submitted passphrase, try to decrypt and unlock for a short period
    if request.method == "POST" and request.form.get("action") == "unlock":
        passphrase = request.form.get("passphrase", "")
        try:
            privarm_bytes = decrypt_bytes(row['pgp_private_key_encrypted'], passphrase, row['pgp_key_salt'], row['pgp_key_nonce'])
            privarm = privarm_bytes.decode("utf-8")
            # parse to pgpy object (pgp_utils.parse_privkey must exist)
            unlocked_privkey_obj = parse_privkey(privarm)

            # store decrypted armored private key in the in-memory cache for a short time
            _unlocked_keys[user_id] = {"privarm": privarm, "expires": now + UNLOCK_TTL_SECONDS}
        except Exception:
            error = "Wrong passphrase or decryption error"

    # If user submitted a message to send - require unlocking (either just unlocked OR already unlocked)
    if request.method == "POST" and request.form.get("action") == "send":
        # ensure unlocked key is present (either from recent unlock or from above action)
        entry = _unlocked_keys.get(user_id)
        if not entry or entry.get("expires", 0) < now:
            # not unlocked
            conn.close()
            return render_template("secure_message.html", recipient=recipient, messages=[], unlocked=False, error="Please unlock your PGP key first (enter passphrase).")

        # create encryption using recipient public key - don't need the sender privkey to encrypt
        content = request.form.get("message", "")
        if not content:
            # nothing to send
            pass
        else:
            # encrypt with recipient public key
            # make sure parse_pubkey handles armored string -> pgpy.PGPKey
            pubkey = parse_pubkey(recipient["pgp_public_key"])
            encrypted_content = encrypt_message(pubkey, content)

            cur.execute("""INSERT INTO messages (ad_id, sender_id, recipient_id, content, is_encrypted) VALUES (NULL, ?, ?, ?, 1)""",
                        (user_id, recipient_id, encrypted_content))
            conn.commit()

    # fetch encrypted messages between these two users (only encrypted ones for secure chat)
    cur.execute("""SELECT m.*, u.username AS sender_name
                   FROM messages m
                   JOIN users u ON m.sender_id = u.id
                   WHERE ((m.sender_id = ? AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = ?))
                     AND m.is_encrypted = 1
                   ORDER BY m.created_at ASC""",
                (user_id, recipient_id, recipient_id, user_id))
    messages = cur.fetchall()

    # If unlocked, decrypt messages for display using the unlocked key from cache
    entry = _unlocked_keys.get(user_id)
    unlocked = False
    if entry and entry.get("expires", 0) > now:
        unlocked = True
        try:
            privarm = entry["privarm"]
            privkey = parse_privkey(privarm)
            # decrypt each message
            decrypted_messages = []
            for m in messages:
                try:
                    # decrypt_message should accept a pgpy.PGPKey (privkey) or adapt accordingly
                    plaintext = decrypt_message(privkey, m["content"])
                    # create a shallow copy-like dict for display
                    decrypted_messages.append({"sender_name": m["sender_name"], "content": plaintext, "created_at": m["created_at"]})
                except Exception as e:
                    decrypted_messages.append({"sender_name": m["sender_name"], "content": f"[Decryption error: {e}]",
                                               "created_at": m["created_at"]})
            messages = decrypted_messages
        except Exception as e:
            # parsing/decrypt failure => treat as locked
            unlocked = False
            error = "Error decrypting with unlocked key."

    conn.close()

    return render_template("secure_message.html",
                           recipient=recipient,
                           messages=messages,
                           unlocked=unlocked,
                           unlock_ttl=UNLOCK_TTL_SECONDS,
                           error=error)

@app.route("/contact_user/<int:user_id>", methods=["GET", "POST"])
def contact_user(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    # prevent messaging yourself
    if user_id == session["user_id"]:
        return redirect(url_for("profile"))

    conn = get_db()
    cur = conn.cursor()

    # recipient info
    cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    recipient = cur.fetchone()
    if not recipient:
        conn.close()
        return "User not found", 404

    if request.method == "POST":
        content = request.form.get("message")
        cur.execute("""INSERT INTO messages (ad_id, sender_id, recipient_id, content) VALUES (NULL, ?, ?, ?)""", (session["user_id"], user_id, content),)
        conn.commit()

    # retrieve message history
    cur.execute("""SELECT m.*, u.username AS sender_name
    FROM messages m
    JOIN users u ON m.sender_id = u.id
    WHERE (m.sender_id = ? AND m.recipient_id = ?)
    OR (m.sender_id = ? AND m.recipient_id = ?)
    ORDER BY m.created_at ASC""", (session["user_id"], user_id, user_id, session["user_id"]),)
    messages = cur.fetchall()
    conn.close()

    return render_template("messages.html", ad=None, messages=messages, recipient=recipient)

@app.route('/create_ad', methods=['GET', 'POST'])
def create_ad():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        image_file = request.files.get('image')

        filename = None
        if image_file and image_file.filename:
            filename = image_file.filename
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)

        conn = get_db()
        cur = conn.cursor()

        # test - inserting ads 
        cur.execute("INSERT INTO ads (title, description, image, user_id) VALUES (?, ?, ?, ?)", (title, description, filename, session["user_id"]))

        conn.commit()
        conn.close()

        # ads.append({"title": title, "description": description})
        return redirect(url_for('home'))
    return render_template('create_ad.html')

@app.route("/rate/<int:seller_id>", methods=["GET", "POST"])
def rate_seller(seller_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE id = ?", (seller_id,))
    seller = cur.fetchone()
    if not seller:
        conn.close()
        return "User not found", 404

    if request.method == "POST":
        rating = int(request.form.get("rating"))
        review = request.form.get("review")[:50]

        conn = get_db()
        cur = conn.cursor()
        cur.execute("""INSERT INTO ratings (seller_id, rater_id, rating, review) VALUES (?, ?, ?, ?)""", (seller_id, session["user_id"], rating, review))
        conn.commit()
        conn.close()

        ad_id = request.args.get("ad_id")
        if ad_id:
            return redirect(url_for("view_ad", ad_id=ad_id))
        else:
            return redirect(url_for("view_user", user_id=seller_id))

    conn.close()
    return render_template("rate.html", seller_id=seller_id, seller=seller)

@app.route("/generate_pgp")
def generate_pgp():
    if "user_id" not in session:
        return redirect(url_for("login"))

    key = generate_ecc_keypair()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET pgp_public_key=?, pgp_private_key=? WHERE id=?", (str(key.pubkey), str(key), session["user_id"]))
    conn.commit()
    conn.close()

    return "PGP key generated successfully"

# supply passphrase for PGP
@app.route("/settings", methods=["GET", "POST"])
def settings():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        passphrase = request.form.get("passphrase")
        passphrase_confirm = request.form.get("passphrase_confirm")
        if not passphrase or passphrase != passphrase_confirm:
            return render_template("settings.html", error="Passphrases must match and not be empty")

        pubarm, privarm = generate_ecc_keypair(session.get("username", "User"), email=f"user{session['user_id']}@example.local")

        ciphertext_b64, salt_b64, nonce_b64 = encrypt_bytes(privarm.encode("utf-8"), passphrase)

        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            UPDATE users SET pgp_public_key=?, pgp_private_key_encrypted=?, pgp_key_salt=?, pgp_key_nonce=?
            WHERE id=?
        """, (pubarm, ciphertext_b64, salt_b64, nonce_b64, session["user_id"]))
        conn.commit()
        conn.close()

        return render_template("settings.html", success="PGP keys generated and stored (encrypted). Please download your private key.")
    else:
        # show settings page
        return render_template("settings.html")

@app.route("/download_public_key/<int:user_id>")
def download_public_key(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT pgp_public_key FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row or not row["pgp_public_key"]:
        return "No public key available", 404
    pub = row["pgp_public_key"]
    # Return as downloadable file
    return (pub, 200, {
        'Content-Type': 'application/pgp-keys',
        'Content-Disposition': f'attachment; filename="user_{user_id}_public.asc"'
    })

@app.route("/download_encrypted_private_key")
def download_encrypted_private_key():
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT pgp_private_key_encrypted, pgp_key_salt, pgp_key_nonce FROM users WHERE id=?", (session["user_id"],))
    row = cur.fetchone()
    conn.close()
    if not row or not row["pgp_private_key_encrypted"]:
        return "No private key stored", 404
    # Provide a JSON-like or text file (they will need passphrase to decrypt locally)
    content = f"ciphertext:{row['pgp_private_key_encrypted']}\nsalt:{row['pgp_key_salt']}\nnonce:{row['pgp_key_nonce']}\n"
    return (content, 200, {
        'Content-Type': 'text/plain',
        'Content-Disposition': f'attachment; filename="user_{session["user_id"]}_privkey_encrypted.txt"'
    })

if __name__=="__main__":
    init_db()
    app.run(debug=True)


