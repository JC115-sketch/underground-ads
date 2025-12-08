import os
from db import init_db, get_db
from flask import Flask, redirect, render_template, request, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

app.secret_key = "IGIVEUP" # this signs 'user_id' which is created at login

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

    return render_template("profile.html", ads=user_ads)

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
        cur.execute("UPDATE users SET about = ? WHERE id = ?", (session["user_id"]))
        conn.commit()
        conn.close()
        return redirect(url_for("profile"))

    cur.execute("SELECT about FROM users WHERE id = ?", (session["user_id"]))
    user = cur.fetchone()
    conn.close()

    return render_template("edit_profile.html", about=user["about"])

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
        SELECT username, about,
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
def message(ad_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    cur = conn.cursor()

    # retrieve ad and owner info
    cur.execute("SELECT ads.*, users.username FROM ads JOIN users ON ads.user_id = users.id WHERE ads.id = ?", (ad_id,))
    ad = cur.fetchone() # chooses next row available from result set

    if request.method == "POST":
        content = request.form.get("message")
        cur.execute(""" INSERT INTO messages (ad_id, sender_id, recipient_id, content) VALUES (?, ?, ?, ?)""", (ad_id, session["user_id"], ad["user_id"], content))
        conn.commit()

    # fetch conversation
    cur.execute(""" SELECT m.*, u.username AS sender_name
    FROM messages m
    JOIN users u ON m.sender_id = u.id
    WHERE m.ad_id = ?
    ORDER BY m.created_at ASC
    """, (ad_id,))
    messages = cur.fetchall()

    conn.close()

    return render_template("messages.html", ad=ad, messages=messages)

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

    if request.method == "POST":
        rating = int(request.form.get("rating"))
        review = request.form.get("review")[:50]

        conn = get_db()
        cur = conn.cursor()
        cur.execute("""INSERT INTO ratings (seller_id, rater_id, rating, review) VALUES (?, ?, ?, ?)""", (seller_id, session["user_id"], rating, review))
        conn.commit()
        conn.close()

        ad_id = request.args.get("ad_id")
        return redirect(url_for("view_ad", ad_id=ad_id))

    return render_template("rate.html", seller_id=seller_id)

if __name__=="__main__":
    init_db()
    app.run(debug=True)


