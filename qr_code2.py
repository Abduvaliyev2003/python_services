# app.py
import os
from io import BytesIO
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_file, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required, logout_user, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import qrcode
from qrcode.constants import ERROR_CORRECT_L, ERROR_CORRECT_M, ERROR_CORRECT_Q, ERROR_CORRECT_H
from PIL import Image
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

# ---------------------------
# Configuration
# ---------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change_this_secret_for_prod")

# 🔹 PostgreSQL connection string
#    postgresql://<user>:<password>@<host>/<database>
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "postgresql://root:root@localhost/qrcode_db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB upload limit

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "webp", "bmp", "gif"}
ALLOWED_TEXT_EXT = {"txt"}

ERROR_LEVELS = {
    "L": ERROR_CORRECT_L,
    "M": ERROR_CORRECT_M,
    "Q": ERROR_CORRECT_Q,
    "H": ERROR_CORRECT_H,
}

# ---------------------------
# Models
# ---------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(220), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------------------
# Helpers
# ---------------------------
def allowed_file(filename, allowed_set):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_set


def image_to_format_bytes(img: Image.Image, target_format: str) -> BytesIO:
    buf = BytesIO()
    fmt = target_format.upper()
    save_img = img
    if fmt in ("JPEG", "JPG") and save_img.mode in ("RGBA", "LA"):
        bg = Image.new("RGB", save_img.size, (255, 255, 255))
        bg.paste(save_img, mask=save_img.split()[-1])
        save_img = bg
    elif fmt in ("JPEG", "JPG") and save_img.mode != "RGB":
        save_img = save_img.convert("RGB")
    save_img.save(buf, format=fmt)
    buf.seek(0)
    return buf


def txt_to_pdf_bytes(txt_bytes, filename_hint="file") -> BytesIO:
    text = txt_bytes.decode("utf-8", errors="replace")
    buf = BytesIO()
    page_w, page_h = A4
    c = canvas.Canvas(buf, pagesize=A4)
    margin = 40
    max_width = page_w - 2 * margin
    text_object = c.beginText(margin, page_h - margin)
    text_object.setFont("Helvetica", 11)

    for line in text.splitlines():
        current = ""
        for word in line.split(" "):
            test = (current + " " + word).strip()
            width = c.stringWidth(test, "Helvetica", 11)
            if width <= max_width:
                current = test
            else:
                text_object.textLine(current)
                current = word
        text_object.textLine(current)
    c.drawText(text_object)
    c.showPage()
    c.save()
    buf.seek(0)
    return buf


# ---------------------------
# Routes
# ---------------------------
@app.route("/")
def home():
    return render_template("home.html", title="Home")


@app.route("/services")
def services():
    return render_template("services.html", title="Services")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "")
        email = request.form.get("email", "")
        message = request.form.get("message", "")
        flash("Thanks! Your message was received.", "success")
        return redirect(url_for("contact"))
    return render_template("contact.html", title="Contact")


# --- Authentication ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        if not (username and email and password):
            flash("Fill all fields.", "danger")
            return redirect(url_for("register"))
        if password != password2:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("User already exists.", "danger")
            return redirect(url_for("register"))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", title="Register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == "POST":
        username_or_email = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for("home"))
        flash("Invalid credentials.", "danger")
        return redirect(url_for("login"))

    return render_template("login.html", title="Login")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


# --- QR generator ---
@app.route("/qr", methods=["GET", "POST"])
def qr_page():
    if request.method == "POST":
        data = request.form.get("data", "").strip()
        if not data:
            flash("Please enter text or URL.", "danger")
            return redirect(url_for("qr_page"))

        error_corr = ERROR_LEVELS.get(request.form.get("error_correction", "M"), ERROR_CORRECT_M)
        box_size = int(request.form.get("box_size", 10) or 10)
        border = int(request.form.get("border", 4) or 4)
        fill_color = request.form.get("fill_color", "#000000") or "#000000"
        back_color = request.form.get("back_color", "#ffffff") or "#ffffff"
        image_format = (request.form.get("format", "PNG") or "PNG").upper()
        if image_format not in ("PNG", "JPEG", "JPG", "WEBP"):
            image_format = "PNG"

        qr_obj = qrcode.QRCode(error_correction=error_corr, box_size=box_size, border=border)
        qr_obj.add_data(data)
        qr_obj.make(fit=True)
        img = qr_obj.make_image(fill_color=fill_color, back_color=back_color).convert("RGBA")

        buf = image_to_format_bytes(img, image_format)
        filename = f"qrcode.{image_format.lower()}"
        return send_file(buf, mimetype=f"image/{image_format.lower()}", as_attachment=True, download_name=filename)

    return render_template("qr.html", title="QR Generator")


# --- Translator ---
@app.route("/translator")
def translator():
    return render_template("translator.html", title="Translator")


# --- File converter ---
@app.route("/converter", methods=["GET", "POST"])
@login_required
def converter():
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file in request.", "danger")
            return redirect(url_for("converter"))

        f = request.files["file"]
        if f.filename == "":
            flash("No file selected.", "danger")
            return redirect(url_for("converter"))

        filename = secure_filename(f.filename)
        ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
        target_format = (request.form.get("target_format") or "").lower()

        if allowed_file(filename, ALLOWED_IMAGE_EXT):
            if target_format not in ALLOWED_IMAGE_EXT:
                flash(f"Target format must be: {', '.join(sorted(ALLOWED_IMAGE_EXT))}", "danger")
                return redirect(url_for("converter"))
            try:
                img = Image.open(f.stream).convert("RGBA")
            except Exception:
                flash("Unable to read image.", "danger")
                return redirect(url_for("converter"))
            buf = image_to_format_bytes(img, target_format)
            out_name = f"{os.path.splitext(filename)[0]}.{target_format}"
            return send_file(buf, mimetype=f"image/{target_format}", as_attachment=True, download_name=out_name)

        if allowed_file(filename, ALLOWED_TEXT_EXT) and target_format == "pdf":
            try:
                pdf_buf = txt_to_pdf_bytes(f.read(), filename)
                out_name = f"{os.path.splitext(filename)[0]}.pdf"
                return send_file(pdf_buf, mimetype="application/pdf", as_attachment=True, download_name=out_name)
            except Exception:
                flash("Failed to convert text.", "danger")
                return redirect(url_for("converter"))

        flash("Unsupported file or format.", "danger")
        return redirect(url_for("converter"))

    return render_template("converter.html", title="File Converter")


# --- Error handlers ---
@app.errorhandler(413)
def too_large(e):
    flash("File too large (max 16MB).", "danger")
    return redirect(request.url or url_for("converter"))


# --- CLI helper to init tables ---
@app.cli.command("initdb")
def initdb_command():
    """Create all tables in PostgreSQL."""
    db.create_all()
    print("Initialized the database.")


# --- Run ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # create tables if not exist
    app.run(host="0.0.0.0", port=5000, debug=True)
