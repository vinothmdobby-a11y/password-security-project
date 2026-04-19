from flask import Flask, render_template, request, redirect
import sqlite3
import bcrypt
import random

app = Flask(__name__)

# Database
def get_db():
    return sqlite3.connect("users.db")

conn = get_db()
conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT, password TEXT)")
conn.close()

otp_store = {}

@app.route("/")
def home():
    return redirect("/login")

# REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        if len(password) < 8:
            return "Password must be at least 8 characters"

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        conn = get_db()
        conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed))
        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")

# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode(), user[2]):
            return render_template("dashboard.html", email=email)

        return "Invalid login"

    return render_template("login.html")

# SEND OTP
@app.route("/send_otp", methods=["POST"])
def send_otp():
    email = request.form["email"]
    otp = str(random.randint(100000, 999999))
    otp_store[email] = otp
    print("OTP:", otp)
    return "OTP sent (check terminal)"

# RESET PASSWORD
@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "POST":
        email = request.form["email"]
        otp = request.form["otp"]
        password = request.form["password"]

        if otp_store.get(email) == otp:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

            conn = get_db()
            conn.execute("UPDATE users SET password=? WHERE email=?", (hashed, email))
            conn.commit()
            conn.close()

            return "Password updated"

        return "Invalid OTP"

    return render_template("reset.html")
if __name__ == "__main__":
    app.run(debug=True)