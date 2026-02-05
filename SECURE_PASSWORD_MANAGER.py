import tkinter as tk
from tkinter import messagebox
import hashlib
import random
import string
import re
import uuid
import datetime

# ================== FILES ==================
USERS_FILE = "users.txt"
LOG_FILE = "audit_log.txt"

# ================== GLOBAL SESSION ==================
CURRENT_USER = None
SESSION_TOKEN = None
CSRF_TOKEN = None

# ================== AUDIT LOG ==================
def audit(action):
    """Write security related actions to audit log"""
    with open(LOG_FILE, "a") as f:
        f.write(
            f"{datetime.datetime.now()} | "
            f"User={CURRENT_USER} | "
            f"Session={SESSION_TOKEN} | "
            f"Action={action}\n"
        )

# ================== SECURITY ==================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_tokens():
    global SESSION_TOKEN, CSRF_TOKEN
    SESSION_TOKEN = str(uuid.uuid4())
    CSRF_TOKEN = str(uuid.uuid4())

def validate_csrf(token):
    return token == CSRF_TOKEN

# ================== AUTH ==================
def signup(username, password):
    if not username or not password:
        messagebox.showerror("Error", "Please fill all fields")
        return False
    try:
        with open(USERS_FILE, "r") as f:
            for line in f:
                u, _ = line.strip().split(",")
                if u == username:
                    messagebox.showerror("Error", "User already exists")
                    return False
    except FileNotFoundError:
        pass
    hashed_pw = hash_password(password)
    with open(USERS_FILE, "a") as f:
        f.write(f"{username},{hashed_pw}\n")
    audit("User Signed Up")
    return True

def login(username, password):
    global CURRENT_USER
    hashed_pw = hash_password(password)
    try:
        with open(USERS_FILE, "r") as f:
            for line in f:
                u, h = line.strip().split(",")
                if u == username and h == hashed_pw:
                    CURRENT_USER = username
                    generate_tokens()
                    audit("User Logged In")
                    return True
    except FileNotFoundError:
        pass
    audit("Failed Login Attempt")
    return False

def logout():
    global CURRENT_USER, SESSION_TOKEN, CSRF_TOKEN
    audit("User Logged Out")
    CURRENT_USER = None
    SESSION_TOKEN = None
    CSRF_TOKEN = None
    generate_tokens()

# ================== PASSWORD LOGIC ==================
def password_strength(password, token):
    if not validate_csrf(token):
        audit("Invalid CSRF Token Used")
        raise Exception("CSRF token invalid")
    score = 0
    if len(password) >= 8: score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"[0-9]", password): score += 1
    if re.search(r"[!@#$%^&*()]", password): score += 1
    if score <= 2:
        strength = "WEAK"
    elif score <= 4:
        strength = "MEDIUM"
    else:
        strength = "STRONG"
    audit(f"Password Strength Checked = {strength}")
    return strength

def generate_secure_password(token, length=12):
    if not validate_csrf(token):
        audit("Invalid CSRF Token Used")
        raise Exception("CSRF token invalid")
    upper = random.choice(string.ascii_uppercase)
    lower = random.choice(string.ascii_lowercase)
    digit = random.choice(string.digits)
    special = random.choice("!@#$%^&*()")
    rest = "".join(random.choice(string.ascii_letters + string.digits + "!@#$%^&*()") for _ in range(length-4))
    password_list = list(upper + lower + digit + special + rest)
    random.shuffle(password_list)
    password = "".join(password_list)
    audit("Secure Password Generated")
    return password

# ================== TKINTER UI ==================
root = tk.Tk()
root.title("Information Security Project")
root.state("zoomed")
root.config(bg="#DFF3E3")

root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=2)
root.columnconfigure(2, weight=1)
root.rowconfigure(0, weight=1)
root.rowconfigure(1, weight=10)
root.rowconfigure(2, weight=0)

def clear():
    for w in root.winfo_children():
        w.destroy()

def toggle(entry, var):
    entry.config(show="" if var.get() else "•")

def footer():
    f = tk.Frame(root, bg="#CE7DA5", height=40)
    f.grid(row=2, column=0, columnspan=3, sticky="nsew")
    tk.Label(f, text="Mahnoor Menahil & Rida | Information Security Project",
             bg="#CE7DA5", fg="white", font=("Segoe UI", 10)
             ).place(relx=0.5, rely=0.5, anchor="center")

# ================= LOGIN UI =================
def show_login_ui():
    clear()
    center = tk.Frame(root, bg="#DFF3E3", padx=40, pady=40)
    center.grid(row=1, column=1)
    tk.Label(center, text="User Login", font=("Segoe UI", 24, "bold"),
             bg="#DFF3E3", fg="#493657").pack(pady=20)
    tk.Label(center, text="Username", bg="#DFF3E3", fg="#493657",
             font=("Segoe UI", 12, "bold")).pack(anchor="w")
    global li_user, li_pass
    li_user = tk.Entry(center, width=35, font=("Segoe UI", 12))
    li_user.pack(pady=5)
    tk.Label(center, text="Password", bg="#DFF3E3", fg="#493657",
             font=("Segoe UI", 12, "bold")).pack(anchor="w")
    li_pass = tk.Entry(center, width=35, font=("Segoe UI", 12), show="•")
    li_pass.pack(pady=5)
    show = tk.BooleanVar()
    tk.Checkbutton(center, text="Show Password", variable=show,
                   command=lambda: toggle(li_pass, show), bg="#DFF3E3").pack(anchor="w")
    tk.Button(center, text="Login", bg="#CE7DA5", fg="white",
              font=("Segoe UI", 12, "bold"), width=18,
              command=lambda: do_login()).pack(pady=15)
    tk.Button(center, text="Create Account", bg="#493657", fg="white",
              font=("Segoe UI", 11), command=show_signup_ui).pack()
    footer()

def do_login():
    if login(li_user.get(), li_pass.get()):
        show_dashboard_ui()
    else:
        messagebox.showerror("Error", "Invalid credentials")

# ================= SIGNUP UI =================
def show_signup_ui():
    clear()
    center = tk.Frame(root, bg="#DFF3E3", padx=40, pady=40)
    center.grid(row=1, column=1)
    tk.Label(center, text="User Signup", font=("Segoe UI", 24, "bold"),
             bg="#DFF3E3", fg="#493657").pack(pady=20)
    global su_user, su_pass
    tk.Label(center, text="Username", bg="#DFF3E3", font=("Segoe UI", 12, "bold")).pack(anchor="w")
    su_user = tk.Entry(center, width=35)
    su_user.pack(pady=5)
    tk.Label(center, text="Password", bg="#DFF3E3", font=("Segoe UI", 12, "bold")).pack(anchor="w")
    su_pass = tk.Entry(center, width=35, show="•")
    su_pass.pack(pady=5)
    show = tk.BooleanVar()
    tk.Checkbutton(center, text="Show Password", variable=show,
                   command=lambda: toggle(su_pass, show), bg="#DFF3E3").pack(anchor="w")
    tk.Button(center, text="Signup", bg="#CE7DA5", fg="white",
              font=("Segoe UI", 12, "bold"), width=18,
              command=lambda: do_signup()).pack(pady=15)
    tk.Button(center, text="Back to Login", command=show_login_ui).pack()
    footer()

def do_signup():
    if signup(su_user.get(), su_pass.get()):
        messagebox.showinfo("Success", "Account created!")
        show_login_ui()

# ================= DASHBOARD UI =================
def show_dashboard_ui():
    clear()
    left = tk.Frame(root, bg="#BEE5BF", padx=25, pady=25)
    left.grid(row=1, column=0, sticky="nsew")
    tk.Label(left, text="Password Rules", font=("Segoe UI", 16, "bold"),
             bg="#BEE5BF", fg="#493657").pack(anchor="w")
    rules = ["✔ Min 8 characters", "✔ Upper & Lower case", "✔ Numbers required", "✔ Special symbols"]
    for r in rules:
        tk.Label(left, text=r, bg="#BEE5BF", fg="#493657", font=("Segoe UI", 11)).pack(anchor="w", pady=4)

    center = tk.Frame(root, bg="#DFF3E3", padx=40, pady=40)
    center.grid(row=1, column=1, sticky="nsew")
    tk.Label(center, text="Password Security", font=("Segoe UI", 22, "bold"),
             bg="#DFF3E3", fg="#493657").pack(anchor="w")
    tk.Label(center, text="Enter password to check strength or generate one", bg="#DFF3E3",
             fg="#6b5a6f").pack(anchor="w", pady=(0, 25))
    tk.Label(center, text="Password", bg="#DFF3E3", fg="#493657", font=("Segoe UI", 12, "bold")).pack(anchor="w")
    global pw_entry, res
    pw_entry = tk.Entry(center, width=40, show="•", font=("Segoe UI", 13), bg="#BEE5BF", bd=0)
    pw_entry.pack(pady=8, ipady=8)
    show = tk.BooleanVar()
    tk.Checkbutton(center, text="Show Password", variable=show,
                   command=lambda: toggle(pw_entry, show), bg="#DFF3E3").pack(anchor="w")

    btns = tk.Frame(center, bg="#DFF3E3")
    btns.pack(anchor="w", pady=15)
    tk.Button(btns, text="Check Strength", bg="#CE7DA5", fg="white",
              font=("Segoe UI", 11, "bold"), padx=25, pady=8,
              command=lambda: res.set(password_strength(pw_entry.get(), CSRF_TOKEN))
              ).grid(row=0, column=0, padx=10)
    tk.Button(btns, text="Generate Password", bg="#493657", fg="white",
              font=("Segoe UI", 11, "bold"), padx=25, pady=8,
              command=lambda: [pw_entry.delete(0, tk.END),
                               pw_entry.insert(0, generate_secure_password(CSRF_TOKEN))]
              ).grid(row=0, column=1)

    res = tk.StringVar()
    tk.Label(center, textvariable=res, font=("Segoe UI", 14, "bold"),
             bg="#DFF3E3", fg="#493657").pack(pady=10)

    right = tk.Frame(root, bg="#BEE5BF", padx=25, pady=25)
    right.grid(row=1, column=2, sticky="nsew")
    tk.Label(right, text="Security Tips", font=("Segoe UI", 16, "bold"),
             bg="#BEE5BF", fg="#493657").pack(anchor="w")
    tips = ["🔐 Never share passwords", "🔄 Change regularly",
            "📦 Use password managers", "🛑 Avoid personal info"]
    for t in tips:
        tk.Label(right, text=t, bg="#BEE5BF", fg="#493657", font=("Segoe UI", 11)).pack(anchor="w", pady=4)
    tk.Button(right, text="Logout", bg="#CE7DA5", fg="white",
              command=lambda: [logout(), show_login_ui()]).pack(side="bottom", pady=20)

    footer()

# ================== START ==================
generate_tokens()
show_login_ui()
root.mainloop()
