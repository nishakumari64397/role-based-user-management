from fastapi import FastAPI, Request, Form, UploadFile, File
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import sqlite3
import random
import os
import uuid
from datetime import datetime, timedelta

app = FastAPI()
os.makedirs("uploads", exist_ok=True)
from fastapi.staticfiles import StaticFiles

app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")
app.add_middleware(
    SessionMiddleware,
    secret_key="my-secret-key-123"
)

templates = Jinja2Templates(directory="templates")


def create_database():
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            dob TEXT NOT NULL,
            password TEXT NOT NULL,
            otp TEXT,
            otp_expires TEXT,
            is_verified INTEGER DEFAULT 0
        )
    """)
    try:
        cursor.execute(
            "ALTER TABLE users ADD COLUMN profile_picture TEXT"
        )
    except sqlite3.OperationalError:
        pass
 
    connection.commit()
    connection.close()


create_database()


def validate_password(password: str):

    if len(password) < 10:
        return "Password must be at least 10 characters long."

    if not any(char.isalpha() for char in password):
        return "Password must contain at least one alphabetic character."

    if not any(char.isdigit() for char in password):
        return "Password must contain at least one number."

    if not any(not char.isalnum() for char in password):
        return "Password must contain at least one special character."

    return None


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={}
    )


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={}
    )


@app.post("/register")
async def register(
    full_name: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    dob: str = Form(...),
    password: str = Form(...)
):

    error = validate_password(password)

    if error:
        return HTMLResponse(
            content=f"""
            <h2>{error}</h2>
            <a href="/register">Go back</a>
            """,
            status_code=400
        )

    otp = str(random.randint(100000, 999999))
    otp_expires = datetime.now() + timedelta(minutes=5)

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    try:
        cursor.execute("""
            INSERT INTO users
            (full_name, email, phone, dob, password, otp, otp_expires, is_verified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            full_name,
            email,
            phone,
            dob,
            password,
            otp,
            otp_expires.isoformat(),
            0
        ))

        connection.commit()

    except sqlite3.IntegrityError:
        connection.close()

        return HTMLResponse(
            content="""
            <h2>Email already registered!</h2>
            <a href="/register">Go back</a>
            """,
            status_code=400
        )

    connection.close()

    print("--------------------------------")
    print("OTP FOR", email, ":", otp)
    print("--------------------------------")

    return RedirectResponse(
        url=f"/verify-otp?email={email}",
        status_code=303
    )


@app.get("/verify-otp", response_class=HTMLResponse)
async def verify_otp_page(request: Request, email: str):

    return templates.TemplateResponse(
        request=request,
        name="verify_otp.html",
        context={"email": email}
    )


@app.post("/verify-otp")
async def verify_otp(
    email: str = Form(...),
    otp: str = Form(...)
):

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    cursor.execute(
        "SELECT otp, otp_expires FROM users WHERE email = ?",
        (email,)
    )

    user = cursor.fetchone()

    if not user:
        connection.close()

        return HTMLResponse(
            content="<h2>User not found.</h2>",
            status_code=404
        )

    saved_otp = user[0]
    expiry = datetime.fromisoformat(user[1])

    if otp != saved_otp:
        connection.close()

        return HTMLResponse(
            content="<h2>Invalid OTP!</h2>",
            status_code=400
        )

    if datetime.now() > expiry:
        connection.close()

        return HTMLResponse(
            content="<h2>OTP has expired!</h2>",
            status_code=400
        )

    cursor.execute(
        """
        UPDATE users
        SET is_verified = 1, otp = NULL, otp_expires = NULL
        WHERE email = ?
        """,
        (email,)
    )

    connection.commit()
    connection.close()

    return RedirectResponse(
        url="/",
        status_code=303
    )


@app.post("/login")
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...)
):

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT * FROM users
        WHERE email = ? AND password = ?
        """,
        (email, password)
    )

    user = cursor.fetchone()
    connection.close()

    if not user:
        return HTMLResponse(
            content="""
            <h1>Login Failed</h1>
            <p>Invalid email or password.</p>
            <a href="/">Try Again</a>
            """,
            status_code=401
        )

    if user[8] == 0:
        return RedirectResponse(
            url=f"/verify-otp?email={email}",
            status_code=303
        )

    request.session["user_email"] = email

    return RedirectResponse(
        url="/dashboard",
        status_code=303
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):

    email = request.session.get("user_email")

    if not email:
        return RedirectResponse(url="/")

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    )

    user = cursor.fetchone()
    connection.close()

    if not user:
        return HTMLResponse(
            content="<h2>User not found.</h2>",
            status_code=404
        )

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"user": user}
    )


@app.get("/edit-profile", response_class=HTMLResponse)
async def edit_profile_page(request: Request):

    email = request.session.get("user_email")

    if not email:
        return RedirectResponse(url="/")

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    )

    user = cursor.fetchone()
    connection.close()

    if not user:
        return HTMLResponse(
            content="<h2>User not found.</h2>",
            status_code=404
        )

    return templates.TemplateResponse(
        request=request,
        name="edit_profile.html",
        context={"user": user}
    )
# ---------------- SAVE EDITED PROFILE ----------------

@app.post("/edit-profile")
async def update_profile(
    request: Request,
    full_name: str = Form(...),
    phone: str = Form(...),
    dob: str = Form(...)
):

    email = request.session.get("user_email")

    if not email:
        return RedirectResponse(url="/")

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE users
        SET full_name = ?, phone = ?, dob = ?
        WHERE email = ?
        """,
        (full_name, phone, dob, email)
    )

    connection.commit()
    connection.close()

    return RedirectResponse(
        url="/dashboard",
        status_code=303
    )
@app.post("/upload-profile-picture")
async def upload_profile_picture(
    request: Request,
    profile_picture: UploadFile = File(...)
):

    email = request.session.get("user_email")

    if not email:
        return RedirectResponse(url="/", status_code=303)

    # Check file type
    extension = os.path.splitext(profile_picture.filename or "")[1].lower()

    allowed_extensions = {
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".webp"
    }

    if extension not in allowed_extensions:
        return HTMLResponse(
            content="<h2>Only image files are allowed.</h2>",
            status_code=400
        )

    # Get current profile picture
    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    cursor.execute(
        "SELECT profile_picture FROM users WHERE email = ?",
        (email,)
    )

    old_picture = cursor.fetchone()

    # Delete old picture if it exists
    if old_picture and old_picture[0]:
        old_path = os.path.join("uploads", old_picture[0])

        if os.path.exists(old_path):
            os.remove(old_path)

    # Create a new unique filename
    filename = uuid.uuid4().hex + extension

    save_path = os.path.join("uploads", filename)

    # Save the uploaded picture
    with open(save_path, "wb") as file:
        file.write(await profile_picture.read())

    # Save filename in database
    cursor.execute(
        """
        UPDATE users
        SET profile_picture = ?
        WHERE email = ?
        """,
        (filename, email)
    )

    connection.commit()
    connection.close()

    return RedirectResponse(
        url="/dashboard",
        status_code=303
    )
@app.post("/delete-profile-picture")
async def delete_profile_picture(request: Request):

    email = request.session.get("user_email")

    if not email:
        return RedirectResponse(url="/", status_code=303)

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    cursor.execute(
        "SELECT profile_picture FROM users WHERE email = ?",
        (email,)
    )

    picture = cursor.fetchone()

    if picture and picture[0]:
        file_path = os.path.join("uploads", picture[0])

        if os.path.exists(file_path):
            os.remove(file_path)

    cursor.execute(
        """
        UPDATE users
        SET profile_picture = NULL
        WHERE email = ?
        """,
        (email,)
    )

    connection.commit()
    connection.close()

    return RedirectResponse(
        url="/dashboard",
        status_code=303
    )
@app.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request):

    email = request.session.get("user_email")

    if not email:
        return RedirectResponse(url="/", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="change_password.html",
        context={}
    )


@app.post("/change-password")
async def change_password(
    request: Request,
    old_password: str = Form(...),
    new_password: str = Form(...)
):

    email = request.session.get("user_email")

    if not email:
        return RedirectResponse(url="/", status_code=303)

    # Check new password rules
    error = validate_password(new_password)

    if error:
        return HTMLResponse(
            content=f"""
            <h2>{error}</h2>
            <a href="/change-password">Go Back</a>
            """,
            status_code=400
        )

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    cursor.execute(
        "SELECT password FROM users WHERE email = ?",
        (email,)
    )

    user = cursor.fetchone()

    if not user:
        connection.close()

        return HTMLResponse(
            content="<h2>User not found.</h2>",
            status_code=404
        )

    # Check old password
    if user[0] != old_password:
        connection.close()

        return HTMLResponse(
            content="""
            <h2>Old password is incorrect.</h2>
            <a href="/change-password">Try Again</a>
            """,
            status_code=400
        )

    # Update password
    cursor.execute(
        """
        UPDATE users
        SET password = ?
        WHERE email = ?
        """,
        (new_password, email)
    )

    connection.commit()
    connection.close()

    return HTMLResponse(
        content="""
        <h2>Password changed successfully!</h2>
        <a href="/dashboard">Go to Dashboard</a>
        """
    )
@app.get("/forgot-password", 
response_class=HTMLResponse)
async def forgot_password_page(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="forgot_password.html",
        context={}
    )


@app.post("/forgot-password")
async def forgot_password(
    request: Request,
    email: str = Form(...)
):

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    cursor.execute(
        "SELECT id FROM users WHERE email = ?",
        (email,)
    )

    user = cursor.fetchone()

    if not user:
        connection.close()

        return HTMLResponse(
            content="""
            <h2>Email not found.</h2>
            <a href="/forgot-password">Try Again</a>
            """,
            status_code=404
        )

    otp = str(random.randint(100000, 999999))
    otp_expires = datetime.now() + timedelta(minutes=5)

    cursor.execute(
        """
        UPDATE users
        SET otp = ?, otp_expires = ?
        WHERE email = ?
        """,
        (otp, otp_expires.isoformat(), email)
    )

    connection.commit()
    connection.close()

    request.session["reset_email"] = email

    print("--------------------------------")
    print("FORGOT PASSWORD OTP FOR", email, ":", otp)
    print("--------------------------------")

    return RedirectResponse(
        url="/verify-forgot-password-otp",
        status_code=303
    )


@app.get("/verify-forgot-password-otp", response_class=HTMLResponse)
async def verify_forgot_password_otp_page(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="verify_forgot_password.html",
        context={}
    )
@app.get("/verify-forgot-password-otp", response_class=HTMLResponse)
async def verify_forgot_password_otp_page(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="verify_forgot_password.html",
        context={}
    )


# Paste the other code below this line
@app.post("/verify-forgot-password-otp")
async def verify_forgot_password_otp(
    request: Request,
    otp: str = Form(...)
):

    email = request.session.get("reset_email")

    if not email:
        return RedirectResponse(
            url="/forgot-password",
            status_code=303
        )

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    cursor.execute(
        "SELECT otp, otp_expires FROM users WHERE email = ?",
        (email,)
    )

    user = cursor.fetchone()
    connection.close()

    if not user:
        return HTMLResponse(
            content="<h2>User not found.</h2>",
            status_code=404
        )

    saved_otp = user[0]
    expiry = datetime.fromisoformat(user[1])

    if otp != saved_otp:
        return HTMLResponse(
            content="<h2>Invalid OTP. Please try again.</h2>",
            status_code=400
        )

    if datetime.now() > expiry:
        return HTMLResponse(
            content="<h2>OTP has expired. Please generate a new OTP.</h2>",
            status_code=400
        )

    request.session["reset_otp_verified"] = True

    return RedirectResponse(
        url="/reset-password",
        status_code=303
    )
@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request):

    if not request.session.get("reset_otp_verified"):
        return RedirectResponse(
            url="/forgot-password",
            status_code=303
        )

    return templates.TemplateResponse(
        request=request,
        name="reset_password.html",
        context={}
    )
@app.post("/reset-password")
async def reset_password(
    request: Request,
    new_password: str = Form(...),
    confirm_password: str = Form(...)
):

    email = request.session.get("reset_email")
    otp_verified = request.session.get("reset_otp_verified")

    if not email or not otp_verified:
        return RedirectResponse(
            url="/forgot-password",
            status_code=303
        )

    if new_password != confirm_password:
        return HTMLResponse(
            content="""
            <h2>Passwords do not match.</h2>
            <a href="/reset-password">Try Again</a>
            """,
            status_code=400
        )

    error = validate_password(new_password)

    if error:
        return HTMLResponse(
            content=f"""
            <h2>{error}</h2>
            <a href="/reset-password">Try Again</a>
            """,
            status_code=400
        )

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE users
        SET password = ?, otp = NULL, otp_expires = NULL
        WHERE email = ?
        """,
        (new_password, email)
    )

    connection.commit()
    connection.close()

    request.session.pop("reset_email", None)
    request.session.pop("reset_otp_verified", None)

    return HTMLResponse(
        content="""
        <h2>Password reset successfully!</h2>
        <a href="/">Go to Login</a>
        """
    )
@app.get("/logout")
async def logout(request: Request):

    request.session.clear()

    return RedirectResponse(
        url="/",
        status_code=303
    )