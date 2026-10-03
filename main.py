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
    password: str = Form(...),
    role: str = Form(...),
    subject: str = Form(None),
    standard: str = Form(None)
):
    # Check selected role
    if role not in ["Teacher", "Student"]:
        return HTMLResponse(
            content="<h2>Please select Teacher or Student.</h2>"
                    '<a href="/register">Go back</a>',
            status_code=400
        )

    # Teacher must enter subject
    if role == "Teacher" and not subject:
        return HTMLResponse(
            content="<h2>Please enter your subject.</h2>"
                    '<a href="/register">Go back</a>',
            status_code=400
        )

    # Student must enter standard
    if role == "Student" and not standard:
        return HTMLResponse(
            content="<h2>Please enter your standard.</h2>"
                    '<a href="/register">Go back</a>',
            status_code=400
        )

    # Validate password
    error = validate_password(password)

    if error:
        return HTMLResponse(
            content=f"""
            <h2>{error}</h2>
            <a href="/register">Go back</a>
            """,
            status_code=400
        )

    # Generate OTP
    otp = str(random.randint(100000, 999999))
    otp_expires = datetime.now() + timedelta(minutes=5)

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    try:
        cursor.execute("""
            INSERT INTO users
            (
                full_name, email, phone, dob, password,
                otp, otp_expires, is_verified,
                role, subject, standard
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            full_name,
            email,
            phone,
            dob,
            password,
            otp,
            otp_expires.isoformat(),
            0,
            role,
            subject if role == "Teacher" else None,
            standard if role == "Student" else None
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

    # Show OTP in terminal
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
        "SELECT * FROM users WHERE email = ? AND password = ?",
        (email, password)
    )

    user = cursor.fetchone()
    connection.close()

    # Check email and password
    if not user:
        return HTMLResponse(
            content="""
            <h1>Login Failed</h1>
            <p>Invalid email or password.</p>
            <a href="/">Try Again</a>
            """,
            status_code=401
        )

    # Check OTP verification
    if user[8] == 0:
        return RedirectResponse(
            url=f"/verify-otp?email={email}",
            status_code=303
        )

    # Save login session
    request.session["user_email"] = email

    print("LOGIN SESSION:", request.session)

    # Open dashboard
        # Get user's role from database
    role = user[10]

    # Redirect based on role
    if role == "Admin":
        return RedirectResponse(
            url="/admin",
            status_code=303
        )

    elif role == "Teacher":
        return RedirectResponse(
            url="/teacher-dashboard",
            status_code=303
        )

    else:
        return RedirectResponse(
            url="/dashboard",
            status_code=303
        )
    
@app.get("/dashboard")
async def dashboard_page(request: Request):
    email = request.session.get("user_email")
    print("DASHBOARD SESSION:", request.session)

    if not email:
        return RedirectResponse(url="/")

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    # Get logged-in user
    cursor.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    )

    user = cursor.fetchone()

    if not user:
        connection.close()
        return HTMLResponse(
            content="<h2>User not found.</h2>",
            status_code=404
        )

    # Find assigned teacher for this student
    teacher = None

    if user[10] == "Student" and user[13]:
        cursor.execute(
            "SELECT full_name, email, phone, subject FROM users WHERE id = ?",
            (user[13],)
        )

        teacher = cursor.fetchone()

    connection.close()

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user": user,
            "teacher": teacher
        }
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
@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):

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

    if not user or user[10] != "Admin":
        connection.close()
        return HTMLResponse(
            content="<h2>Access Denied</h2>",
            status_code=403
        )

    cursor.execute("""
        SELECT full_name, email, role, subject, standard
        FROM users
        WHERE role != 'Admin'
    """)

    users = cursor.fetchall()
    connection.close()

    user_rows = ""

    for u in users:
        user_rows += f"""
        <tr>
            <td>{u[0]}</td>
            <td>{u[1]}</td>
            <td>{u[2]}</td>
            <td>{u[3] or '-'}</td>
            <td>{u[4] or '-'}</td>
        </tr>
        """

    return HTMLResponse(
        content=f"""
        <html>
        <body>

        <h1>Admin Dashboard</h1>
        <p>Welcome, Admin!</p>

        <hr>

        <h2>Create Teacher / Student Account</h2>

        <form action="/admin/create-user" method="post">

            <label>Full Name:</label>
            <input type="text" name="full_name" required>
            <br><br>

            <label>Email:</label>
            <input type="email" name="email" required>
            <br><br>

            <label>Phone:</label>
            <input type="text" name="phone" required>
            <br><br>

            <label>Date of Birth:</label>
            <input type="date" name="dob" required>
            <br><br>

            <label>Role:</label>
            <select name="role" required>
                <option value="">Select Role</option>
                <option value="Teacher">Teacher</option>
                <option value="Student">Student</option>
            </select>
            <br><br>

            <label>Subject (Teacher only):</label>
            <input type="text" name="subject">
            <br><br>

            <label>Standard/Class (Student only):</label>
            <input type="text" name="standard">
            <br><br>

            <button type="submit">Create Account</button>

        </form>

        <hr>

        <h2>Registered Teachers and Students</h2>

        <table border="1" cellpadding="8">
            <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>Subject</th>
                <th>Standard</th>
            </tr>

            {user_rows}

        </table>

        </body>
        </html>
        """
    )
@app.post("/admin/create-user")
async def admin_create_user(
    request: Request,
    full_name: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    dob: str = Form(...),
    role: str = Form(...),
    subject: str = Form(None),
    standard: str = Form(None)
):

    admin_email = request.session.get("user_email")

    if not admin_email:
        return RedirectResponse(url="/")

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    # Check that the logged-in user is Admin
    cursor.execute(
        "SELECT * FROM users WHERE email = ?",
        (admin_email,)
    )

    admin = cursor.fetchone()

    if not admin or admin[10] != "Admin":
        connection.close()
        return HTMLResponse(
            content="<h2>Access Denied</h2>",
            status_code=403
        )

    # Validate role
    if role not in ["Teacher", "Student"]:
        connection.close()
        return HTMLResponse(
            content="<h2>Please select Teacher or Student.</h2>"
                    '<a href="/admin">Go back</a>',
            status_code=400
        )

    # Teacher must have subject
    if role == "Teacher" and not subject:
        connection.close()
        return HTMLResponse(
            content="<h2>Please enter the teacher subject.</h2>"
                    '<a href="/admin">Go back</a>',
            status_code=400
        )

    # Student must have standard
    if role == "Student" and not standard:
        connection.close()
        return HTMLResponse(
            content="<h2>Please enter the student standard/class.</h2>"
                    '<a href="/admin">Go back</a>',
            status_code=400
        )

    # Temporary password
    temporary_password = "Temp@12345"

    try:
        cursor.execute("""
            INSERT INTO users
            (
                full_name,
                email,
                phone,
                dob,
                password,
                otp,
                otp_expires,
                is_verified,
                role,
                subject,
                standard
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            full_name,
            email,
            phone,
            dob,
            temporary_password,
            None,
            None,
            1,
            role,
            subject if role == "Teacher" else None,
            standard if role == "Student" else None
        ))

        connection.commit()

    except sqlite3.IntegrityError:
        connection.close()
        return HTMLResponse(
            content="""
            <h2>Email already registered!</h2>
            <a href="/admin">Go back</a>
            """,
            status_code=400
        )

    connection.close()

    return HTMLResponse(
        content=f"""
        <h2>Account Created Successfully!</h2>

        <p><b>Name:</b> {full_name}</p>
        <p><b>Email:</b> {email}</p>
        <p><b>Role:</b> {role}</p>
        <p><b>Temporary Password:</b> {temporary_password}</p>

        <br>

        <a href="/admin">Back to Admin Dashboard</a>
        """
    )
@app.get("/admin/assign-teacher", response_class=HTMLResponse)
async def assign_teacher_page(request: Request):

    email = request.session.get("user_email")

    if not email:
        return RedirectResponse(url="/")

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    # Check Admin
    cursor.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    )

    admin = cursor.fetchone()

    if not admin or admin[10] != "Admin":
        connection.close()
        return HTMLResponse(
            content="<h2>Access Denied</h2>",
            status_code=403
        )

    # Get students
    cursor.execute("""
        SELECT id, full_name, email, teacher_id
        FROM users
        WHERE role = 'Student'
    """)

    students = cursor.fetchall()

    # Get teachers
    cursor.execute("""
        SELECT id, full_name, email, subject
        FROM users
        WHERE role = 'Teacher'
    """)

    teachers = cursor.fetchall()

    connection.close()

    student_options = ""

    for student in students:
        student_options += f"""
        <option value="{student[0]}">
            {student[1]} - {student[2]}
        </option>
        """

    teacher_options = ""

    for teacher in teachers:
        teacher_options += f"""
        <option value="{teacher[0]}">
            {teacher[1]} - {teacher[3] or 'No Subject'}
        </option>
        """

    return HTMLResponse(
        content=f"""
        <html>
        <body>

        <h1>Assign Student to Teacher</h1>

        <form action="/admin/assign-teacher" method="post">

            <label>Select Student:</label>
            <select name="student_id" required>
                <option value="">Select Student</option>
                {student_options}
            </select>

            <br><br>

            <label>Select Teacher:</label>
            <select name="teacher_id" required>
                <option value="">Select Teacher</option>
                {teacher_options}
            </select>

            <br><br>

            <button type="submit">Assign Teacher</button>

        </form>

        <br>

        <a href="/admin">Back to Admin Dashboard</a>

        </body>
        </html>
        """
    )


@app.post("/admin/assign-teacher")
async def assign_teacher(
    request: Request,
    student_id: int = Form(...),
    teacher_id: int = Form(...)
):

    email = request.session.get("user_email")

    if not email:
        return RedirectResponse(url="/")

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    # Check Admin
    cursor.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    )

    admin = cursor.fetchone()

    if not admin or admin[10] != "Admin":
        connection.close()
        return HTMLResponse(
            content="<h2>Access Denied</h2>",
            status_code=403
        )

    # Assign teacher to student
    cursor.execute(
        "UPDATE users SET teacher_id = ? WHERE id = ? AND role = 'Student'",
        (teacher_id, student_id)
    )

    connection.commit()
    connection.close()

    return HTMLResponse(
        content="""
        <h2>Teacher Assigned Successfully!</h2>

        <br>

        <a href="/admin/assign-teacher">Assign Another Student</a>

        <br><br>

        <a href="/admin">Back to Admin Dashboard</a>
        """
    )
@app.get("/teacher-dashboard", response_class=HTMLResponse)
async def teacher_dashboard(request: Request):

    email = request.session.get("user_email")

    if not email:
        return RedirectResponse(url="/")

    connection = sqlite3.connect("users.db")
    cursor = connection.cursor()

    # Get logged-in teacher
    cursor.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    )

    teacher = cursor.fetchone()

    if not teacher or teacher[10] != "Teacher":
        connection.close()
        return HTMLResponse(
            content="<h2>Access Denied</h2>",
            status_code=403
        )

    # Get only students assigned to this teacher
    cursor.execute("""
        SELECT full_name, email, phone, dob, standard
        FROM users
        WHERE role = 'Student' AND teacher_id = ?
    """, (teacher[0],))

    students = cursor.fetchall()

    connection.close()

    student_rows = ""

    for student in students:
        student_rows += f"""
        <tr>
            <td>{student[0]}</td>
            <td>{student[1]}</td>
            <td>{student[2]}</td>
            <td>{student[3]}</td>
            <td>{student[4] or '-'}</td>
        </tr>
        """

    if not student_rows:
        student_rows = """
        <tr>
            <td colspan="5">No students assigned yet.</td>
        </tr>
        """

    return HTMLResponse(
        content=f"""
        <html>
        <body>

        <h1>Teacher Dashboard</h1>

        <p><b>Welcome, {teacher[1]}</b></p>

        <p>
            <b>Subject:</b> {teacher[11] or '-'}
        </p>

        <hr>

        <h2>My Assigned Students</h2>

        <table border="1" cellpadding="8">

            <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Phone</th>
                <th>Date of Birth</th>
                <th>Standard</th>
            </tr>

            {student_rows}

        </table>

        <br>

        <a href="/dashboard">Go to Dashboard</a>

        </body>
        </html>
        """
    )