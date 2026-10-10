
import os
import sqlite3
import secrets
import math
import csv
import io
from functools import wraps

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, session, abort, make_response
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

DATABASE = os.path.join(app.root_path, "database", "school.db")


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection



def initialize_database():
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

    with get_db() as connection:
        # Create the users table.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin'
            )
        """)

        # Create the students table.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_code TEXT UNIQUE,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                gender TEXT NOT NULL,
                date_of_birth TEXT,
                class_name TEXT NOT NULL,
                guardian_name TEXT NOT NULL,
                guardian_phone TEXT NOT NULL,
                address TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create the school settings table.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS school_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                school_name TEXT NOT NULL DEFAULT 'SchoolCore',
                school_address TEXT DEFAULT '',
                school_phone TEXT DEFAULT '',
                school_email TEXT DEFAULT '',
                academic_year TEXT DEFAULT '',
                current_term TEXT DEFAULT '',
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Insert default settings if they do not exist.
        connection.execute("""
            INSERT OR IGNORE INTO school_settings (id)
            VALUES (1)
        """)

        
        # Create the admin account if necessary.
        admin = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            ("admin",)
        ).fetchone()

        if admin is None:
            initial_admin_password = os.environ.get("INITIAL_ADMIN_PASSWORD")

            if not initial_admin_password:
                raise RuntimeError(
                    "Set the INITIAL_ADMIN_PASSWORD environment variable "
                    "before creating the first administrator account."
                )

            connection.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
                """,
                (
                    "admin",
                    generate_password_hash(initial_admin_password),
                    "admin"
                )
            )

            
            


def ensure_classes_subjects_tables(conn):
    """Create the classes and subjects tables if they do not exist."""

    conn.execute("""
        CREATE TABLE IF NOT EXISTS school_classes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_name TEXT NOT NULL UNIQUE,
            class_teacher TEXT DEFAULT '',
            room TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_name TEXT NOT NULL UNIQUE,
            subject_code TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()

def ensure_attendance_table(conn):
    """Create the student attendance table if it does not exist."""

    conn.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            attendance_date TEXT NOT NULL,
            status TEXT NOT NULL
                CHECK (status IN ('Present', 'Absent', 'Late', 'Excused')),
            remarks TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES students(id),
            UNIQUE (student_id, attendance_date)
        )
    """)

    conn.commit()

def ensure_results_table(conn):
    """Create the student examination results table if needed."""

    conn.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            subject_id INTEGER NOT NULL,
            class_score REAL NOT NULL DEFAULT 0,
            exam_score REAL NOT NULL DEFAULT 0,
            total_score REAL NOT NULL DEFAULT 0,
            grade TEXT NOT NULL DEFAULT '',
            remarks TEXT DEFAULT '',
            term TEXT NOT NULL,
            academic_year TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (student_id) REFERENCES students(id),
            FOREIGN KEY (subject_id) REFERENCES subjects(id),

            UNIQUE (
                student_id,
                subject_id,
                term,
                academic_year
            ),

            CHECK (class_score >= 0 AND class_score <= 30),
            CHECK (exam_score >= 0 AND exam_score <= 70)
        )
    """)

    conn.commit()
    
def ensure_school_fees_tables(conn):
    """Create school fee records and payment history tables."""

    conn.execute("""
        CREATE TABLE IF NOT EXISTS school_fees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            fee_name TEXT NOT NULL,
            amount_due REAL NOT NULL DEFAULT 0,
            academic_year TEXT NOT NULL,
            term TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (student_id) REFERENCES students(id),

            UNIQUE (
                student_id,
                fee_name,
                academic_year,
                term
            ),

            CHECK (amount_due >= 0)
        )
    """)


    conn.execute("""
        CREATE TABLE IF NOT EXISTS fee_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fee_id INTEGER NOT NULL,
            amount_paid REAL NOT NULL,
            payment_method TEXT NOT NULL DEFAULT 'Cash',
            reference TEXT DEFAULT '',
            payment_date TEXT NOT NULL,
            recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (fee_id) REFERENCES school_fees(id),

            CHECK (amount_paid > 0)
        )
    """)

    conn.commit()

def ensure_school_expenses_table(conn):
    """Create the school expenses table if it does not exist."""

    conn.execute("""
        CREATE TABLE IF NOT EXISTS school_expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            expense_name TEXT NOT NULL,
            category TEXT NOT NULL,
            amount REAL NOT NULL CHECK (amount > 0),
            expense_date TEXT NOT NULL,
            payment_method TEXT NOT NULL DEFAULT 'Cash',
            reference TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view


@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as connection:
            user = connection.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        flash("Incorrect username or password.", "error")

    return render_template("login.html")


@app.route("/admin/account-settings", methods=["GET", "POST"])
@login_required
def admin_account_settings():
    # Only administrators may access this page.
    if session.get("role") != "admin":
        abort(403)

    with get_db() as connection:
        user = connection.execute(
            """
            SELECT id, username, password_hash, role
            FROM users
            WHERE id = ?
            """,
            (session["user_id"],)
        ).fetchone()

        if user is None:
            session.clear()
            flash("Please log in again.", "error")
            return redirect(url_for("login"))

        if request.method == "POST":
            current_password = request.form.get(
                "current_password", ""
            )
            new_username = request.form.get(
                "username", ""
            ).strip()
            new_password = request.form.get(
                "new_password", ""
            )
            confirm_password = request.form.get(
                "confirm_password", ""
            )

            # Verify the current password first.
            if not check_password_hash(
                user["password_hash"], current_password
            ):
                flash("Your current password is incorrect.", "error")

            elif not new_username:
                flash("Username cannot be empty.", "error")

            elif len(new_username) < 3 or len(new_username) > 50:
                flash(
                    "Username must contain 3 to 50 characters.",
                    "error"
                )

            elif new_password and len(new_password) < 10:
                flash(
                    "The new password must contain at least 10 characters.",
                    "error"
                )

            elif new_password != confirm_password:
                flash("The new passwords do not match.", "error")

            else:
                existing_user = connection.execute(
                    """
                    SELECT id FROM users
                    WHERE username = ? AND id != ?
                    """,
                    (new_username, user["id"])
                ).fetchone()

                if existing_user:
                    flash(
                        "That username is already in use.",
                        "error"
                    )
                else:
                    password_hash = (
                        generate_password_hash(new_password)
                        if new_password
                        else user["password_hash"]
                    )

                    try:
                        connection.execute(
                            """
                            UPDATE users
                            SET username = ?, password_hash = ?
                            WHERE id = ?
                            """,
                            (
                                new_username,
                                password_hash,
                                user["id"]
                            )
                        )

                        # Keep the current session consistent.
                        session["username"] = new_username

                        flash(
                            "Account settings updated successfully.",
                            "success"
                        )
                        return redirect(
                            url_for("admin_account_settings")
                        )

                    except sqlite3.IntegrityError:
                        flash(
                            "That username is already in use.",
                            "error"
                        )

    return render_template(
        "admin_account_settings.html",
        username=user["username"]
    )



@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()

    total_students = conn.execute(
        "SELECT COUNT(*) FROM students"
    ).fetchone()[0]

    male_students = conn.execute(
        "SELECT COUNT(*) FROM students WHERE LOWER(gender) = 'male'"
    ).fetchone()[0]

    female_students = conn.execute(
        "SELECT COUNT(*) FROM students WHERE LOWER(gender) = 'female'"
    ).fetchone()[0]

    total_classes = conn.execute(
        """
        SELECT COUNT(DISTINCT class_name)
        FROM students
        WHERE class_name IS NOT NULL AND TRIM(class_name) != ''
        """
    ).fetchone()[0]

    recent_students = conn.execute(
        """
        SELECT student_code, first_name, last_name, class_name, created_at
        FROM students
        ORDER BY id DESC
        LIMIT 5
        """
    ).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        student_count=total_students,
        total_students=total_students,
        male_students=male_students,
        female_students=female_students,
        total_classes=total_classes,
        recent_students=recent_students
    )

@app.route("/students")
@login_required
def students():
    search = request.args.get("search", "").strip()

    with get_db() as connection:
        if search:
            pattern = f"%{search}%"
            records = connection.execute("""
                SELECT * FROM students
                WHERE student_code LIKE ?
                   OR first_name LIKE ?
                   OR last_name LIKE ?
                   OR class_name LIKE ?
                ORDER BY id DESC
            """, (pattern, pattern, pattern, pattern)).fetchall()
        else:
            records = connection.execute("""
                SELECT * FROM students
                ORDER BY id DESC
            """).fetchall()

        total = connection.execute(
            "SELECT COUNT(*) FROM students"
        ).fetchone()[0]

    return render_template(
        "students.html",
        students=records,
        search=search,
        total=total
    )

def ensure_teachers_table(conn):
    """Create the teachers table if it does not already exist."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS teachers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_code TEXT NOT NULL UNIQUE,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            gender TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT,
            qualification TEXT,
            subject TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()



@app.route("/students/add", methods=["GET", "POST"])
@login_required
def add_student():
    with get_db() as connection:
        ensure_classes_subjects_tables(connection)
        classes = connection.execute("""
            SELECT * FROM school_classes
            ORDER BY class_name ASC
        """).fetchall()

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        gender = request.form.get("gender", "").strip()
        date_of_birth = request.form.get("date_of_birth", "").strip()
        class_name = request.form.get("class_name", "").strip()
        guardian_name = request.form.get("guardian_name", "").strip()
        guardian_phone = request.form.get("guardian_phone", "").strip()
        address = request.form.get("address", "").strip()

        if not all([
            first_name, last_name, gender, class_name,
            guardian_name, guardian_phone
        ]):
            flash("Please complete all required fields.", "error")
            return render_template(
                "student_form.html",
                student=None,
                classes=classes
            )

        if gender not in ("Male", "Female", "Other"):
            abort(400)

        # Make sure the selected class exists.
        valid_class = any(
            school_class["class_name"] == class_name
            for school_class in classes
        )

        if not valid_class:
            flash("Please select a valid class.", "error")
            return render_template(
                "student_form.html",
                student=None,
                classes=classes
            )

        with get_db() as connection:
            cursor = connection.execute("""
                INSERT INTO students (
                    first_name, last_name, gender, date_of_birth,
                    class_name, guardian_name, guardian_phone, address
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                first_name, last_name, gender, date_of_birth,
                class_name, guardian_name, guardian_phone, address
            ))

            student_id = cursor.lastrowid
            student_code = f"STU-{student_id:05d}"

            connection.execute("""
                UPDATE students
                SET student_code = ?
                WHERE id = ?
            """, (student_code, student_id))

        flash(
            f"Student registered successfully. ID: {student_code}",
            "success"
        )
        return redirect(url_for("students"))

    return render_template(
        "student_form.html",
        student=None,
        classes=classes
    )


@app.route("/students/edit/<int:student_id>", methods=["GET", "POST"])
@login_required
def edit_student(student_id):
    with get_db() as connection:
        ensure_classes_subjects_tables(connection)

        student = connection.execute(
            "SELECT * FROM students WHERE id = ?",
            (student_id,)
        ).fetchone()

        classes = connection.execute("""
            SELECT * FROM school_classes
            ORDER BY class_name ASC
        """).fetchall()

    if student is None:
        abort(404)

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        gender = request.form.get("gender", "").strip()
        date_of_birth = request.form.get("date_of_birth", "").strip()
        class_name = request.form.get("class_name", "").strip()
        guardian_name = request.form.get("guardian_name", "").strip()
        guardian_phone = request.form.get("guardian_phone", "").strip()
        address = request.form.get("address", "").strip()

        if not all([
            first_name, last_name, gender, class_name,
            guardian_name, guardian_phone
        ]):
            flash("Please complete all required fields.", "error")
            return render_template(
                "student_form.html",
                student=student,
                classes=classes
            )

        if gender not in ("Male", "Female", "Other"):
            abort(400)

        valid_class = any(
            school_class["class_name"] == class_name
            for school_class in classes
        )

        if not valid_class:
            flash("Please select a valid class.", "error")
            return render_template(
                "student_form.html",
                student=student,
                classes=classes
            )

        with get_db() as connection:
            connection.execute("""
                UPDATE students
                SET first_name = ?, last_name = ?, gender = ?,
                    date_of_birth = ?, class_name = ?,
                    guardian_name = ?, guardian_phone = ?, address = ?
                WHERE id = ?
            """, (
                first_name, last_name, gender, date_of_birth,
                class_name, guardian_name, guardian_phone,
                address, student_id
            ))

        flash("Student information updated successfully.", "success")
        return redirect(url_for("students"))

    return render_template(
        "student_form.html",
        student=student,
        classes=classes
    )

@app.route("/students/delete/<int:student_id>", methods=["POST"])
@login_required
def delete_student(student_id):
    with get_db() as connection:
        student = connection.execute(
            "SELECT id FROM students WHERE id = ?",
            (student_id,)
        ).fetchone()

        if student is None:
            abort(404)

        connection.execute(
            "DELETE FROM students WHERE id = ?",
            (student_id,)
        )

    flash("Student record deleted successfully.", "success")
    return redirect(url_for("students"))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have signed out successfully.", "success")
    return redirect(url_for("login"))


initialize_database()

# ==========================================
# TEACHERS MANAGEMENT
# ==========================================

@app.route("/teachers")
@login_required
def teachers():
    conn = get_db()
    ensure_teachers_table(conn)

    search = request.args.get("search", "").strip()

    if search:
        pattern = f"%{search}%"
        teacher_records = conn.execute(
            """
            SELECT * FROM teachers
            WHERE staff_code LIKE ?
               OR first_name LIKE ?
               OR last_name LIKE ?
               OR phone LIKE ?
               OR subject LIKE ?
            ORDER BY id DESC
            """,
            (pattern, pattern, pattern, pattern, pattern)
        ).fetchall()
    else:
        teacher_records = conn.execute(
            "SELECT * FROM teachers ORDER BY id DESC"
        ).fetchall()

    total_teachers = conn.execute(
        "SELECT COUNT(*) FROM teachers"
    ).fetchone()[0]

    conn.close()

    return render_template(
        "teachers.html",
        teachers=teacher_records,
        total=total_teachers,
        search=search
    )


@app.route("/teachers/add", methods=["GET", "POST"])
@login_required
def add_teacher():
    conn = get_db()
    ensure_teachers_table(conn)

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        gender = request.form.get("gender", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        qualification = request.form.get("qualification", "").strip()
        subject = request.form.get("subject", "").strip()

        if not all([first_name, last_name, gender, phone]):
            flash("Please complete all required fields.", "error")
            conn.close()
            return redirect(url_for("add_teacher"))

        next_id = conn.execute(
            "SELECT COALESCE(MAX(id), 0) + 1 FROM teachers"
        ).fetchone()[0]
        staff_code = f"TCH-{next_id:05d}"

        try:
            conn.execute(
                """
                INSERT INTO teachers (
                    staff_code, first_name, last_name, gender,
                    phone, email, qualification, subject
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    staff_code, first_name, last_name, gender,
                    phone, email, qualification, subject
                )
            )
            conn.commit()
            flash(
                f"Teacher registered successfully. Staff ID: {staff_code}",
                "success"
            )
        except Exception:
            conn.rollback()
            flash(
                "Unable to register this teacher. Please check the details and try again.",
                "error"
            )
            conn.close()
            return redirect(url_for("add_teacher"))

        conn.close()
        return redirect(url_for("teachers"))

    conn.close()
    return render_template("teacher_form.html", teacher=None)


@app.route("/teachers/edit/<int:teacher_id>", methods=["GET", "POST"])
@login_required
def edit_teacher(teacher_id):
    conn = get_db()
    ensure_teachers_table(conn)

    teacher = conn.execute(
        "SELECT * FROM teachers WHERE id = ?",
        (teacher_id,)
    ).fetchone()

    if teacher is None:
        conn.close()
        flash("Teacher record not found.", "error")
        return redirect(url_for("teachers"))

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        gender = request.form.get("gender", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        qualification = request.form.get("qualification", "").strip()
        subject = request.form.get("subject", "").strip()

        if not all([first_name, last_name, gender, phone]):
            flash("Please complete all required fields.", "error")
            conn.close()
            return redirect(
                url_for("edit_teacher", teacher_id=teacher_id)
            )

        conn.execute(
            """
            UPDATE teachers
            SET first_name = ?,
                last_name = ?,
                gender = ?,
                phone = ?,
                email = ?,
                qualification = ?,
                subject = ?
            WHERE id = ?
            """,
            (
                first_name, last_name, gender, phone,
                email, qualification, subject, teacher_id
            )
        )
        conn.commit()
        conn.close()

        flash("Teacher details updated successfully.", "success")
        return redirect(url_for("teachers"))

    conn.close()
    return render_template("teacher_form.html", teacher=teacher)


@app.route("/teachers/delete/<int:teacher_id>", methods=["POST"])
@login_required
def delete_teacher(teacher_id):
    conn = get_db()
    ensure_teachers_table(conn)

    teacher = conn.execute(
        "SELECT id FROM teachers WHERE id = ?",
        (teacher_id,)
    ).fetchone()

    if teacher is None:
        conn.close()
        flash("Teacher record not found.", "error")
        return redirect(url_for("teachers"))

    conn.execute(
        "DELETE FROM teachers WHERE id = ?",
        (teacher_id,)
    )
    conn.commit()
    conn.close()

    flash("Teacher record deleted successfully.", "success")
    return redirect(url_for("teachers"))

@app.route("/classes")
@login_required
def classes():
    conn = get_db()
    ensure_classes_subjects_tables(conn)

    search = request.args.get("search", "").strip()

    if search:
        pattern = f"%{search}%"
        class_records = conn.execute(
            """
            SELECT * FROM school_classes
            WHERE class_name LIKE ?
               OR class_teacher LIKE ?
               OR room LIKE ?
            ORDER BY class_name
            """,
            (pattern, pattern, pattern)
        ).fetchall()
    else:
        class_records = conn.execute(
            "SELECT * FROM school_classes ORDER BY class_name"
        ).fetchall()

    total = conn.execute(
        "SELECT COUNT(*) FROM school_classes"
    ).fetchone()[0]

    conn.close()

    return render_template(
        "classes.html",
        classes=class_records,
        total=total,
        search=search
    )


@app.route("/classes/add", methods=["GET", "POST"])
@login_required
def add_class():
    conn = get_db()
    ensure_classes_subjects_tables(conn)

    if request.method == "POST":
        class_name = request.form.get("class_name", "").strip()
        class_teacher = request.form.get("class_teacher", "").strip()
        room = request.form.get("room", "").strip()

        if not class_name:
            conn.close()
            flash("Please enter a class name.", "error")
            return redirect(url_for("add_class"))

        try:
            conn.execute(
                """
                INSERT INTO school_classes
                (class_name, class_teacher, room)
                VALUES (?, ?, ?)
                """,
                (class_name, class_teacher, room)
            )
            conn.commit()
            flash("Class added successfully.", "success")

        except Exception as error:
            conn.rollback()
            conn.close()

            if "UNIQUE constraint failed" in str(error):
                flash("This class already exists.", "error")
            else:
                flash("Unable to add the class. Please try again.", "error")

            return redirect(url_for("add_class"))

        conn.close()
        return redirect(url_for("classes"))

    conn.close()
    return render_template("class_form.html", class_record=None)


@app.route("/classes/edit/<int:class_id>", methods=["GET", "POST"])
@login_required
def edit_class(class_id):
    conn = get_db()
    ensure_classes_subjects_tables(conn)

    class_record = conn.execute(
        "SELECT * FROM school_classes WHERE id = ?",
        (class_id,)
    ).fetchone()

    if class_record is None:
        conn.close()
        flash("Class not found.", "error")
        return redirect(url_for("classes"))

    if request.method == "POST":
        class_name = request.form.get("class_name", "").strip()
        class_teacher = request.form.get("class_teacher", "").strip()
        room = request.form.get("room", "").strip()

        if not class_name:
            conn.close()
            flash("Please enter a class name.", "error")
            return redirect(
                url_for("edit_class", class_id=class_id)
            )

        try:
            conn.execute(
                """
                UPDATE school_classes
                SET class_name = ?, class_teacher = ?, room = ?
                WHERE id = ?
                """,
                (class_name, class_teacher, room, class_id)
            )
            conn.commit()
            conn.close()
            flash("Class updated successfully.", "success")
            return redirect(url_for("classes"))

        except Exception as error:
            conn.rollback()
            conn.close()

            if "UNIQUE constraint failed" in str(error):
                flash("Another class already has this name.", "error")
            else:
                flash("Unable to update the class.", "error")

            return redirect(
                url_for("edit_class", class_id=class_id)
            )

    conn.close()
    return render_template(
        "class_form.html",
        class_record=class_record
    )


@app.route("/classes/delete/<int:class_id>", methods=["POST"])
@login_required
def delete_class(class_id):
    conn = get_db()
    ensure_classes_subjects_tables(conn)

    existing = conn.execute(
        "SELECT id FROM school_classes WHERE id = ?",
        (class_id,)
    ).fetchone()

    if existing is None:
        conn.close()
        flash("Class not found.", "error")
        return redirect(url_for("classes"))

    conn.execute(
        "DELETE FROM school_classes WHERE id = ?",
        (class_id,)
    )
    conn.commit()
    conn.close()

    flash("Class deleted successfully.", "success")
    return redirect(url_for("classes"))

@app.route("/subjects")
@login_required
def subjects():
    conn = get_db()
    ensure_classes_subjects_tables(conn)

    search = request.args.get("search", "").strip()

    if search:
        pattern = f"%{search}%"
        subject_records = conn.execute(
            """
            SELECT * FROM subjects
            WHERE subject_name LIKE ? OR subject_code LIKE ?
            ORDER BY subject_name
            """,
            (pattern, pattern)
        ).fetchall()
    else:
        subject_records = conn.execute(
            "SELECT * FROM subjects ORDER BY subject_name"
        ).fetchall()

    total = conn.execute(
        "SELECT COUNT(*) FROM subjects"
    ).fetchone()[0]

    conn.close()

    return render_template(
        "subjects.html",
        subjects=subject_records,
        total=total,
        search=search
    )


@app.route("/subjects/add", methods=["GET", "POST"])
@login_required
def add_subject():
    conn = get_db()
    ensure_classes_subjects_tables(conn)

    if request.method == "POST":
        subject_name = request.form.get("subject_name", "").strip()
        subject_code = request.form.get("subject_code", "").strip()

        if not subject_name:
            conn.close()
            flash("Please enter a subject name.", "error")
            return redirect(url_for("add_subject"))

        try:
            conn.execute(
                """
                INSERT INTO subjects (subject_name, subject_code)
                VALUES (?, ?)
                """,
                (subject_name, subject_code)
            )
            conn.commit()
            flash("Subject added successfully.", "success")

        except Exception as error:
            conn.rollback()
            conn.close()

            if "UNIQUE constraint failed" in str(error):
                flash("This subject name already exists.", "error")
            else:
                flash("Unable to add the subject. Please try again.", "error")

            return redirect(url_for("add_subject"))

        conn.close()
        return redirect(url_for("subjects"))

    conn.close()
    return render_template("subject_form.html", subject=None)


@app.route("/subjects/edit/<int:subject_id>", methods=["GET", "POST"])
@login_required
def edit_subject(subject_id):
    conn = get_db()
    ensure_classes_subjects_tables(conn)

    subject = conn.execute(
        "SELECT * FROM subjects WHERE id = ?",
        (subject_id,)
    ).fetchone()

    if subject is None:
        conn.close()
        flash("Subject not found.", "error")
        return redirect(url_for("subjects"))

    if request.method == "POST":
        subject_name = request.form.get("subject_name", "").strip()
        subject_code = request.form.get("subject_code", "").strip()

        if not subject_name:
            conn.close()
            flash("Please enter a subject name.", "error")
            return redirect(
                url_for("edit_subject", subject_id=subject_id)
            )

        try:
            conn.execute(
                """
                UPDATE subjects
                SET subject_name = ?, subject_code = ?
                WHERE id = ?
                """,
                (subject_name, subject_code, subject_id)
            )
            conn.commit()
            conn.close()
            flash("Subject updated successfully.", "success")
            return redirect(url_for("subjects"))

        except Exception as error:
            conn.rollback()
            conn.close()

            if "UNIQUE constraint failed" in str(error):
                flash("Another subject already has this name.", "error")
            else:
                flash("Unable to update the subject.", "error")

            return redirect(
                url_for("edit_subject", subject_id=subject_id)
            )

    conn.close()
    return render_template("subject_form.html", subject=subject)


@app.route("/subjects/delete/<int:subject_id>", methods=["POST"])
@login_required
def delete_subject(subject_id):
    conn = get_db()
    ensure_classes_subjects_tables(conn)

    existing = conn.execute(
        "SELECT id FROM subjects WHERE id = ?",
        (subject_id,)
    ).fetchone()

    if existing is None:
        conn.close()
        flash("Subject not found.", "error")
        return redirect(url_for("subjects"))

    conn.execute(
        "DELETE FROM subjects WHERE id = ?",
        (subject_id,)
    )
    conn.commit()
    conn.close()

    flash("Subject deleted successfully.", "success")
    return redirect(url_for("subjects"))

@app.route("/attendance")
@login_required
def attendance():
    with get_db() as connection:
        ensure_attendance_table(connection)
        ensure_classes_subjects_tables(connection)

        classes = connection.execute("""
            SELECT * FROM school_classes
            ORDER BY class_name ASC
        """).fetchall()

        selected_class = request.args.get("class_name", "").strip()
        attendance_date = request.args.get(
            "attendance_date",
            __import__("datetime").date.today().isoformat()
        )

        students = []

        if selected_class:
            students = connection.execute("""
                SELECT id, student_code, first_name, last_name, class_name
                FROM students
                WHERE class_name = ?
                ORDER BY first_name ASC, last_name ASC
            """, (selected_class,)).fetchall()

    return render_template(
        "attendance.html",
        classes=classes,
        students=students,
        selected_class=selected_class,
        attendance_date=attendance_date
    )

@app.route("/attendance/save", methods=["POST"])
@login_required
def save_attendance():
    attendance_date = request.form.get("attendance_date", "").strip()
    class_name = request.form.get("class_name", "").strip()

    if not attendance_date or not class_name:
        flash("Please select a class and attendance date.", "error")
        return redirect(url_for("attendance"))

    try:
        from datetime import date
        date.fromisoformat(attendance_date)
    except ValueError:
        flash("Please enter a valid attendance date.", "error")
        return redirect(url_for("attendance"))

    with get_db() as connection:
        ensure_attendance_table(connection)

        # Only accept attendance records for students in the selected class.
        students = connection.execute("""
            SELECT id
            FROM students
            WHERE class_name = ?
        """, (class_name,)).fetchall()

        if not students:
            flash("No students were found in the selected class.", "error")
            return redirect(url_for(
                "attendance",
                class_name=class_name,
                attendance_date=attendance_date
            ))

        allowed_statuses = {"Present", "Absent", "Late", "Excused"}

        for student in students:
            student_id = student["id"]
            status = request.form.get(f"status_{student_id}", "").strip()
            remarks = request.form.get(
                f"remarks_{student_id}", ""
            ).strip()

            if status not in allowed_statuses:
                flash("Please select a valid status for every student.", "error")
                return redirect(url_for(
                    "attendance",
                    class_name=class_name,
                    attendance_date=attendance_date
                ))

        for student in students:
            student_id = student["id"]
            status = request.form.get(f"status_{student_id}", "").strip()
            remarks = request.form.get(
                f"remarks_{student_id}", ""
            ).strip()

            connection.execute("""
                INSERT INTO attendance (
                    student_id, attendance_date, status, remarks
                )
                VALUES (?, ?, ?, ?)
                ON CONFLICT(student_id, attendance_date)
                DO UPDATE SET
                    status = excluded.status,
                    remarks = excluded.remarks
            """, (
                student_id,
                attendance_date,
                status,
                remarks
            ))

    flash("Attendance saved successfully.", "success")

    return redirect(url_for(
        "attendance",
        class_name=class_name,
        attendance_date=attendance_date
    ))

@app.route("/attendance/reports")
@login_required
def attendance_reports():
    from datetime import date

    selected_class = request.args.get("class_name", "").strip()
    attendance_date = request.args.get(
        "attendance_date", date.today().isoformat()
    )

    try:
        date.fromisoformat(attendance_date)
    except ValueError:
        attendance_date = date.today().isoformat()

    with get_db() as connection:
        ensure_attendance_table(connection)
        ensure_classes_subjects_tables(connection)

        classes = connection.execute("""
            SELECT class_name
            FROM school_classes
            ORDER BY class_name ASC
        """).fetchall()

        query = """
            SELECT
                a.attendance_date,
                a.status,
                a.remarks,
                s.student_code,
                s.first_name,
                s.last_name,
                s.class_name
            FROM attendance a
            JOIN students s ON s.id = a.student_id
            WHERE a.attendance_date = ?
        """
        params = [attendance_date]

        if selected_class:
            query += " AND s.class_name = ?"
            params.append(selected_class)

        query += " ORDER BY s.class_name, s.first_name, s.last_name"

        records = connection.execute(query, params).fetchall()

    totals = {
        "Present": 0,
        "Absent": 0,
        "Late": 0,
        "Excused": 0
    }

    for record in records:
        if record["status"] in totals:
            totals[record["status"]] += 1

    return render_template(
        "attendance_reports.html",
        classes=classes,
        records=records,
        totals=totals,
        selected_class=selected_class,
        attendance_date=attendance_date
    )

# ==========================================
# EXAMINATIONS AND STUDENT RESULTS
# ==========================================

def calculate_grade(total_score):
    """Calculate a grade from a score out of 100."""

    if total_score >= 80:
        return "A"
    elif total_score >= 70:
        return "B"
    elif total_score >= 60:
        return "C"
    elif total_score >= 50:
        return "D"
    elif total_score >= 40:
        return "E"
    else:
        return "F"


def calculate_remarks(total_score):
    """Return remarks based on the total score."""

    if total_score >= 80:
        return "Excellent"
    elif total_score >= 70:
        return "Very Good"
    elif total_score >= 60:
        return "Good"
    elif total_score >= 50:
        return "Credit"
    elif total_score >= 40:
        return "Pass"
    else:
        return "Needs Improvement"


@app.route("/results")
@login_required
def results():
    with get_db() as connection:
        ensure_classes_subjects_tables(connection)
        ensure_results_table(connection)

        classes = connection.execute("""
            SELECT class_name
            FROM school_classes
            ORDER BY class_name
        """).fetchall()

        subjects = connection.execute("""
            SELECT id, subject_name, subject_code
            FROM subjects
            ORDER BY subject_name
        """).fetchall()

        selected_class = request.args.get(
            "class_name", ""
        ).strip()

        selected_subject = request.args.get(
            "subject_id", ""
        ).strip()

        term = request.args.get("term", "First Term").strip()

        academic_year = request.args.get(
            "academic_year", "2026/2027"
        ).strip()

        students = []

        if selected_class:
            students = connection.execute("""
                SELECT
                    s.id,
                    s.student_code,
                    s.first_name,
                    s.last_name,
                    r.class_score,
                    r.exam_score,
                    r.total_score,
                    r.grade,
                    r.remarks
                FROM students s
                LEFT JOIN results r
                    ON r.student_id = s.id
                    AND r.subject_id = ?
                    AND r.term = ?
                    AND r.academic_year = ?
                WHERE s.class_name = ?
                ORDER BY s.first_name, s.last_name
            """, (
                int(selected_subject)
                if selected_subject.isdigit() else 0,
                term,
                academic_year,
                selected_class
            )).fetchall()

    return render_template(
        "results.html",
        classes=classes,
        subjects=subjects,
        students=students,
        selected_class=selected_class,
        selected_subject=selected_subject,
        term=term,
        academic_year=academic_year
    )


@app.route("/results/save", methods=["POST"])
@login_required
def save_results():
    class_name = request.form.get(
        "class_name", ""
    ).strip()

    subject_id = request.form.get(
        "subject_id", ""
    ).strip()

    term = request.form.get("term", "").strip()

    academic_year = request.form.get(
        "academic_year", ""
    ).strip()

    allowed_terms = {
        "First Term",
        "Second Term",
        "Third Term"
    }

    if (
        not class_name
        or not subject_id.isdigit()
        or term not in allowed_terms
        or not academic_year
    ):
        flash("Please provide valid class, subject, term and academic year.", "error")
        return redirect(url_for("results"))

    try:
        from datetime import date

        if (
            len(academic_year) != 9
            or academic_year[4] != "/"
            or not academic_year[:4].isdigit()
            or not academic_year[5:].isdigit()
            or int(academic_year[5:]) != int(academic_year[:4]) + 1
        ):
            raise ValueError

    except ValueError:
        flash("Enter the academic year in the format 2026/2027.", "error")
        return redirect(url_for(
            "results",
            class_name=class_name,
            subject_id=subject_id,
            term=term,
            academic_year=academic_year
        ))

    try:
        subject_id = int(subject_id)

        with get_db() as connection:
            ensure_classes_subjects_tables(connection)
            ensure_results_table(connection)

            valid_class = connection.execute("""
                SELECT id FROM school_classes
                WHERE class_name = ?
            """, (class_name,)).fetchone()

            valid_subject = connection.execute("""
                SELECT id FROM subjects
                WHERE id = ?
            """, (subject_id,)).fetchone()

            if not valid_class or not valid_subject:
                flash("Please select a valid class and subject.", "error")
                return redirect(url_for("results"))

            students = connection.execute("""
                SELECT id
                FROM students
                WHERE class_name = ?
            """, (class_name,)).fetchall()

            if not students:
                flash("There are no students registered in this class.", "error")
                return redirect(url_for(
                    "results",
                    class_name=class_name,
                    subject_id=subject_id,
                    term=term,
                    academic_year=academic_year
                ))

            for student in students:
                student_id = student["id"]

                class_score_text = request.form.get(
                    f"class_score_{student_id}", ""
                ).strip()

                exam_score_text = request.form.get(
                    f"exam_score_{student_id}", ""
                ).strip()

                if not class_score_text or not exam_score_text:
                    raise ValueError(
                        "Enter both scores for every student."
                    )

                class_score = float(class_score_text)
                exam_score = float(exam_score_text)

                if not (
                    0 <= class_score <= 30
                    and 0 <= exam_score <= 70
                ):
                    raise ValueError(
                        "Class scores must be 0–30 and exam scores 0–70."
                    )

                total_score = round(class_score + exam_score, 2)
                grade = calculate_grade(total_score)
                remarks = calculate_remarks(total_score)

                connection.execute("""
                    INSERT INTO results (
                        student_id,
                        subject_id,
                        class_score,
                        exam_score,
                        total_score,
                        grade,
                        remarks,
                        term,
                        academic_year
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (
                        student_id,
                        subject_id,
                        term,
                        academic_year
                    )
                    DO UPDATE SET
                        class_score = excluded.class_score,
                        exam_score = excluded.exam_score,
                        total_score = excluded.total_score,
                        grade = excluded.grade,
                        remarks = excluded.remarks
                """, (
                    student_id,
                    subject_id,
                    class_score,
                    exam_score,
                    total_score,
                    grade,
                    remarks,
                    term,
                    academic_year
                ))

    except (ValueError, TypeError):
        flash(
            "Invalid scores. Enter numbers only: class score 0–30 and exam score 0–70.",
            "error"
        )
        return redirect(url_for(
            "results",
            class_name=class_name,
            subject_id=subject_id,
            term=term,
            academic_year=academic_year
        ))

    flash("Examination results saved successfully.", "success")

    return redirect(url_for(
        "results",
        class_name=class_name,
        subject_id=subject_id,
        term=term,
        academic_year=academic_year
    ))

# ==========================================
# STUDENT RESULTS REPORT
# ==========================================

@app.route("/results/reports")
@login_required
def results_reports():
    with get_db() as connection:
        ensure_classes_subjects_tables(connection)
        ensure_results_table(connection)

        classes = connection.execute("""
            SELECT class_name
            FROM school_classes
            ORDER BY class_name
        """).fetchall()

        subjects = connection.execute("""
            SELECT id, subject_name
            FROM subjects
            ORDER BY subject_name
        """).fetchall()

        selected_class = request.args.get(
            "class_name", ""
        ).strip()

        selected_subject = request.args.get(
            "subject_id", ""
        ).strip()

        term = request.args.get(
            "term", "First Term"
        ).strip()

        academic_year = request.args.get(
            "academic_year", "2026/2027"
        ).strip()

        records = []
        totals = {
            "students": 0,
            "class_score": 0,
            "exam_score": 0,
            "total_score": 0,
            "passed": 0,
            "failed": 0
        }

        if selected_class and selected_subject.isdigit():
            records = connection.execute("""
                SELECT
                    s.student_code,
                    s.first_name,
                    s.last_name,
                    r.class_score,
                    r.exam_score,
                    r.total_score,
                    r.grade,
                    r.remarks
                FROM results r
                JOIN students s
                    ON s.id = r.student_id
                WHERE s.class_name = ?
                  AND r.subject_id = ?
                  AND r.term = ?
                  AND r.academic_year = ?
                ORDER BY r.total_score DESC,
                         s.first_name ASC,
                         s.last_name ASC
            """, (
                selected_class,
                int(selected_subject),
                term,
                academic_year
            )).fetchall()

            totals["students"] = len(records)

            for record in records:
                totals["class_score"] += record["class_score"]
                totals["exam_score"] += record["exam_score"]
                totals["total_score"] += record["total_score"]

                if record["total_score"] >= 50:
                    totals["passed"] += 1
                else:
                    totals["failed"] += 1

        if totals["students"]:
            average_score = round(
                totals["total_score"] / totals["students"], 2
            )
        else:
            average_score = 0

    return render_template(
        "results_reports.html",
        classes=classes,
        subjects=subjects,
        records=records,
        totals=totals,
        average_score=average_score,
        selected_class=selected_class,
        selected_subject=selected_subject,
        term=term,
        academic_year=academic_year
    )

@app.route("/students/<int:student_id>/report-card")
@login_required
def student_report_card(student_id):
    with get_db() as connection:
        ensure_classes_subjects_tables(connection)
        ensure_results_table(connection)

        # Find the student.
        student = connection.execute("""
            SELECT
                id,
                student_code,
                first_name,
                last_name,
                class_name,
                guardian_name
            FROM students
            WHERE id = ?
        """, (student_id,)).fetchone()

        if student is None:
            abort(404)

        # Get the selected term and academic year.
        term = request.args.get(
            "term", "First Term"
        ).strip()

        academic_year = request.args.get(
            "academic_year", "2026/2027"
        ).strip()

        # Retrieve all recorded subject results for the student.
        records = connection.execute("""
            SELECT
                sub.subject_name,
                r.class_score,
                r.exam_score,
                r.total_score,
                r.grade,
                r.remarks
            FROM results r
            JOIN subjects sub
                ON sub.id = r.subject_id
            WHERE r.student_id = ?
              AND r.term = ?
              AND r.academic_year = ?
            ORDER BY sub.subject_name ASC
        """, (
            student_id,
            term,
            academic_year
        )).fetchall()

        # Calculate the overall performance.
        subject_count = len(records)

        total_score = sum(
            float(record["total_score"] or 0)
            for record in records
        )

        average_score = (
            round(total_score / subject_count, 2)
            if subject_count else 0
        )

        # Retrieve school information.
        settings = connection.execute("""
            SELECT
                school_name,
                school_address,
                school_phone,
                school_email,
                academic_year,
                current_term
            FROM school_settings
            WHERE id = 1
        """).fetchone()

    return render_template(
        "student_report_card.html",
        student=student,
        records=records,
        term=term,
        academic_year=academic_year,
        subject_count=subject_count,
        total_score=total_score,
        average_score=average_score,
        settings=settings
    )


@app.route("/fees")
@login_required
def school_fees():
    conn = get_db()

    try:
        ensure_school_fees_tables(conn)

        # Get search and filter values from the page
        search = request.args.get("search", "").strip().lower()
        academic_year = request.args.get("academic_year", "").strip().lower()
        term = request.args.get("term", "").strip()
        status = request.args.get("status", "").strip().lower()

        # Get all students
        student_rows = conn.execute(
            "SELECT * FROM students ORDER BY id DESC"
        ).fetchall()

        students = []

        for student in student_rows:
            student_data = dict(student)

            student_data["display_name"] = (
                student_data.get("full_name")
                or student_data.get("student_name")
                or " ".join(
                    str(student_data.get(field) or "")
                    for field in ["first_name", "middle_name", "last_name"]
                ).strip()
                or student_data.get("name")
                or f"Student #{student_data['id']}"
            )

            students.append(student_data)

        # Create a lookup for student names
        student_names = {
            student["id"]: student["display_name"]
            for student in students
        }

        # Get all school fee records and their payments
        fee_rows = conn.execute("""
            SELECT
                f.id,
                f.student_id,
                f.fee_name,
                f.amount_due,
                f.academic_year,
                f.term,
                f.created_at,
                COALESCE(
                    (
                        SELECT SUM(p.amount_paid)
                        FROM fee_payments p
                        WHERE p.fee_id = f.id
                    ),
                    0
                ) AS amount_paid
            FROM school_fees f
            ORDER BY f.id DESC
        """).fetchall()

        fees = []

        for fee in fee_rows:
            fee_data = dict(fee)

            fee_data["student_name"] = student_names.get(
                fee_data["student_id"],
                f"Student #{fee_data['student_id']}"
            )

            fee_data["balance"] = (
                float(fee_data["amount_due"])
                - float(fee_data["amount_paid"])
            )

            # Filter by student name or fee name
            if search:
                searchable_text = (
                    fee_data["student_name"] + " "
                    + str(fee_data["fee_name"])
                ).lower()

                if search not in searchable_text:
                    continue

            # Filter by academic year
            if academic_year:
                if academic_year not in str(
                    fee_data["academic_year"]
                ).lower():
                    continue

            # Filter by term
            if term:
                if fee_data["term"] != term:
                    continue

            # Filter by payment status
            if status == "paid":
                if fee_data["balance"] > 0.009:
                    continue

            elif status == "outstanding":
                if fee_data["balance"] <= 0.009:
                    continue

            # Keep records that match all selected filters
            fees.append(fee_data)

        # Calculate totals for the displayed, filtered records
        total_due = sum(
            float(fee["amount_due"]) for fee in fees
        )

        total_paid = sum(
            float(fee["amount_paid"]) for fee in fees
        )

        total_balance = sum(
            fee["balance"] for fee in fees
        )

        # Get payment history
        payment_rows = conn.execute("""
            SELECT
                p.id,
                p.amount_paid,
                p.payment_method,
                p.reference,
                p.payment_date,
                f.fee_name,
                f.academic_year,
                f.term,
                f.student_id
            FROM fee_payments p
            JOIN school_fees f ON f.id = p.fee_id
            ORDER BY p.payment_date DESC, p.id DESC
        """).fetchall()

        payments = []

        for payment in payment_rows:
            payment_data = dict(payment)

            payment_data["student_name"] = student_names.get(
                payment_data["student_id"],
                f"Student #{payment_data['student_id']}"
            )

            payments.append(payment_data)

        # Display the page after all records have been processed
        return render_template(
            "fees.html",
            students=students,
            fees=fees,
            total_due=total_due,
            total_paid=total_paid,
            total_balance=total_balance,
            payments=payments
        )

    finally:
        conn.close()


@app.route("/fee-balances")
@login_required
def fee_balances():
    conn = get_db()

    try:
        ensure_school_fees_tables(conn)

        # Get each student's total fees and payments.
        # Payments are totaled per fee first to avoid double-counting.
        
        
        rows = conn.execute("""
            SELECT
                s.id AS student_id,

                TRIM(
                    COALESCE(s.first_name, '') || ' ' ||
                    COALESCE(s.last_name, '')
                ) AS student_name,

                COALESCE(SUM(f.amount_due), 0) AS total_due,
                COALESCE(SUM(p.paid), 0) AS total_paid

            FROM students AS s

            LEFT JOIN school_fees AS f
                ON f.student_id = s.id

            LEFT JOIN (
                SELECT
                    fee_id,
                    SUM(amount_paid) AS paid
                FROM fee_payments
                GROUP BY fee_id
            ) AS p
                ON p.fee_id = f.id

            GROUP BY
                s.id,
                s.first_name,
                s.last_name

            ORDER BY s.first_name COLLATE NOCASE,
                     s.last_name COLLATE NOCASE
        """).fetchall()

        students = []

        for row in rows:
            student = dict(row)

            student["total_due"] = float(
                student["total_due"] or 0
            )

            student["total_paid"] = float(
                student["total_paid"] or 0
            )

            student["balance"] = max(
                0,
                student["total_due"] - student["total_paid"]
            )

            if student["total_due"] <= 0:
                student["status"] = "No Fees Assigned"
            elif student["balance"] <= 0.009:
                student["status"] = "Paid"
            elif student["total_paid"] > 0:
                student["status"] = "Partial"
            else:
                student["status"] = "Unpaid"

            students.append(student)

        total_due = sum(
            s["total_due"] for s in students
        )

        total_paid = sum(
            s["total_paid"] for s in students
        )

        total_balance = sum(
            s["balance"] for s in students
        )

        return render_template(
            "fee_balances.html",
            students=students,
            total_due=total_due,
            total_paid=total_paid,
            total_balance=total_balance
        )

    finally:
        conn.close()

@app.route("/fees/assign", methods=["POST"])
@login_required
def save_school_fee():
    student_id = request.form.get("student_id", "").strip()
    fee_name = request.form.get("fee_name", "").strip()
    amount_due_text = request.form.get("amount_due", "").strip()
    academic_year = request.form.get("academic_year", "").strip()
    term = request.form.get("term", "").strip()

    if not all([
        student_id,
        fee_name,
        amount_due_text,
        academic_year,
        term
    ]):
        flash("Please complete all fee assignment fields.", "error")
        return redirect(url_for("school_fees"))

    try:
        student_id = int(student_id)
        amount_due = float(amount_due_text)

        if amount_due <= 0:
            flash("The fee amount must be greater than zero.", "error")
            return redirect(url_for("school_fees"))

    except ValueError:
        flash("Please enter a valid student and fee amount.", "error")
        return redirect(url_for("school_fees"))

    conn = get_db()

    try:
        ensure_school_fees_tables(conn)

        student = conn.execute(
            "SELECT id FROM students WHERE id = ?",
            (student_id,)
        ).fetchone()

        if student is None:
            flash("The selected student could not be found.", "error")
            return redirect(url_for("school_fees"))

        conn.execute("""
            INSERT INTO school_fees (
                student_id,
                fee_name,
                amount_due,
                academic_year,
                term
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            student_id,
            fee_name,
            amount_due,
            academic_year,
            term
        ))

        conn.commit()
        flash("School fee assigned successfully.", "success")

    except sqlite3.IntegrityError:
        conn.rollback()
        flash(
            "This fee has already been assigned to that student "
            "for the selected academic year and term.",
            "error"
        )

    finally:
        conn.close()

    return redirect(url_for("school_fees"))


@app.route("/fees/payment", methods=["POST"])
@login_required
def record_fee_payment():
    fee_id = request.form.get("fee_id", "").strip()
    amount_paid_text = request.form.get("amount_paid", "").strip()
    payment_method = request.form.get("payment_method", "Cash").strip()
    reference = request.form.get("reference", "").strip()
    payment_date = request.form.get("payment_date", "").strip()

    if not all([fee_id, amount_paid_text, payment_date]):
        flash("Please complete all required payment fields.", "error")
        return redirect(url_for("school_fees"))

    try:
        fee_id = int(fee_id)
        amount_paid = float(amount_paid_text)

        if amount_paid <= 0:
            flash("Payment must be greater than zero.", "error")
            return redirect(url_for("school_fees"))

    except ValueError:
        flash("Please enter a valid payment amount.", "error")
        return redirect(url_for("school_fees"))

    conn = get_db()

    try:
        ensure_school_fees_tables(conn)

        fee = conn.execute("""
            SELECT
                f.amount_due,
                COALESCE(
                    (
                        SELECT SUM(p.amount_paid)
                        FROM fee_payments p
                        WHERE p.fee_id = f.id
                    ),
                    0
                ) AS amount_paid
            FROM school_fees f
            WHERE f.id = ?
        """, (fee_id,)).fetchone()

        if fee is None:
            flash("The selected fee record could not be found.", "error")
            return redirect(url_for("school_fees"))

        balance = float(fee["amount_due"]) - float(fee["amount_paid"])

        if amount_paid > balance:
            flash(
                f"Payment exceeds the outstanding balance of "
                f"{balance:.2f}. Please enter a smaller amount.",
                "error"
            )
            return redirect(url_for("school_fees"))

        conn.execute("""
            INSERT INTO fee_payments (
                fee_id,
                amount_paid,
                payment_method,
                reference,
                payment_date
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            fee_id,
            amount_paid,
            payment_method or "Cash",
            reference,
            payment_date
        ))

        conn.commit()
        flash("Payment recorded successfully.", "success")

    finally:
        conn.close()

    return redirect(url_for("school_fees"))

@app.route("/fees/receipt/<int:payment_id>")
@login_required
def fee_payment_receipt(payment_id):
    conn = get_db()

    try:
        ensure_school_fees_tables(conn)

        payment = conn.execute("""
            SELECT
                p.id AS payment_id,
                p.amount_paid,
                p.payment_method,
                p.reference,
                p.payment_date,
                p.recorded_at,
                f.fee_name,
                f.amount_due,
                f.academic_year,
                f.term,
                f.student_id,
                COALESCE(
                    (
                        SELECT SUM(p2.amount_paid)
                        FROM fee_payments p2
                        WHERE p2.fee_id = f.id
                    ),
                    0
                ) AS total_paid,
                s.*
            FROM fee_payments p
            JOIN school_fees f ON f.id = p.fee_id
            JOIN students s ON s.id = f.student_id
            WHERE p.id = ?
        """, (payment_id,)).fetchone()

        if payment is None:
            abort(404)

        student = dict(payment)

        student_name = (
            student.get("full_name")
            or student.get("student_name")
            or " ".join(
                str(student.get(field) or "")
                for field in ["first_name", "middle_name", "last_name"]
            ).strip()
            or student.get("name")
            or f"Student #{student['student_id']}"
        )

        balance = (
            float(student["amount_due"])
            - float(student["total_paid"])
        )

        return render_template(
            "fee_receipt.html",
            payment=student,
            student_name=student_name,
            balance=balance
        )

    finally:
        conn.close()
        

@app.route("/expenses")
@login_required
def school_expenses():
    conn = get_db()

    try:
        ensure_school_expenses_table(conn)

        # Read the search and filter values
        search = request.args.get("search", "").strip()
        category = request.args.get("category", "").strip()
        payment_method = request.args.get("payment_method", "").strip()
        start_date = request.args.get("start_date", "").strip()
        end_date = request.args.get("end_date", "").strip()

        # Build the query safely using placeholders
        query = """
            SELECT *
            FROM school_expenses
            WHERE 1 = 1
        """
        params = []

        if search:
            query += """
                AND (
                    LOWER(expense_name) LIKE ?
                    OR LOWER(category) LIKE ?
                    OR LOWER(COALESCE(reference, '')) LIKE ?
                )
            """
            keyword = f"%{search.lower()}%"
            params.extend([keyword, keyword, keyword])

        if category:
            query += " AND category = ?"
            params.append(category)

        if payment_method:
            query += " AND payment_method = ?"
            params.append(payment_method)

        if start_date:
            query += " AND expense_date >= ?"
            params.append(start_date)

        if end_date:
            query += " AND expense_date <= ?"
            params.append(end_date)

        query += " ORDER BY expense_date DESC, id DESC"

        expenses = conn.execute(query, params).fetchall()

        # Calculate the total for the matching records
        total_expenses = sum(
            float(expense["amount"]) for expense in expenses
        )

        return render_template(
            "expenses.html",
            expenses=expenses,
            total_expenses=total_expenses
        )

    finally:
        conn.close()



@app.route("/expenses/save", methods=["POST"])
@login_required
def save_school_expense():
    conn = get_db()

    try:
        ensure_school_expenses_table(conn)

        expense_name = request.form.get(
            "expense_name", ""
        ).strip()

        category = request.form.get(
            "category", ""
        ).strip()

        amount_text = request.form.get(
            "amount", ""
        ).strip()

        expense_date = request.form.get(
            "expense_date", ""
        ).strip()

        payment_method = request.form.get(
            "payment_method", "Cash"
        ).strip()

        reference = request.form.get(
            "reference", ""
        ).strip()

        notes = request.form.get(
            "notes", ""
        ).strip()

        # Check required fields
        if not all([
            expense_name,
            category,
            amount_text,
            expense_date,
            payment_method
        ]):
            flash("Please complete all required expense fields.", "error")
            return redirect(url_for("school_expenses"))

        # Validate the expense amount
        try:
            amount = float(amount_text)

            if not math.isfinite(amount) or amount <= 0:
                raise ValueError

        except (ValueError, OverflowError):
            flash("Enter a valid expense amount greater than zero.", "error")
            return redirect(url_for("school_expenses"))

        # Save the expense
        conn.execute("""
            INSERT INTO school_expenses (
                expense_name,
                category,
                amount,
                expense_date,
                payment_method,
                reference,
                notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            expense_name,
            category,
            amount,
            expense_date,
            payment_method,
            reference,
            notes
        ))

        conn.commit()

        flash("Expense recorded successfully!", "success")
        return redirect(url_for("school_expenses"))

    except Exception:
        conn.rollback()
        app.logger.exception("Unable to save school expense")
        flash("Unable to save the expense. Please check the server error.", "error")
        return redirect(url_for("school_expenses"))

    finally:
        conn.close()

@app.route("/expenses/edit/<int:expense_id>", methods=["GET", "POST"])
@login_required
def edit_school_expense(expense_id):
    conn = get_db()

    try:
        ensure_school_expenses_table(conn)

        expense = conn.execute(
            "SELECT * FROM school_expenses WHERE id = ?",
            (expense_id,)
        ).fetchone()

        if expense is None:
            abort(404)

        if request.method == "POST":
            expense_name = request.form.get(
                "expense_name", ""
            ).strip()

            category = request.form.get(
                "category", ""
            ).strip()

            amount_text = request.form.get(
                "amount", ""
            ).strip()

            expense_date = request.form.get(
                "expense_date", ""
            ).strip()

            payment_method = request.form.get(
                "payment_method", ""
            ).strip()

            reference = request.form.get(
                "reference", ""
            ).strip()

            notes = request.form.get(
                "notes", ""
            ).strip()

            if not all([
                expense_name,
                category,
                amount_text,
                expense_date,
                payment_method
            ]):
                flash("Please complete all required fields.", "error")
                return redirect(
                    url_for("edit_school_expense", expense_id=expense_id)
                )

            try:
                amount = float(amount_text)

                if not math.isfinite(amount) or amount <= 0:
                    raise ValueError

            except (ValueError, OverflowError):
                flash("Enter a valid amount greater than zero.", "error")
                return redirect(
                    url_for("edit_school_expense", expense_id=expense_id)
                )

            conn.execute("""
                UPDATE school_expenses
                SET expense_name = ?,
                    category = ?,
                    amount = ?,
                    expense_date = ?,
                    payment_method = ?,
                    reference = ?,
                    notes = ?
                WHERE id = ?
            """, (
                expense_name,
                category,
                amount,
                expense_date,
                payment_method,
                reference,
                notes,
                expense_id
            ))

            conn.commit()
            flash("Expense updated successfully!", "success")
            return redirect(url_for("school_expenses"))

        return render_template(
            "edit_expense.html",
            expense=expense
        )

    finally:
        conn.close()

@app.route("/expenses/delete/<int:expense_id>", methods=["POST"])
@login_required
def delete_school_expense(expense_id):
    conn = get_db()

    try:
        ensure_school_expenses_table(conn)

        expense = conn.execute(
            "SELECT id FROM school_expenses WHERE id = ?",
            (expense_id,)
        ).fetchone()

        if expense is None:
            abort(404)

        conn.execute(
            "DELETE FROM school_expenses WHERE id = ?",
            (expense_id,)
        )

        conn.commit()
        flash("Expense deleted successfully.", "success")

    except Exception:
        conn.rollback()
        app.logger.exception("Unable to delete school expense")
        flash("Unable to delete this expense.", "error")

    finally:
        conn.close()

    return redirect(url_for("school_expenses"))


@app.route("/financial-reports")
@login_required
def financial_reports():
    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()

    conn = get_db()

    try:
        ensure_school_fees_tables(conn)
        ensure_school_expenses_table(conn)

        # 1. Calculate total fee income for the selected period.
        payment_sql = """
            SELECT
                COALESCE(SUM(amount_paid), 0) AS total_income,
                COUNT(*) AS payment_count
            FROM fee_payments
            WHERE 1 = 1
        """
        payment_params = []

        if start_date:
            payment_sql += " AND payment_date >= ?"
            payment_params.append(start_date)

        if end_date:
            payment_sql += " AND payment_date <= ?"
            payment_params.append(end_date)

        payment_result = conn.execute(
            payment_sql, payment_params
        ).fetchone()

        total_income = float(payment_result["total_income"])
        payment_count = int(payment_result["payment_count"])

        # 2. Calculate total expenses for the selected period.
        expense_sql = """
            SELECT
                COALESCE(SUM(amount), 0) AS total_expenses,
                COUNT(*) AS expense_count
            FROM school_expenses
            WHERE 1 = 1
        """
        expense_params = []

        if start_date:
            expense_sql += " AND expense_date >= ?"
            expense_params.append(start_date)

        if end_date:
            expense_sql += " AND expense_date <= ?"
            expense_params.append(end_date)

        expense_result = conn.execute(
            expense_sql, expense_params
        ).fetchone()

        total_expenses = float(expense_result["total_expenses"])
        expense_count = int(expense_result["expense_count"])

        net_balance = total_income - total_expenses

        # 3. Get monthly income, respecting the date filters.
        monthly_income_sql = """
            SELECT
                strftime('%Y-%m', payment_date) AS month_key,
                COALESCE(SUM(amount_paid), 0) AS amount
            FROM fee_payments
            WHERE payment_date IS NOT NULL
              AND payment_date != ''
        """
        monthly_income_params = []

        if start_date:
            monthly_income_sql += " AND payment_date >= ?"
            monthly_income_params.append(start_date)

        if end_date:
            monthly_income_sql += " AND payment_date <= ?"
            monthly_income_params.append(end_date)

        monthly_income_sql += """
            GROUP BY strftime('%Y-%m', payment_date)
            ORDER BY month_key
        """

        monthly_income_rows = conn.execute(
            monthly_income_sql,
            monthly_income_params
        ).fetchall()

        # 4. Get monthly expenses, respecting the date filters.
        monthly_expense_sql = """
            SELECT
                strftime('%Y-%m', expense_date) AS month_key,
                COALESCE(SUM(amount), 0) AS amount
            FROM school_expenses
            WHERE expense_date IS NOT NULL
              AND expense_date != ''
        """
        monthly_expense_params = []

        if start_date:
            monthly_expense_sql += " AND expense_date >= ?"
            monthly_expense_params.append(start_date)

        if end_date:
            monthly_expense_sql += " AND expense_date <= ?"
            monthly_expense_params.append(end_date)

        monthly_expense_sql += """
            GROUP BY strftime('%Y-%m', expense_date)
            ORDER BY month_key
        """

        monthly_expense_rows = conn.execute(
            monthly_expense_sql,
            monthly_expense_params
        ).fetchall()

        # 5. Combine income and expenses into one monthly summary.
        monthly_data = {}

        for row in monthly_income_rows:
            month_key = row["month_key"]

            if month_key:
                monthly_data.setdefault(
                    month_key,
                    {"income": 0.0, "expenses": 0.0}
                )
                monthly_data[month_key]["income"] = float(
                    row["amount"]
                )

        for row in monthly_expense_rows:
            month_key = row["month_key"]

            if month_key:
                monthly_data.setdefault(
                    month_key,
                    {"income": 0.0, "expenses": 0.0}
                )
                monthly_data[month_key]["expenses"] = float(
                    row["amount"]
                )

        monthly_summary = []

        for month_key in sorted(monthly_data.keys()):
            income = monthly_data[month_key]["income"]
            expenses = monthly_data[month_key]["expenses"]

            # Convert YYYY-MM to a readable month label.
            from datetime import datetime
            month_label = datetime.strptime(
                month_key, "%Y-%m"
            ).strftime("%B %Y")

            monthly_summary.append({
                "month_key": month_key,
                "month": month_label,
                "income": income,
                "expenses": expenses,
                "balance": income - expenses
            })

        # Chart data is passed to the template separately.
        chart_labels = [
            item["month"] for item in monthly_summary
        ]
        chart_income = [
            item["income"] for item in monthly_summary
        ]
        chart_expenses = [
            item["expenses"] for item in monthly_summary
        ]
        chart_balance = [
            item["balance"] for item in monthly_summary
        ]

        # 6. Recent fee payments for the selected period.
        recent_payments_sql = """
            SELECT
                id,
                fee_id,
                amount_paid,
                payment_method,
                reference,
                payment_date
            FROM fee_payments
            WHERE 1 = 1
        """
        recent_payment_params = []

        if start_date:
            recent_payments_sql += " AND payment_date >= ?"
            recent_payment_params.append(start_date)

        if end_date:
            recent_payments_sql += " AND payment_date <= ?"
            recent_payment_params.append(end_date)

        recent_payments_sql += """
            ORDER BY payment_date DESC, id DESC
            LIMIT 10
        """

        recent_payments = conn.execute(
            recent_payments_sql,
            recent_payment_params
        ).fetchall()

        # 7. Recent expenses for the selected period.
        recent_expenses_sql = """
            SELECT
                id,
                expense_name,
                category,
                amount,
                payment_method,
                expense_date
            FROM school_expenses
            WHERE 1 = 1
        """
        recent_expense_params = []

        if start_date:
            recent_expenses_sql += " AND expense_date >= ?"
            recent_expense_params.append(start_date)

        if end_date:
            recent_expenses_sql += " AND expense_date <= ?"
            recent_expense_params.append(end_date)

        recent_expenses_sql += """
            ORDER BY expense_date DESC, id DESC
            LIMIT 10
        """

        recent_expenses = conn.execute(
            recent_expenses_sql,
            recent_expense_params
        ).fetchall()

    finally:
        conn.close()

    return render_template(
        "financial_reports.html",
        start_date=start_date,
        end_date=end_date,
        total_income=total_income,
        total_expenses=total_expenses,
        net_balance=net_balance,
        payment_count=payment_count,
        expense_count=expense_count,
        recent_payments=recent_payments,
        recent_expenses=recent_expenses,
        monthly_summary=monthly_summary,
        chart_labels=chart_labels,
        chart_income=chart_income,
        chart_expenses=chart_expenses,
        chart_balance=chart_balance
    )

@app.route("/financial-dashboard")
@login_required
def financial_dashboard():
    from datetime import date

    today = date.today()
    current_month = today.strftime("%Y-%m")
    current_month_start = today.replace(day=1).isoformat()

    # Find the first month to include in the six-month chart.
    month_cursor = today.replace(day=1)
    for _ in range(5):
        if month_cursor.month == 1:
            month_cursor = month_cursor.replace(
                year=month_cursor.year - 1, month=12
            )
        else:
            month_cursor = month_cursor.replace(
                month=month_cursor.month - 1
            )

    first_chart_month = month_cursor.strftime("%Y-%m")
    chart_start_date = month_cursor.isoformat()

    # Prepare six consecutive month labels, including months with no data.
    chart_months = []
    cursor = month_cursor

    for _ in range(6):
        chart_months.append({
            "key": cursor.strftime("%Y-%m"),
            "label": cursor.strftime("%b %Y"),
            "income": 0.0,
            "expenses": 0.0,
        })

        if cursor.month == 12:
            cursor = cursor.replace(
                year=cursor.year + 1, month=1
            )
        else:
            cursor = cursor.replace(month=cursor.month + 1)

    conn = get_db()

    try:
        ensure_school_fees_tables(conn)
        ensure_school_expenses_table(conn)

        # Current-month fee income and number of payments.
        income_result = conn.execute("""
            SELECT
                COALESCE(SUM(amount_paid), 0) AS total_income,
                COUNT(*) AS payment_count
            FROM fee_payments
            WHERE payment_date >= ?
              AND payment_date < date(?, '+1 month')
        """, (current_month_start, current_month_start)).fetchone()

        # Current-month expenses.
        expense_result = conn.execute("""
            SELECT COALESCE(SUM(amount), 0) AS total_expenses
            FROM school_expenses
            WHERE expense_date >= ?
              AND expense_date < date(?, '+1 month')
        """, (current_month_start, current_month_start)).fetchone()

        monthly_income = float(income_result["total_income"])
        monthly_expenses = float(expense_result["total_expenses"])
        monthly_balance = monthly_income - monthly_expenses
        payment_count = int(income_result["payment_count"])

        # Group fee payments by month for the chart.
        income_rows = conn.execute("""
            SELECT
                strftime('%Y-%m', payment_date) AS month_key,
                COALESCE(SUM(amount_paid), 0) AS total
            FROM fee_payments
            WHERE payment_date >= ?
              AND payment_date < date(?, '+1 month')
            GROUP BY strftime('%Y-%m', payment_date)
        """, (chart_start_date, today.isoformat())).fetchall()

        # Group expenses by month for the chart.
        expense_rows = conn.execute("""
            SELECT
                strftime('%Y-%m', expense_date) AS month_key,
                COALESCE(SUM(amount), 0) AS total
            FROM school_expenses
            WHERE expense_date >= ?
              AND expense_date < date(?, '+1 day')
            GROUP BY strftime('%Y-%m', expense_date)
        """, (chart_start_date, today.isoformat())).fetchall()

        income_by_month = {
            row["month_key"]: float(row["total"])
            for row in income_rows if row["month_key"]
        }

        expenses_by_month = {
            row["month_key"]: float(row["total"])
            for row in expense_rows if row["month_key"]
        }

        for month in chart_months:
            month["income"] = income_by_month.get(month["key"], 0.0)
            month["expenses"] = expenses_by_month.get(month["key"], 0.0)

        # Latest five fee payments.
        recent_payments = conn.execute("""
            SELECT
                p.id,
                p.amount_paid,
                p.payment_method,
                p.payment_date,
                p.reference,
                s.fee_name,
                st.first_name,
                st.last_name
            FROM fee_payments p
            JOIN school_fees s ON s.id = p.fee_id
            JOIN students st ON st.id = s.student_id
            ORDER BY p.payment_date DESC, p.id DESC
            LIMIT 5
        """).fetchall()

        # Latest five recorded expenses.
        recent_expenses = conn.execute("""
            SELECT
                id, expense_name, category, amount,
                payment_method, expense_date
            FROM school_expenses
            ORDER BY expense_date DESC, id DESC
            LIMIT 5
        """).fetchall()

    finally:
        conn.close()

    return render_template(
        "financial_dashboard.html",
        current_month=today.strftime("%B %Y"),
        monthly_income=monthly_income,
        monthly_expenses=monthly_expenses,
        monthly_balance=monthly_balance,
        payment_count=payment_count,
        chart_labels=[m["label"] for m in chart_months],
        chart_income=[m["income"] for m in chart_months],
        chart_expenses=[m["expenses"] for m in chart_months],
        recent_payments=recent_payments,
        recent_expenses=recent_expenses,
    )

@app.route("/debug-student-columns")
@login_required
def debug_student_columns():
    conn = get_db()

    try:
        columns = conn.execute(
            "PRAGMA table_info(students)"
        ).fetchall()

        return "<h2>Students table columns</h2><pre>" + "\n".join(
            str(dict(column)) for column in columns
        ) + "</pre>"

    finally:
        conn.close()
        
@app.route("/fee-payment-history")
@login_required
def fee_payment_history():
    conn = get_db()

    try:
        ensure_school_fees_tables(conn)

        payments = conn.execute("""
            SELECT
                p.id AS payment_id,
                p.amount_paid,
                p.payment_method,
                p.reference,
                p.payment_date,
                p.recorded_at,
                s.student_code,
                s.first_name,
                s.last_name,
                f.fee_name,
                f.academic_year,
                f.term
            FROM fee_payments p
            JOIN school_fees f ON p.fee_id = f.id
            JOIN students s ON f.student_id = s.id
            ORDER BY p.payment_date DESC, p.id DESC
        """).fetchall()

        total_payments = len(payments)
        total_collected = sum(
            float(payment["amount_paid"] or 0)
            for payment in payments
        )



        return render_template(
            "fee_payment_history.html",
            payments=payments,
            total_payments=total_payments,
            total_collected=total_collected
        )

    finally:
        conn.close()

@app.route("/fee-payment-history/export")
@login_required
def export_fee_payment_history():
    conn = get_db()

    try:
        ensure_school_fees_tables(conn)

        payments = conn.execute("""
            SELECT
                p.payment_date,
                s.student_code,
                s.first_name,
                s.last_name,
                f.fee_name,
                f.academic_year,
                f.term,
                p.amount_paid,
                p.payment_method,
                p.reference
            FROM fee_payments p
            JOIN school_fees f ON p.fee_id = f.id
            JOIN students s ON f.student_id = s.id
            ORDER BY p.payment_date DESC, p.id DESC
        """).fetchall()

        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            "Payment Date",
            "Student ID",
            "First Name",
            "Last Name",
            "Fee Name",
            "Academic Year",
            "Term",
            "Amount Paid",
            "Payment Method",
            "Reference"
        ])

        for payment in payments:
            writer.writerow([
                payment["payment_date"],
                payment["student_code"],
                payment["first_name"],
                payment["last_name"],
                payment["fee_name"],
                payment["academic_year"],
                payment["term"],
                payment["amount_paid"],
                payment["payment_method"],
                payment["reference"]
            ])

        response = make_response("\ufeff" + output.getvalue())
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = (
            "attachment; filename=schoolcore_fee_payment_history.csv"
        )

        return response

    finally:
        conn.close()
        

@app.route("/fees/payment/<int:payment_id>/receipt")
@login_required
def fee_payment_receipt_page(payment_id):
    conn = get_db()

    try:
        ensure_school_fees_tables(conn)

        payment = conn.execute("""
            SELECT
                p.id AS payment_id,
                p.amount_paid,
                p.payment_method,
                p.reference,
                p.payment_date,
                p.recorded_at,
                s.student_code,
                s.first_name,
                s.last_name,
                s.class_name,
                f.fee_name,
                f.academic_year,
                f.term
            FROM fee_payments p
            JOIN school_fees f ON p.fee_id = f.id
            JOIN students s ON f.student_id = s.id
            WHERE p.id = ?
        """, (payment_id,)).fetchone()

        if payment is None:
            flash(
                "Payment receipt could not be found.",
                "error"
            )
            return redirect(url_for("fee_payment_history"))

        settings = conn.execute("""
            SELECT
                school_name,
                school_address,
                school_phone,
                school_email,
                academic_year,
                current_term
            FROM school_settings
            WHERE id = 1
        """).fetchone()

        return render_template(
            "fee_payment_receipt.html",
            payment=payment,
            settings=settings
        )

    finally:
        conn.close()

        
# ==========================================
# STUDENT PROFILE
# ==========================================

@app.route("/students/<int:student_id>/profile")
@login_required
def student_profile(student_id):
    conn = get_db()

    try:
        # Ensure the existing fee tables are available.
        ensure_school_fees_tables(conn)

        # Get the selected student's actual database record.
        student = conn.execute("""
            SELECT
                id,
                student_code,
                first_name,
                last_name,
                gender,
                date_of_birth,
                class_name,
                guardian_name,
                guardian_phone,
                address,
                created_at
            FROM students
            WHERE id = ?
        """, (student_id,)).fetchone()

        if student is None:
            abort(404)

        # Get all fee records for this student.
        fee_records = conn.execute("""
            SELECT
                f.id,
                f.fee_name,
                f.amount_due,
                f.academic_year,
                f.term,
                f.created_at,
                COALESCE(
                    (
                        SELECT SUM(p.amount_paid)
                        FROM fee_payments p
                        WHERE p.fee_id = f.id
                    ),
                    0
                ) AS amount_paid
            FROM school_fees f
            WHERE f.student_id = ?
            ORDER BY f.id DESC
        """, (student_id,)).fetchall()

        # Get the student's individual payment history.
        payment_history = conn.execute("""
            SELECT
                p.id AS payment_id,
                p.amount_paid,
                p.payment_method,
                p.reference,
                p.payment_date,
                p.recorded_at,
                f.fee_name,
                f.academic_year,
                f.term
            FROM fee_payments p
            INNER JOIN school_fees f
                ON f.id = p.fee_id
            WHERE f.student_id = ?
            ORDER BY p.payment_date DESC, p.id DESC
        """, (student_id,)).fetchall()

        # Calculate totals from the existing records.
        total_fees = sum(
            float(fee["amount_due"] or 0)
            for fee in fee_records
        )

        total_paid = sum(
            float(payment["amount_paid"] or 0)
            for payment in payment_history
        )

        outstanding_balance = max(
            0.0,
            total_fees - total_paid
        )

        return render_template(
            "student_profile.html",
            student=student,
            fee_records=fee_records,
            payment_history=payment_history,
            total_fees=total_fees,
            total_paid=total_paid,
            outstanding_balance=outstanding_balance
        )

    finally:
        conn.close()

# ==========================================
# INDIVIDUAL STUDENT FEE STATEMENT
# ==========================================

@app.route("/students/<int:student_id>/fee-statement")
@login_required
def student_fee_statement(student_id):
    conn = get_db()

    try:
        ensure_school_fees_tables(conn)

        # Find the student.
        student = conn.execute("""
            SELECT
                id,
                student_code,
                first_name,
                last_name,
                gender,
                class_name,
                guardian_name,
                guardian_phone,
                address
            FROM students
            WHERE id = ?
        """, (student_id,)).fetchone()

        if student is None:
            abort(404)

        # Get every fee assigned to this student.
        fee_records = conn.execute("""
            SELECT
                f.id AS fee_id,
                f.fee_name,
                f.amount_due,
                f.academic_year,
                f.term,
                COALESCE(
                    (
                        SELECT SUM(p.amount_paid)
                        FROM fee_payments p
                        WHERE p.fee_id = f.id
                    ),
                    0
                ) AS amount_paid
            FROM school_fees f
            WHERE f.student_id = ?
            ORDER BY
                f.academic_year DESC,
                f.term ASC,
                f.id DESC
        """, (student_id,)).fetchall()

        # Get every payment made by this student.
        payment_history = conn.execute("""
            SELECT
                p.id AS payment_id,
                p.amount_paid,
                p.payment_method,
                p.reference,
                p.payment_date,
                f.fee_name,
                f.academic_year,
                f.term
            FROM fee_payments p
            JOIN school_fees f ON f.id = p.fee_id
            WHERE f.student_id = ?
            ORDER BY p.payment_date DESC, p.id DESC
        """, (student_id,)).fetchall()

        # Calculate totals.
        total_fees = sum(
            float(fee["amount_due"] or 0)
            for fee in fee_records
        )

        total_paid = sum(
            float(payment["amount_paid"] or 0)
            for payment in payment_history
        )

        outstanding_balance = max(
            0.0,
            total_fees - total_paid
        )

        
        # Get the school information.
        settings = conn.execute("""
            SELECT
                school_name,
                school_address,
                school_phone,
                school_email,
                academic_year,
                current_term
            FROM school_settings
            WHERE id = 1
        """).fetchone()

        return render_template(
            "student_fee_statement.html",
            student=student,
            fee_records=fee_records,
            payment_history=payment_history,
            total_fees=total_fees,
            total_paid=total_paid,
            outstanding_balance=outstanding_balance,
            settings=settings
        )

        

    finally:
        conn.close()

@app.route("/school-settings", methods=["GET", "POST"])
def school_settings():
    with get_db() as connection:

        if request.method == "POST":
            school_name = request.form.get(
                "school_name", "SchoolCore"
            ).strip()

            school_address = request.form.get(
                "school_address", ""
            ).strip()

            school_phone = request.form.get(
                "school_phone", ""
            ).strip()

            school_email = request.form.get(
                "school_email", ""
            ).strip()

            academic_year = request.form.get(
                "academic_year", ""
            ).strip()

            current_term = request.form.get(
                "current_term", ""
            ).strip()

            if not school_name:
                flash("Please enter the school name.", "error")
            else:
                connection.execute(
                    """
                    UPDATE school_settings
                    SET school_name = ?,
                        school_address = ?,
                        school_phone = ?,
                        school_email = ?,
                        academic_year = ?,
                        current_term = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = 1
                    """,
                    (
                        school_name,
                        school_address,
                        school_phone,
                        school_email,
                        academic_year,
                        current_term
                    )
                )

                flash("School settings saved successfully.", "success")
                return redirect(url_for("school_settings"))

        settings = connection.execute(
            "SELECT * FROM school_settings WHERE id = 1"
        ).fetchone()

    return render_template(
        "school_settings.html",
        settings=settings
    )

if __name__ == "__main__":
    app.run(debug=True)
