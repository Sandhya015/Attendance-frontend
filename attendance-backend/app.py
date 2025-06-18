print("✅ Flask app.py loaded!")

from flask import Flask, request, jsonify, Response
from datetime import datetime, timedelta
from bson.json_util import dumps
from bson.binary import Binary
from flask_jwt_extended import (
    jwt_required, get_jwt_identity,
    create_access_token, get_jwt
)
from flask_jwt_extended.exceptions import JWTExtendedException
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from pymongo import MongoClient
import bcrypt
import re
import io
from werkzeug.security import generate_password_hash, check_password_hash
from io import StringIO
import csv
from bson.objectid import ObjectId
import os
import csv
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from datetime import datetime


# ==== App Setup ====
app = Flask(__name__)
CORS(app, supports_credentials=True, origins="*", expose_headers=["Authorization"])
app.config['JWT_SECRET_KEY'] = "16c8733b8d05fa2e4c9649465b8ea78c34ca4ba1f342bc6a84b5d6d553052ed5"
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=8)
jwt = JWTManager(app)

# ==== MongoDB Setup ====
client = MongoClient("mongodb://localhost:27017")
db = client['attendance_db']
users_col = db['users']
logs_col = db['attendance_logs']
leave_requests = db['leave_requests']
records_col = db["records"]
attendance_col = db["attendance_logs"]
leave_col = db["leave_requests"] 
pending_checkins_col = db["pending_checkins"]

# ==== JWT Error Handler ====
@app.errorhandler(JWTExtendedException)
def handle_jwt_errors(e):
    print("❌ JWT Error:", str(e))
    return jsonify({"msg": "JWT Error", "detail": str(e)}), 422

# ==== Routes ====

@app.route("/admin/check", methods=["GET"])
def check_admin_exists():
    existing_admin = users_col.find_one({"role": "admin"})
    return jsonify({"exists": bool(existing_admin)})

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()

    if not re.fullmatch(r"[A-Za-z ]+", data["name"]):
        return jsonify({"msg": "Name must contain only letters and spaces"}), 400

    if len(data["password"]) < 8:
        return jsonify({"msg": "Password must be at least 8 characters"}), 400

    if not all(key in data for key in ("name", "email", "password", "role")):
        return jsonify({"msg": "All fields are required"}), 400

    if users_col.find_one({"email": data["email"]}):
        return jsonify({"msg": "Email already registered"}), 400

    hashed_password = generate_password_hash(data["password"])

    users_col.insert_one({
        "name": data["name"],
        "email": data["email"],
        "password": hashed_password,
        "role": data["role"]
    })

    return jsonify({"msg": "Signup successful"}), 201

  


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user = users_col.find_one({"email": data["email"]})

    if not user:
        return jsonify({"msg": "Invalid credentials"}), 401

    password_hash = user["password"]
    if isinstance(password_hash, Binary):
        password_hash = password_hash.decode("utf-8")

    if not check_password_hash(password_hash, data["password"]):
        return jsonify({"msg": "Invalid credentials"}), 401

    expires = timedelta(hours=8)
    print("⏳ Token will expire at:", datetime.utcnow() + expires)

    token = create_access_token(
        identity=user["email"],  # ✅ string identity
        additional_claims={"role": user["role"]},
        expires_delta=expires
    )

    return jsonify({
        "token": token,
        "role": user["role"],
        "name": user["name"]
    }), 200






@app.route("/admin/checkins/pending", methods=["GET"])
@jwt_required()
def get_pending_checkins():
    email = get_jwt_identity()
    admin = users_col.find_one({"email": email})
    if not admin or admin["role"] != "admin":
        return jsonify({"msg": "Unauthorized"}), 403

    pending = list(pending_checkins_col.find({"status": "Pending"}))
    for p in pending:
        p["_id"] = str(p["_id"])
        p["checkin_time"] = p["requested_at"].strftime("%I:%M %p") if p.get("requested_at") else "—"
    print("✅ Sent to frontend:")
    from pprint import pprint
    pprint(pending)
    return jsonify(pending), 200






@app.route("/admin/checkins/approve/<checkin_id>", methods=["POST"])
@jwt_required()
def approve_checkin(checkin_id):
    email = get_jwt_identity()
    admin = users_col.find_one({"email": email})
    if not admin or admin["role"] != "admin":
        return jsonify({"msg": "Unauthorized"}), 403

    checkin = pending_checkins_col.find_one({"_id": ObjectId(checkin_id)})
    if not checkin:
        return jsonify({"msg": "Check-in request not found"}), 404

    checkin_dt = checkin.get("requested_at")
    if not checkin_dt:
        return jsonify({"msg": "Invalid check-in time"}), 400

    date_str = checkin["date"]
    time_str = checkin_dt.strftime("%H:%M")  # Save time in 24-hr format

    # ❌ Avoid duplicate check-in
    existing = logs_col.find_one({"email": checkin["email"], "date": date_str})
    if existing:
        return jsonify({"msg": "Employee already has a check-in for this date"}), 400

    # ✅ Save to logs_col
    logs_col.insert_one({
        "email": checkin["email"],
        "date": date_str,
        "checkin": time_str,
        "checkout": None,
        "approved": True
    })

    # ✅ Update pending request to approved
    pending_checkins_col.update_one(
        {"_id": ObjectId(checkin_id)},
        {"$set": {"status": "Approved"}}
    )

    return jsonify({"msg": "Check-in approved successfully."}), 200







@app.route("/attendance/checkin", methods=["POST"])
@jwt_required()
def checkin():
    email = get_jwt_identity()
    data = request.get_json()
    print("📥 Received data in checkin route:", data)

    if not data or 'datetime' not in data:
        return jsonify({"msg": "Missing datetime"}), 400

    requested_datetime = datetime.strptime(data['datetime'], "%Y-%m-%dT%H:%M")
    date_str = requested_datetime.strftime('%Y-%m-%d')

    user = users_col.find_one({"email": email})
    doj = datetime.strptime(user.get("join_date", ""), "%Y-%m-%d")

    if requested_datetime < doj:
        return jsonify({"msg": "You cannot check in before your date of joining."}), 400

    # Prevent duplicate
    if logs_col.find_one({"email": email, "date": date_str}):
        return jsonify({"msg": "Already checked in on this day"}), 400

    if pending_checkins_col.find_one({"email": email, "date": date_str, "status": "Pending"}):
        return jsonify({"msg": "Check-in request already submitted and awaiting approval"}), 400

    # Insert as pending
    pending_checkins_col.insert_one({
        "email": email,
        "date": date_str,
        "requested_at": requested_datetime,
        "status": "Pending"
    })

    return jsonify({"msg": "Check-in request submitted. Awaiting admin approval."}), 200






from dateutil import parser  # add this at the top if not already

@app.route("/attendance/checkout", methods=["POST"])
@jwt_required()
def checkout():
    email = get_jwt_identity()
    data = request.json or {}
    print("📥 Checkout data received:", data)

    if "datetime" not in data:
        return jsonify({"msg": "Missing datetime"}), 400

    try:
        checkout_datetime = datetime.strptime(data["datetime"], "%Y-%m-%dT%H:%M")
        print("🧪 Parsed checkout datetime:", checkout_datetime)
    except ValueError:
        return jsonify({"msg": "Invalid datetime format"}), 400

    # Get employee's join date
    user = users_col.find_one({"email": email})
    if not user:
        return jsonify({"msg": "User not found"}), 404

    join_date = datetime.strptime(user["join_date"], "%Y-%m-%d")
    print("🧪 User join date:", join_date)

    if checkout_datetime.date() < join_date.date():
        return jsonify({"msg": "Check-out cannot be before date of joining"}), 400

    # Find last log with check-in but no check-out
    log = logs_col.find_one(
        {"email": email, "checkin": {"$exists": True}, "checkout": None},
        sort=[("date", -1)]
    )
    print("🧪 Checking log:", log)
    print("🧪 Existing checkin:", log["checkin"] if log else "No log")

    if not log:
        return jsonify({"msg": "Please check-in first"}), 400

    # ✅ Convert check-in string to datetime if needed
    if isinstance(log["checkin"], str):
        try:
            checkin_datetime = parser.parse(f"{log['date']} {log['checkin']}")
        except Exception:
            return jsonify({"msg": "Invalid check-in format"}), 400
    else:
        checkin_datetime = log["checkin"]

    if checkout_datetime <= checkin_datetime:
        return jsonify({"msg": "Check-out must be after check-in"}), 400

    # Update
    logs_col.update_one(
        {"_id": log["_id"]},
        {"$set": {"checkout": checkout_datetime}}
    )

    return jsonify({"msg": "Checked out successfully"}), 200


from datetime import datetime

@app.route("/admin/records", methods=["GET"])
@jwt_required()
def all_attendance():
    email = request.args.get('email')
    date = request.args.get('date')

    query = {}
    if email:
        query['email'] = email
    if date:
        query['date'] = date

    records = list(logs_col.find(query))
    for r in records:
        r["_id"] = str(r["_id"])
        
        checkin = r.get("checkin")
        if isinstance(checkin, datetime):
            r["checkin"] = checkin.strftime("%I:%M %p")
        # else if already str, keep as it is

        checkout = r.get("checkout")
        if isinstance(checkout, datetime):
            r["checkout"] = checkout.strftime("%I:%M %p")
        # else if already str, keep as it is

    return jsonify(records), 200



@app.route("/attendance/history", methods=["GET"])
@jwt_required()
def attendance_history():
    email = get_jwt_identity()

    records = list(logs_col.find({"email": email}))

    for r in records:
        r["_id"] = str(r["_id"])
        checkin = r.get("checkin")
        checkout = r.get("checkout")

        # Format time if it's a datetime
        if isinstance(checkin, datetime):
            r["checkin"] = checkin.strftime("%I:%M %p")
        if isinstance(checkout, datetime):
            r["checkout"] = checkout.strftime("%I:%M %p")

    return jsonify(records), 200



@app.route('/admin/export', methods=['GET'])
@jwt_required()
def export_attendance():
    query = {}
    email = request.args.get('email')
    date = request.args.get('date')

    if email:
        query['email'] = {'$regex': f'^{email}$', '$options': 'i'}  # 🔥 case-insensitive match
    if date:
        query['date'] = date

    records = list(logs_col.find(query))  # or use your actual collection

    if not records:
        return jsonify({"msg": "No records found"}), 404

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(['Email', 'Date', 'Check-In', 'Check-Out'])
    for r in records:
        writer.writerow([
            r.get('email', ''),
            r.get('date', ''),
            r.get('checkin') if isinstance(r.get('checkin'), str) else (r.get('checkin').strftime("%I:%M %p") if r.get('checkin') else ''),
            r.get('checkout') if isinstance(r.get('checkout'), str) else (r.get('checkout').strftime("%I:%M %p") if r.get('checkout') else '')
        ])

    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv', headers={"Content-Disposition": "attachment; filename=attendance_export.csv"})


@app.route("/leave/request", methods=["POST"])
@jwt_required()
def request_leave():
    email = get_jwt_identity()
    data = request.json

    existing = leave_requests.find_one({"email": email, "date": data["date"]})
    if existing:
        return jsonify({"msg": "Leave request already submitted for this date"}), 400

    leave_requests.insert_one({
        "email": email,
        "reason": data["reason"],
        "date": data["date"],
        "status": "Pending",
        "submitted_at": datetime.now()
    })

    return jsonify({"msg": "Leave request submitted"}), 201


@app.route("/admin/leave-requests", methods=["GET"])
@jwt_required()
def view_leave_requests():
    email = get_jwt_identity()
    user = users_col.find_one({"email": email})
    if user["role"] != "admin":
        return jsonify({"msg": "Unauthorized"}), 403
    requests = list(leave_requests.find())
    for r in requests:
        r["_id"] = str(r["_id"])
    return jsonify(requests), 200


from bson import ObjectId

@app.route("/admin/leave-requests/<req_id>", methods=["PUT"])
@jwt_required()
def update_leave_status(req_id):
    email = get_jwt_identity()
    user = users_col.find_one({"email": email})
    if user["role"] != "admin":
        return jsonify({"msg": "Unauthorized"}), 403

    data = request.get_json()
    leave_requests.update_one(
        {"_id": ObjectId(req_id)},
        {"$set": {"status": data["status"], "updated_at": datetime.now()}}
    )

    return jsonify({"msg": "Leave status updated"}), 200


@app.route("/leave/my-requests", methods=["GET"])
@jwt_required()
def my_leave_requests():
    email = get_jwt_identity()
    requests = list(leave_requests.find({"email": email}))
    for r in requests:
        r["_id"] = str(r["_id"])
    return jsonify(requests), 200

from datetime import datetime, timedelta

@app.route("/employee/summary", methods=["GET"])
@jwt_required()
def employee_summary():
    identity = get_jwt_identity()
    email = identity["email"] if isinstance(identity, dict) else identity

    all_logs = list(logs_col.find({"email": email}))
    leave_logs = list(leave_col.find({"email": email}))
    pending_leaves = [leave for leave in leave_logs if leave.get("status") == "Pending"]
    accepted_leaves = [leave for leave in leave_logs if leave.get("status") == "Accepted"]

    # Holiday list
    HOLIDAYS = {
        "2025-01-01", "2025-01-14", "2025-02-26", "2025-03-31", "2025-05-01",
        "2025-08-15", "2025-08-27", "2025-10-01", "2025-10-02",
        "2025-10-20", "2025-12-25", "2025-03-13", "2025-04-18",
        "2025-09-05", "2025-10-22"
    }

    # Calculate total working days from Jan 1st to today excluding holidays & weekends
    start = datetime(2025, 1, 1)
    today = datetime.today()

    def calculate_working_days(start, end):
        day_count = 0
        current = start
        while current <= end:
            if current.weekday() < 5 and current.strftime('%Y-%m-%d') not in HOLIDAYS:
                day_count += 1
            current += timedelta(days=1)
        return day_count

    total_working_days = calculate_working_days(start, today)

    # Leaves taken
    leaves_taken = len(accepted_leaves)
    leaves_left = max(12 - leaves_taken, 0)

    # This month attendance
    current_month = datetime.now().strftime("%Y-%m")
    month_logs = [log for log in all_logs if log["date"].startswith(current_month)]
    present_days = len([log for log in month_logs if log.get("checkin")])

    return jsonify({
        "totalDays": total_working_days,
        "leavesTaken": leaves_taken,
        "leavesLeft": leaves_left,
        "pendingRequests": len(pending_leaves)
    }), 200







UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route("/admin/upload-attendance", methods=["POST"])
@jwt_required()
def upload_attendance():
    file = request.files.get('file')
    if not file:
        return jsonify({"msg": "No file uploaded"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)  # 💾 Save the file temporarily

    try:
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            entries = []
            for row in reader:
                # Parse each CSV row and prepare MongoDB entries
                entry = {
                    "email": row["email"].strip(),
                    "date": row["date"].strip(),  # keep as string YYYY-MM-DD
                    "checkin": datetime.strptime(row["checkin"], "%I:%M %p") if row["checkin"] else None,
                    "checkout": datetime.strptime(row["checkout"], "%I:%M %p") if row["checkout"] else None
                }
                entries.append(entry)

            if entries:
                logs_col.insert_many(entries)  # 🗃️ Insert into your MongoDB collection

    except Exception as e:
        print("Error processing CSV:", e)
        return jsonify({"msg": "Failed to process file"}), 500
    finally:
        os.remove(filepath)  # 🧹 Clean up: remove uploaded file after processing

    return jsonify({"msg": "Attendance uploaded and processed successfully"}), 200

# Assuming you have employees collection or users collection

@app.route('/admin/total-employees', methods=['GET'])
@jwt_required()
def total_employees():
    total = users_col.count_documents({})  # Replace users_col with your correct collection (example: users_col, employees_col)
    return jsonify({'total_employees': total}), 200



@jwt_required()
@app.route('/employee/profile', methods=['GET'])
@jwt_required()
def employee_profile():
    current_user_email = get_jwt_identity()
    user = users_col.find_one({"email": current_user_email})

    if not user:
        return jsonify({"msg": "User not found"}), 404

    # Map backend DB fields to frontend fields
    return jsonify({
        "name": user.get("name", ""),
        "email": user.get("email", ""),
        "department": user.get("department", ""),
        "position": user.get("position", ""),
        "doj": user.get("join_date") or user.get("joinDate", ""),   # "doj" for frontend, from join_date/joinDate in DB
        "bloodGroup": user.get("bloodGroup") or user.get("blood_group", ""),  # support both
    }), 200


from flask import request, jsonify


from werkzeug.security import generate_password_hash

@app.route('/employee/update-profile', methods=['PUT'])
@jwt_required()
def update_profile():
    user_email = get_jwt_identity()
    data = request.get_json()

    update_data = {}
    if 'name' in data:
        update_data['name'] = data['name']
    if 'department' in data:
        update_data['department'] = data['department']
    if 'position' in data:
        update_data['position'] = data['position']
    if 'password' in data and data['password'].strip() != "":
        hashed_password = generate_password_hash(data['password'])
        update_data['password'] = hashed_password

    if not update_data:
        return jsonify({"msg": "No fields to update"}), 400

    result = users_col.update_one(
        {"email": user_email},
        {"$set": update_data}
    )

    if result.modified_count > 0:
        return jsonify({"msg": "Profile updated successfully"}), 200
    else:
        return jsonify({"msg": "No changes made"}), 200





@app.route('/admin/add-employee', methods=['POST'])
@jwt_required()
def add_employee():
    try:
        data = request.json
        name = data.get("name")
        email = data.get("email")
        password = data.get("password")
        join_date = data.get('doj')
        department = data.get('department', 'Not Assigned')
        position = data.get('position', 'Not Assigned')
        blood_group = data.get('bloodGroup', '')  # <-- ADD THIS

        # Validation
        if not all([name, email, password, join_date]):
            return jsonify({"msg": "Missing required fields"}), 400

        if users_col.find_one({"email": email}):
            return jsonify({"msg": "Employee with this email already exists"}), 409

        hashed_password = generate_password_hash(password)

        new_employee = {
            "name": name,
            "email": email,
            "password": hashed_password,
            "role": "employee",
            "join_date": join_date,
            "department": department,
            "position": position,
            "bloodGroup": blood_group  # <-- ADD THIS
        }

        users_col.insert_one(new_employee)

        return jsonify({"msg": "Employee added successfully"}), 201

    except Exception as e:
        print("Error in /admin/add-employee:", e)
        return jsonify({"msg": "Server error"}), 500

        



# if __name__ == "__main__":
#     app.run(debug=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
























