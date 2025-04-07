from flask import Flask, request, jsonify
import sqlite3
import json
import os
import hashlib
import random
from dotenv import load_dotenv

# Load environment variables at startup
load_dotenv()

# Handle environment variable substitution
def process_json_with_env(json_data):
    if isinstance(json_data, dict):
        return {
            key: process_json_with_env(value) 
            for key, value in json_data.items()
        }
    elif isinstance(json_data, list):
        return [process_json_with_env(item) for item in json_data]
    elif isinstance(json_data, str) and json_data.startswith("${") and json_data.endswith("}"):
        env_var = json_data[2:-1]
        return os.getenv(env_var, json_data)
    return json_data

app = Flask(__name__)

DB_FILE = "grades.db"
USER_FILE = "students.json"

# Hash a password using SHA256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Generate a random 256-bit CPA key
def generate_cpa_key():
    return os.urandom(32)

# Modify init_db() to use the new processing function
def init_db():
    print("Initializing database...")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            cpa_key BLOB NOT NULL,
            score INTEGER NOT NULL DEFAULT 0
        )
    """)
    
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as f:
            users = json.load(f)
            # Process environment variables
            users = process_json_with_env(users)
            print(f"Processed users from JSON: {users}")  # Debug print
            
            for user in users:
                if user.get("role") == "student":
                    username = user["username"]
                    password_hashed = hash_password(user["password"])
                    new_cpa_key = generate_cpa_key()
                    
                    # Debug output
                    print(f"Processing student: {username}")
                    
                    cursor.execute("SELECT username, score FROM students WHERE username = ?", (username,))
                    row = cursor.fetchone()
                    if row:
                        cursor.execute("UPDATE students SET cpa_key = ? WHERE username = ?", 
                                     (new_cpa_key, username))
                    else:
                        cursor.execute("""
                            INSERT INTO students (username, password, cpa_key, score)
                            VALUES (?, ?, ?, ?)
                        """, (username, password_hashed, new_cpa_key, 0))
    else:
        print(f"Error: {USER_FILE} not found!")
    
    conn.commit()
    conn.close()

# Helper function: authenticate student (returns a dictionary containing username, CPA key, and score)
def authenticate_student(username, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password, cpa_key, score FROM students WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row and row[0] == hash_password(password):
        return {"username": username, "cpa_key": row[1], "score": row[2]}
    return None

# Update the student's CPA key
def update_student_cpa_key(username, new_key):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE students SET cpa_key = ? WHERE username = ?", (new_key, username))
    conn.commit()
    conn.close()

# Update the student's score
def update_student_score(username, new_score):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE students SET score = ? WHERE username = ?", (new_score, username))
    conn.commit()
    conn.close()

#########################
# User Authentication Endpoints
#########################

# Get grade endpoint: requires username and password for verification
@app.route("/grades", methods=["GET"])
def get_grade():
    username = request.args.get("username")
    password = request.args.get("password")
    student = authenticate_student(username, password)
    if not student:
        return jsonify({"error": "Invalid credentials"}), 401
    return jsonify({"username": username, "score": student["score"]}), 200

#########################
# CPA Challenge Endpoints
#########################

# Implement a pseudo-random function H(key, r) using SHA256
def cpa_H(key, r):
    r_bytes = r.to_bytes(1, 'big')
    return hashlib.sha256(key + r_bytes).digest()

# Global storage for each user's challenge info; the key is (username, challenge_id)
challenge_store = {}
# Record the next challenge id for each user
challenge_count = {}

# /encrypt endpoint: encrypt a 256-bit message using the student's CPA key
@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json()
    # Username and password are required for authentication
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Authentication required"}), 401
    student = authenticate_student(username, password)
    if not student:
        return jsonify({"error": "Invalid credentials"}), 401
    # If the score reaches 100, reject other operations
    if student["score"] >= 100:
        return jsonify({"error": "Score limit reached. Only login allowed."}), 403
    if 'message' not in data:
        return jsonify({"error": "Message not provided"}), 400
    try:
        m = bytes.fromhex(data['message'])
    except Exception:
        return jsonify({"error": "Invalid message format, should be a hex string"}), 400
    if len(m) != 32:
        return jsonify({"error": "Message must be 256 bits (32 bytes)"}), 400
    # Generate a random 5-bit integer (0 to 31)
    r = random.randint(0, 31)
    # Use the student's CPA key from the database
    key = student["cpa_key"]
    pad = cpa_H(key, r)
    # Compute c2 = pad XOR m
    c2 = bytes(a ^ b for a, b in zip(pad, m))
    return jsonify({"r": r, "c2": c2.hex()})

# /challenge endpoint: provide a challenge ciphertext based on two messages and assign a challenge id
@app.route("/challenge", methods=["POST"])
def challenge():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Authentication required"}), 401
    student = authenticate_student(username, password)
    if not student:
        return jsonify({"error": "Invalid credentials"}), 401
    if student["score"] >= 100:
        return jsonify({"error": "Score limit reached. Only login allowed."}), 403
    if 'm0' not in data or 'm1' not in data:
        return jsonify({"error": "Both m0 and m1 must be provided"}), 400
    try:
        m0 = bytes.fromhex(data['m0'])
        m1 = bytes.fromhex(data['m1'])
    except Exception:
        return jsonify({"error": "Invalid message format, should be hex strings"}), 400
    if len(m0) != 32 or len(m1) != 32:
        return jsonify({"error": "Messages must be 256 bits (32 bytes)"}), 400
    # Randomly choose a bit b (0 or 1)
    b = random.randint(0, 1)
    chosen = m0 if b == 0 else m1
    r = random.randint(0, 31)
    key = student["cpa_key"]
    pad = cpa_H(key, r)
    # Compute c2 = pad XOR chosen message
    c2 = bytes(a ^ byte for a, byte in zip(pad, chosen))
    # Assign a challenge id for the current user
    cid = challenge_count.get(username, 1)
    challenge_count[username] = cid + 1
    # Store the correct answer and associated data for the challenge using (username, challenge_id)
    challenge_store[(username, cid)] = {
        "b": b,
        "r": r,
        "c2": c2.hex()
    }
    return jsonify({"challenge_id": cid, "r": r, "c2": c2.hex()})

# /guess endpoint: accept the user's guess for the challenge bit, update score, and refresh CPA key regardless of result
@app.route("/guess", methods=["POST"])
def guess():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Authentication required"}), 401
    student = authenticate_student(username, password)
    if not student:
        return jsonify({"error": "Invalid credentials"}), 401
    if student["score"] >= 100:
        return jsonify({"error": "Score limit reached. Only login allowed."}), 403
    if 'challenge_id' not in data or 'b_prime' not in data:
        return jsonify({"error": "challenge_id and b_prime must be provided"}), 400
    try:
        cid = int(data['challenge_id'])
        b_prime = int(data['b_prime'])
    except Exception:
        return jsonify({"error": "challenge_id and b_prime must be integers"}), 400
    if b_prime not in [0, 1]:
        return jsonify({"error": "b_prime must be 0 or 1"}), 400

    key_tuple = (username, cid)
    if key_tuple not in challenge_store:

        new_key = generate_cpa_key()
        update_student_cpa_key(username, new_key)
        return jsonify({"error": "Challenge not found"}), 404

    correct_b = challenge_store[key_tuple]["b"]
    result = (b_prime == correct_b)
    new_score = student["score"] + (1 if result else -1)
    update_student_score(username, new_score)

    new_key = generate_cpa_key()
    update_student_cpa_key(username, new_key)

    del challenge_store[key_tuple]
    return jsonify({"result": result, "correct_b": correct_b, "new_score": new_score})

#####################################
# Admin Endpoint: Print current information of all students
#####################################
# Admin password (set to "admin123" in this example)
ADMIN_PASSWORD = "admin123"

@app.route("/admin/students", methods=["GET"])
def list_students():
    # The admin must provide the admin password as a request parameter
    admin_pass = request.args.get("admin_password")
    if admin_pass != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized access"}), 403
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username, score, cpa_key FROM students")
    rows = cursor.fetchall()
    conn.close()
    students = []
    for row in rows:
        students.append({
            "username": row[0],
            "score": row[1],
            "cpa_key": row[2].hex() if row[2] is not None else None
        })
    return jsonify({"students": students}), 200

if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
