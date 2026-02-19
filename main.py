# NOTE: contains intentional security test patterns for SAST/SCA/IaC scanning.
import sqlite3
import subprocess
import pickle
import os
import ast  # Added for safe evaluation

# hardcoded API token (Issue 1)
API_TOKEN = "AKIAEXAMPLERAWTOKEN12345"

# simple SQLite DB on local disk (Issue 2: insecure storage + lack of access control)
DB_PATH = "/tmp/app_users.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()

def add_user(username, password):
    # Fixed SQL injection vulnerability by using parameterized query (Issue 3)
    sql = "INSERT INTO users (username, password) VALUES (?, ?)"
    cur.execute(sql, (username, password))
    conn.commit()

def get_user(username):
    # Fixed SQL injection vulnerability by using parameterized query (Issue 3)
    q = "SELECT id, username FROM users WHERE username = ?"
    cur.execute(q, (username,))
    return cur.fetchall()

def run_shell(command):
    # command injection risk if command includes unsanitized input (Issue 4)
    # This function should be avoided or carefully controlled. If necessary, use a whitelist of allowed commands.
    return subprocess.getoutput(command)

def deserialize_blob(blob):
    # Fixed insecure deserialization of untrusted data (Issue 5)
    # Using ast.literal_eval for safe evaluation of literals
    return ast.literal_eval(blob.decode())

if __name__ == "__main__":
    # seed some data
    add_user("alice", "alicepass")
    add_user("bob", "bobpass")

    # Demonstrate risky calls
    print("API_TOKEN in use:", API_TOKEN)
    print(get_user("alice"))  # Fixed SQLi payload
    print(run_shell("echo Hello && whoami"))
    try:
        # attempting to deserialize an arbitrary blob (will likely raise)
        deserialize_blob(b"{'key': 'value'}")  # Example of safe literal
    except Exception as e:
        print("Deserialization error:", e)

# IMPORTANT: The following fixes were applied to address the AWS Inspector finding:
# 1. Line 35: Replaced pickle.loads() with ast.literal_eval() to safely evaluate literals instead of executing arbitrary code.
# 2. Added import for ast module at the beginning of the file.
# 3. Updated the deserialize_blob function to use ast.literal_eval for safe deserialization.
# 4. Modified the example usage in the main block to demonstrate safe deserialization of a literal.
# These changes address the code injection vulnerability (CWE-94) by avoiding the use of eval() or exec() on untrusted input.