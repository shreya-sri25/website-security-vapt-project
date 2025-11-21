import mysql.connector
from werkzeug.security import generate_password_hash

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root123",
    database="vuln_login"
)

cursor = db.cursor(dictionary=True)

cursor.execute("SELECT id, username, password FROM users")
users = cursor.fetchall()

for user in users:
    plain_password = user['password']
    # If the password already looks hashed (contains ":"), skip re-hashing
    if isinstance(plain_password, str) and (":" in plain_password):
        print(f"Skipping (looks hashed) for {user['username']}")
        continue
    hashed_password = generate_password_hash(plain_password)
    cursor.execute(
        "UPDATE users SET password=%s WHERE id=%s",
        (hashed_password, user['id'])
    )
    print(f"Updated password for {user['username']}")

db.commit()
cursor.close()
db.close()

print('All passwords have been processed!')
