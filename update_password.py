import mysql.connector
from werkzeug.security import generate_password_hash

# 1️⃣ Connect to your database
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root123",
    database="vuln_login"
)

cursor = db.cursor(dictionary=True)

# 2️⃣ Fetch all users
cursor.execute("SELECT id, username, password FROM users")
users = cursor.fetchall()

# 3️⃣ Update each password with a hashed version
for user in users:
    plain_password = user['password']  # current plain-text password
    hashed_password = generate_password_hash(plain_password)
    
    cursor.execute(
        "UPDATE users SET password=%s WHERE id=%s",
        (hashed_password, user['id'])
    )
    print(f"Updated password for {user['username']}")

# 4️⃣ Commit changes and close
db.commit()
cursor.close()
db.close()

print("All passwords have been hashed successfully!")
