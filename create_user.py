# create_user.py
import sys
import mysql.connector
from werkzeug.security import generate_password_hash

def main():
    # Allow passing username/password as command-line args:
    # python create_user.py username password
    if len(sys.argv) >= 3:
        username = sys.argv[1].strip()
        password = sys.argv[2]
    else:
        username = input("Username to create: ").strip()
        password = input("Password: ").strip()

    if not username or not password:
        print("Username and password required.")
        return

    try:
        db = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root123",
            database="vuln_login"
        )
    except Exception as e:
        print("Could not connect to database:", e)
        return

    cursor = db.cursor()
    # Hash the password using werkzeug
    hashed_pw = generate_password_hash(password)

    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_pw))
        db.commit()
        print(f"✅ Created user: {username}")
        print("Stored hash (first 60 chars):", hashed_pw[:60], "...")
    except mysql.connector.IntegrityError:
        print(f"❌ User '{username}' already exists. Choose a different username.")
    except Exception as e:
        print("Database error:", e)
    finally:
        try:
            cursor.close()
        except:
            pass
        try:
            db.close()
        except:
            pass

if __name__ == "__main__":
    main()
