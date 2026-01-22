import sys
import os
from pathlib import Path

# Add app to python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from app.database import SessionLocal
from app.services.auth.user_service import create_user, get_user_by_username

def create_admin_user(username="admin", password="password123", email="admin@example.com"):
    db = SessionLocal()
    try:
        user = get_user_by_username(db, username)
        if user:
            print(f"User {username} already exists.")
            return

        print(f"Creating user: {username}")
        create_user(db, username, email, password)
        print(f"User {username} created successfully.")
    except Exception as e:
        print(f"Error creating user: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        username = sys.argv[1]
        password = sys.argv[2] if len(sys.argv) > 2 else "password123"
        create_admin_user(username, password)
    else:
        create_admin_user()