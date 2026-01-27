import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import SessionLocal, init_db
from app.services.auth.user_service import create_user

def create_admin():
    """Create default admin user"""
    init_db()
    db = SessionLocal()
    
    try:
        admin = create_user(
            db=db,
            username="admin",
            email="admin@minifw.local",
            password="admin123"  # GANTI password ini!
        )
        print(f"✅ Admin user created: {admin.username}")
        print(f"   Email: {admin.email}")
        print(f"   Password: admin12345")
        print(f"\n⚠️  PLEASE CHANGE THE DEFAULT PASSWORD!")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    create_admin()
