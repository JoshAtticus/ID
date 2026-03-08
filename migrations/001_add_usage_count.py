from sqlalchemy import text, inspect

def upgrade(app, db):
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('oauth_authorization')]
            
            if 'usage_count' not in columns:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE oauth_authorization ADD COLUMN usage_count INTEGER DEFAULT 0"))
                    conn.commit()
                print("Migration successful: Added usage_count column.")
            else:
                print("Migration skipped: usage_count column already exists.")
        except Exception as e:
            print(f"Migration failed: {e}")
