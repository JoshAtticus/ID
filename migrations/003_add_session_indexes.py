from sqlalchemy import text

def upgrade(app, db):
    with app.app_context():
        try:
            with db.engine.connect() as conn:
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_session_token ON session (token)"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_session_user_id ON session (user_id)"))
                conn.commit()
            print("Migration successful: Added session indexes.")
        except Exception as e:
            print(f"Migration failed: {e}")
