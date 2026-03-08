from sqlalchemy import text, inspect

def upgrade(app, db):
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('user')]
            
            if 'has_acknowledged_legal_update' not in columns:
                with db.engine.connect() as conn:
                    # SQLite doesn't support adding a column with a default value that isn't NULL without some workarounds or a fresh table, 
                    # but for BOOLEAN it usually works if we provide a default.
                    conn.execute(text("ALTER TABLE user ADD COLUMN has_acknowledged_legal_update BOOLEAN NOT NULL DEFAULT 1"))
                    conn.commit()
                print("Migration successful: Added has_acknowledged_legal_update column.")
            else:
                print("Migration skipped: has_acknowledged_legal_update column already exists.")
        except Exception as e:
            print(f"Migration failed: {e}")
