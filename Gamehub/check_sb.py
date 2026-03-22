import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Gamehub.settings')
django.setup()
from django.db import connection
with connection.cursor() as c:
    c.execute("""
        CREATE TABLE IF NOT EXISTS seabattlelobby (
            id SERIAL PRIMARY KEY,
            lobby_owner INTEGER NOT NULL,
            opponent INTEGER,
            owner_ships JSONB NOT NULL DEFAULT '[]',
            opponent_ships JSONB NOT NULL DEFAULT '[]',
            owner_shots JSONB NOT NULL DEFAULT '[]',
            opponent_shots JSONB NOT NULL DEFAULT '[]',
            turn INTEGER,
            winner INTEGER,
            owner_ready BOOLEAN NOT NULL DEFAULT FALSE,
            opponent_ready BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
print("Table created")