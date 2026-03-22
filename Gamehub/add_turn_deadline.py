import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Gamehub.settings')
django.setup()
from django.db import connection

with connection.cursor() as c:
    c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='gamelobby'")
    cols = [r[0] for r in c.fetchall()]
    if 'turn_deadline' not in cols:
        c.execute("ALTER TABLE gamelobby ADD COLUMN turn_deadline TIMESTAMPTZ")
        print("Added turn_deadline")
    else:
        print("turn_deadline already exists")
print("Done")
