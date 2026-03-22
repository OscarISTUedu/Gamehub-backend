import os

from django.core.management.base import BaseCommand
from django.db import connection, transaction
from django.apps import apps
import time


class Command(BaseCommand):
    help = 'Безопасно создает начальные данные после миграций'

    def handle(self, *args, **options):
        # Проверяем существование таблиц
        Game = apps.get_model('mainapp', 'Game')
        max_retries = 5
        retry_count = 0
        while retry_count < max_retries:
            try:
                table_name = Game._meta.db_table
                with connection.cursor() as cursor:
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_name = %s
                        );
                    """, [table_name])
                    table_exists = cursor.fetchone()[0]
                if not table_exists:
                    time.sleep(2)
                    retry_count += 1
                    continue
                self.create_initial_data()
                break
            except Exception as e:
                time.sleep(2)
                retry_count += 1

    @transaction.atomic
    def create_initial_data(self):
        from mainapp.models import Game, Achievement
        from mainapp.management.commands.bd_data.games.games import games_data
        from mainapp.management.commands.bd_data.achievements.achievements import achievements_data
        if Game.objects.exists() or Achievement.objects.exists():
            return

        games = {}
        for game_data in games_data:
            game, created = Game.objects.get_or_create(
                name=game_data["name"],
                defaults={
                    "description": game_data["description"],
                }
            )
            image_filename = f"{game_data['name']}.png"
            image_relative_path = os.path.join('static/img/game_icons', image_filename)
            game.picture = image_relative_path
            game.save()
            games[game_data["name"]] = game
        for game_name, achievements in achievements_data.items():
            if game_name in games:
                game = games[game_name]
                for ach_data in achievements:
                    achievement, created = Achievement.objects.get_or_create(
                        name=ach_data["name"],
                        game_id=game.id,
                        defaults={
                            "description": ach_data["description"]
                        }
                    )
