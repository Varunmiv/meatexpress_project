# commands.py
import click
from flask import current_app
from flask.cli import AppGroup

cli = AppGroup('custom')

@cli.command('create_admin')
def create_admin():
    """Create an admin user"""
    from app import create_app
    app = create_app()
    with app.app_context():
        from .models import db, User
        admin = User(email='newadmin@meatexpress.com', name='Admin', phone='1234567890', password_hash='varun', is_admin=True)
        db.session.add(admin)
        db.session.commit()
        print('Admin user created successfully.')
