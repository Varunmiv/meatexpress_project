from app import create_app, db
from models import User
from flask_bcrypt import Bcrypt

app = create_app()
bcrypt = Bcrypt(app)

with app.app_context():
    # Remove the existing admin user if any
    existing_admin = User.query.filter_by(email='admin@meatexpress.com').first()
    if existing_admin:
        db.session.delete(existing_admin)
        db.session.commit()

    # Create a new admin user
    password_hash = bcrypt.generate_password_hash('reddy').decode('utf-8')
    
    # Provide values for all required fields
    new_admin = User(
        email='admin@meatexpress.com',
        name='Reddy',  # Replace with the actual name
        phone='9008185943',  # Replace with the actual phone number or remove if not required
        password_hash=password_hash,
        is_admin=True
    )
    
    db.session.add(new_admin)
    db.session.commit()
    print("Admin user created successfully.")
