from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy import event
from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String, default='')
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship('Recipe', backref='user', lazy=True, cascade="all, delete-orphan")

    @hybrid_property
    def password_hash(self):
        raise AttributeError('password_hash is not a readable attribute.')

    @password_hash.setter
    def password_hash(self, password):
        if password:
            self._password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)

    @validates('username')
    def validate_username(self, key, username):
        if not username:
            raise ValueError('Username is required.')
        return username

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), default=0)

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if instructions and len(instructions) < 50:
            raise ValueError("Instructions must be at least 50 characters long.")
        return instructions

@event.listens_for(Recipe, 'before_insert')
def set_default_user_id(mapper, connection, target):
    if target.user_id is None:
        target.user_id = 0