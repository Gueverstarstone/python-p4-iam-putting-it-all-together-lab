#!/usr/bin/env python3

from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt


class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    serialize_rules = ('-recipes.user', '-_password_hash')

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)

    _password_hash = db.Column(
        db.String,
        nullable=False,
        default=""
    )

    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # Relationship
    recipes = db.relationship(
        'Recipe',
        back_populates='user',
        cascade='all, delete-orphan'
    )

    # Prevent reading password
    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password hashes may not be viewed.")

    # Set password
    @password_hash.setter
    def password_hash(self, password):
        hashed = bcrypt.generate_password_hash(
            password.encode('utf-8')
        )
        self._password_hash = hashed.decode('utf-8')

    # Authenticate
    def authenticate(self, password):
        if not self._password_hash:
            return False
        return bcrypt.check_password_hash(
            self._password_hash,
            password.encode('utf-8')
        )

    # Username validation
    @validates('username')
    def validate_username(self, key, username):
        if not username or username.strip() == '':
            raise ValueError("Username must be present.")
        return username


class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    serialize_rules = ('-user.recipes',)

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False, default=0)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id'),
        nullable=False
    )

    user = db.relationship('User', back_populates='recipes')

    @validates('title')
    def validate_title(self, key, title):
        if not title or title.strip() == '':
            raise ValueError("Title must be present.")
        return title

    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions or instructions.strip() == '':
            raise ValueError("Instructions must be present.")
        if len(instructions) < 50:
            raise ValueError(
                "Instructions must be at least 50 characters long."
            )
        return instructions