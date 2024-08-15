#!/usr/bin/env python3

from flask import request, session as flask_session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as SQLAlchemySession

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        try:
            if not username:
                return {'error': 'Username is required'}, 422
            
            user = User(username=username, image_url=image_url, bio=bio)
            if password:
                user.password_hash = password  # bcrypt handles the hashing
            else:
                return {'error': 'Password is required'}, 422
            
            db.session.add(user)
            db.session.commit()

            flask_session['user_id'] = user.id

            return {
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }, 201

        except ValueError as e:
            db.session.rollback()
            return {'error': str(e)}, 422
        except IntegrityError:
            db.session.rollback()
            return {'error': 'Username already exists or invalid input'}, 422
        
class CheckSession(Resource):
    def get(self):
        user_id = flask_session.get('user_id')

        if not user_id:
            return {'error': 'Unauthorized'}, 401

        with SQLAlchemySession(db.engine) as db_session:
            user = db_session.get(User, user_id)
            if user:
                return {
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }, 200
            else:
                return {'error': 'User not found'}, 404

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        with SQLAlchemySession(db.engine) as db_session:
            user = db_session.query(User).filter_by(username=username).first()

            if user and user.authenticate(password):
                flask_session['user_id'] = user.id
                return {
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }, 200
            else:
                return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        if 'user_id' in flask_session and flask_session['user_id'] is not None:
            flask_session.pop('user_id')
            return '', 204
        else:
            return {'error': 'Unauthorized'}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = flask_session.get('user_id')

        if not user_id:
            return {'error': 'Unauthorized'}, 401

        with SQLAlchemySession(db.engine) as db_session:
            recipes = db_session.query(Recipe).filter_by(user_id=user_id).all()
            return [{
                'id': recipe.id,
                'title': recipe.title,
                'instructions': recipe.instructions,
                'minutes_to_complete': recipe.minutes_to_complete,
                'user': {
                    'id': recipe.user.id,
                    'username': recipe.user.username,
                    'image_url': recipe.user.image_url
                }
            } for recipe in recipes], 200

    def post(self):
        user_id = flask_session.get('user_id')

        if not user_id:
            return {'error': 'Unauthorized'}, 401

        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')

        if not title or not instructions or len(instructions) < 50:
            return {'error': 'Invalid recipe data'}, 422

        with SQLAlchemySession(db.engine) as db_session:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id
            )
            db_session.add(recipe)
            db_session.commit()

            return {
                'id': recipe.id,
                'title': recipe.title,
                'instructions': recipe.instructions,
                'minutes_to_complete': recipe.minutes_to_complete,
                'user': {
                    'id': recipe.user.id,
                    'username': recipe.user.username,
                    'image_url': recipe.user.image_url
                }
            }, 201

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)