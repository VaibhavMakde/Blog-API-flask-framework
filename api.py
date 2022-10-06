import datetime
from functools import wraps
from flask_marshmallow import Marshmallow, fields
from flask import Flask, request, jsonify, make_response, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from flask_migrate import Migrate
from flask_swagger_ui import get_swaggerui_blueprint
from flask_login import LoginManager
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

#######################    APP CONFIG HERE  ########################################

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://////home/vaibhav/PycharmProjects/blog3-api-flask (copy)/blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# set up the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "super-secret"
jwt = JWTManager(app)

db = SQLAlchemy(app)
ma = Marshmallow(app)

# adding migration
migrate = Migrate(app, db)

'''Steps for migration
1. export FLASK_APP=file_name.py
2. flask db init
3. flask db migrate
4. flask db upgrade
'''

# authentication and authorization setting
login_manager = LoginManager()

'''
Flask-login also requires you to define a “user_loader” function which,
given a user ID, returns the associated user object.
The @login_manager.user_loader 
piece tells Flask-login how to load users given an id.'''


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#######################  MODELS HERE  ########################################

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50))
    email = db.Column(db.String(150), unique=True, nullable=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)
    blogs = db.relationship('Blog', backref='user')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    author = db.Column(db.Integer, db.ForeignKey(
        'user.id', ondelete="CASCADE"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey(
        'blog.id', ondelete="CASCADE"), nullable=False)


class Blog(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    blog = db.Column(db.String(500))
    author = db.Column(db.Integer, db.ForeignKey(
        'user.id', ondelete="CASCADE"), nullable=False)
    comments = db.relationship('Comment', backref='blog')


#######################    MODELS SCHEMA USING MARSHMALLOW HERE  ########################################

class CommentSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Comment
        load_instance = True
        include_relationships = True
        fields = ('id', 'text', 'author', 'post_id')
        # include_fk = True

class BlogSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Blog
        load_instance = True
        include_relationships = True

        fields = ('id', 'title', 'blog', 'author', 'comments')

    comments = ma.Nested(CommentSchema, many=True)


class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        load_instance = True
        include_relationships = True
        fields = ('id', 'public_id', 'username', 'admin')


################################   swagger specific  ####################################################

# swagger configs
SWAGGER_URL = '/swagger'
API_URL = "/static/swagger.json"

SWAGGER_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Blog Post API"
    }
)
app.register_blueprint(SWAGGER_BLUEPRINT, url_prifix=SWAGGER_URL)


##########################      USER REGISTER AND LOGIN CODE HERE     #####################################

@app.route('/signup', methods=['POST'])
def signup():
    username = request.json.get("username", None)
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    username_exists = User.query.filter_by(username=username).first()
    if username_exists:
        return jsonify({'message': 'Username already exits !'})

    email_exists = User.query.filter_by(email=email).first()
    if email_exists:
        return jsonify({'message': 'email already exits !'})

    hashed_password = generate_password_hash(password=password, method='sha256')
    print(hashed_password)
    new_user = User(public_id=str(uuid.uuid4()), username=username, email=email, password=hashed_password,
                    admin=False)
    print(new_user)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created!'})


@app.route('/login', methods=["POST"])
def login_user():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    user = User.query.filter_by(username=username).first()
    print(user)
    if user:
        if check_password_hash(user.password, password):
            access_token = create_access_token(identity=username)
            print(access_token)
            return jsonify(access_token=access_token)
            return jsonify({'message': 'Logged in successfully!'})

        else:
            return jsonify({'message': 'Incorrect Password !'})

    else:
        return jsonify({'message': "User does not exits !!!"})


@app.route('/user', methods=['GET'])
@jwt_required()
def get_all_users():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    print(current_user)
    access_token = create_access_token(identity=current_user)
    users = User.query.all()

    if users:
        # marshmallow serialization on user
        user_schema = UserSchema(many=True)
        output = user_schema.dump(users)

        return jsonify({'users': output})
    else:
        return jsonify({'message': 'No user found'})


@app.route('/user/<public_id>', methods=['GET'])
@jwt_required()
def get_one_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_schema = UserSchema()
    output = user_schema.dump(user)
    print(output)

    return jsonify({'user': output})


# promoting user to admin
@app.route('/user/<public_id>', methods=['PUT'])
@jwt_required()
def promote_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted!'})


@app.route('/user/<public_id>', methods=['DELETE'])
@jwt_required()
def delete_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted!'})


@app.route('/blog', methods=['GET'])
@jwt_required()
def get_all_blog():
    blogs = Blog.query.all()

    # Blog serialization using marshmallow
    blog_schema = BlogSchema(many=True)
    output = blog_schema.dump(blogs)

    return jsonify({'Blogs': output})


@app.route('/blog/<blog_id>', methods=['GET'])
@jwt_required()
def get_one_blog(blog_id):
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    blog = Blog.query.filter_by(id=blog_id).first()
    print(blog.author)
    if not blog:
        return jsonify({'message': 'No Blog found!'})

    # Blog serialization using marshmallow
    blog_schema = BlogSchema()
    output = blog_schema.dump(blog)

    return jsonify(output)


@app.route('/blog/search', methods=['POST'])
@jwt_required()
def search():
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    data = request.get_json()

    try:
        if data['title']:
            search_by_title = data['title']
            blog = Blog.query.filter_by(title=search_by_title).first()
    except:
        pass

    try:
        if data['author']:
            search_by_author = data['author']
            blog = Blog.query.filter_by(author=search_by_author).first()
    except:
        pass

    try:
        if data['blog']:
            search_by_blog = data['blog']
            blog = Blog.query.filter_by(blog=search_by_blog).first()
    except:
        pass

    if not blog:
        return jsonify({'message': 'No Blog found!'})

    # Blog serialization using marshmallow
    blog_schema = BlogSchema()
    output = blog_schema.dump(blog)

    return jsonify(output)


@app.route('/blog', methods=['POST'])
@jwt_required()
def create_blog():
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    title = request.json.get("title", None)
    blog = request.json.get("blog", None)

    if title and blog:
        new_blog = Blog(title=title, blog=blog, author=current_user)
        db.session.add(new_blog)
        db.session.commit()

        return jsonify({'message': "Blog created!"})
    else:
        return jsonify({'message': "Blog does not created! missing some fields"})


@app.route('/blog/<blog_id>', methods=['DELETE'])
@jwt_required()
def delete_blog(blog_id):
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    blog = Blog.query.filter_by(id=blog_id, author=current_user).first()
    if blog:
        db.session.delete(blog)
        db.session.commit()
        return jsonify({'message': 'BLog item deleted!'})
    else:
        return jsonify({'message': 'No Blog found!'})


@app.route('/blog/<blog_id>/comment', methods=['GET'])
@jwt_required()
def get_all_comment(blog_id):
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)

    comments = Comment.query.filter_by(post_id=blog_id).all()
    if comments:
        comment_schema = CommentSchema(many=True)
        comment_data = comment_schema.dump(comments)
        return jsonify(comment_data)
    else:
        return jsonify({'message': "No comments found"})


@app.route('/blog/<blog_id>/comment/<comment_id>', methods=['GET'])
@jwt_required()
def get_one_comment(blog_id, comment_id):
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    comment = Comment.query.filter_by(id=comment_id).first()
    blog = Blog.query.filter_by(id=blog_id).first()
    print(comment)
    print(blog)

    if comment and blog:
        comment_schema = CommentSchema()
        comment_data = comment_schema.dump(comment)
        comment_data['Blog'] = blog.blog
        comment_data['Blog Title'] = blog.title

        return jsonify(comment_data)

    else:
        return jsonify({"message": "No comment Found !!!"})


@app.route('/blog/<blog_id>/comment', methods=['POST'])
@jwt_required()
def create_comment(blog_id):
    data = request.get_json()
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    new_comment = Comment(text=data['text'], author=current_user, post_id=blog_id)

    db.session.add(new_comment)
    db.session.commit()

    return jsonify({'message': "Commented on Blog!"})


@app.route('/blog/<blog_id>/comment/<comment_id>', methods=['DELETE'])
@jwt_required()
def delete_comment(blog_id, comment_id):
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    comment = Comment.query.filter_by(id=comment_id, author=current_user).first()

    if not comment:
        return jsonify({'message': 'No Comment found by User!'})

    db.session.delete(comment)
    db.session.commit()
    print(comment)

    return jsonify({'message': 'Comment  deleted!'})


if __name__ == '__main__':
    app.run(debug=True)
