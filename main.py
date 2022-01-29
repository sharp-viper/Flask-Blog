from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegUser, LogMeIn, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['my_secret_key']
ckeditor = CKEditor(app)
Bootstrap(app)


## CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

## CONFIGURE TABLES


class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)

    posts = relationship('BlogPost', back_populates='author')

    comments = relationship('Comment',back_populates='commentator')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = relationship("User", back_populates="posts")

    comments = relationship('Comment', back_populates='parent_post')


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    commentator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    commentator = relationship("User", back_populates="comments")

    parent_post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship('BlogPost', back_populates='comments')

# db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_func(*args, **kwargs):
        if current_user.get_id() == '1':
            return f(*args, **kwargs)
        return abort(403)
    return decorated_func


@app.route('/')
def get_all_posts():
    year = datetime.datetime.now().year
    x = current_user.get_id()
    try:
        name = current_user.name
    except AttributeError:
        name = 'to all of you!'

    if x == '1':
        x = True
    else:
        x = False

    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, admin=x, year=year, name=f"{name}")


@app.route('/register', methods=['GET', 'POST'])
def register():
    year = datetime.datetime.now().year
    form = RegUser()
    try:
        name = current_user.name
    except AttributeError:
        name = 'to all of you!'

    if request.method == 'POST':
        name = form.name.data
        password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        email = form.email.data

        try:
            if email == User.query.filter_by(email=email).first().email:
                flash('This user already exists, try to Log In instead =)')
                return redirect('/login')

        except:

            new_user = User(email=email, password=password, name=name)

            db.session.add(new_user)
            db.session.commit()

            return redirect('/')

    return render_template("register.html", form=form, year=year, name=name)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LogMeIn()
    year = datetime.datetime.now().year

    try:
        name = current_user.name
    except AttributeError:
        name = 'to all of you!'

    if request.method == 'POST':
        logging_mail = form.email.data
        logging_pass = form.password.data
        user_lookup = User.query.filter_by(email=logging_mail).first()

        if user_lookup and user_lookup.email == logging_mail:
            if check_password_hash(user_lookup.password, logging_pass):

                login_user(user_lookup)
                return redirect('/')

            else:
                flash('Wrong password')
                return redirect('/login')
        else:
            flash('Wrong username or password')
            return redirect('/login')

    return render_template("login.html", form=form, year=year, name=name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods={'GET', 'POST'})
def show_post(post_id):
    form = CommentForm()
    year = datetime.datetime.now().year
    x = current_user.get_id()
    try:
        name = current_user.name
    except:
        name = 'all of you!'
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        text = form.comment.data

        new_comment = Comment(text=text, commentator=current_user, parent_post_id=post_id)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(f'/post/{post_id}')

    if x == '1':
        x = True
    else:
        x = False
    requested_post = BlogPost.query.get(post_id)
    post_comments = Comment.query.filter_by(parent_post_id=post_id).all()

    return render_template("post.html", post=requested_post, admin=x, year=year, form=form, comments=post_comments, name=f"{name.capitalize()}")


@app.route("/about")
def about():
    try:
        name = current_user.name
    except AttributeError:
        name = 'to all of you!'
    return render_template("about.html", name=name)


@app.route("/contact")
def contact():
    try:
        name = current_user.name
    except AttributeError:
        name = 'to all of you!'
    return render_template("contact.html", name=name)


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    year = datetime.datetime.now().year
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, year=year)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    year = datetime.datetime.now().year
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )

    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data

        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, year=year)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)

