import os

import jinja2

import webapp2

import re

import hmac

import hashlib

import secret

import random

import string

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

class Handler(webapp2.RequestHandler):
    '''Helper methods for rendering pages and managing sessions'''

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '{}={}; Path=/'.format(name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        if uid:
            self.uid = uid
            self.user = User.by_id(int(uid))
        else:
            self.user = None


class BlogHandler(Handler):
    '''Handles the forum home page'''

    def render_blog(self, blog_posts="", username="", source=""):

        if self.user:
            username = self.user.name  # check if user is logged in and get name

        source = self.request.url  # Posted to the Like handler so it can redirect back

        blog_posts = Blog_post.all().ancestor(blog_key()).order('-created').run()

        self.render("home.html",
                    blog_posts=blog_posts,
                    username=username,
                    source=source)

    def get(self):
        self.render_blog()


class PostHandler(Handler):
    '''Gets new posts and writes them to the Blog_post kind'''

    def render_form(self, subject="", content="", username="", error=""):
        self.render("newpost.html",
                    subject=subject,
                    content=content,
                    username=username,
                    error=error)

    def get(self):
        username = self.user.name
        self.render_form(username=username)

    def post(self):
        username = self.user.name
        subject = self.request.get("subject")
        content = self.request.get("content")
        owner = username
        parent = blog_key()

        if subject and content:
            p = Blog_post(parent=parent, owner=owner, subject=subject, content=content)
            p.put()
            post_id = p.key().id()
            self.redirect("/posts/{}".format(post_id))
        else:
            error = "Please fill in both the Subject and Content fields."
            self.render_form(subject, content, username, error)


class ReadPostHandler(Handler):
    '''Manages the permalink page for each post'''

    def render_post(self,
                    subject="",
                    content="",
                    created="",
                    comments="",
                    comment_count="",
                    like_count="",
                    username="",
                    owner="",
                    post_id="",
                    source="",
                    liked=""):

        self.render("readpost.html",
                    subject=subject,
                    content=content,
                    created=created,
                    comments=comments,
                    comment_count=comment_count,
                    like_count=like_count,
                    username=username,
                    owner=owner,
                    post_id=post_id,
                    source=source,
                    liked=liked)

    def get(self, post_id):

        if self.user:
            username = self.user.name
        else:
            username = None

        post_id_int = int(post_id)

        p = Blog_post.by_id(post_id_int)
        subject = p.subject
        content = p.content
        created = p.created
        owner = p.owner
        comment_count = p.comment_count
        like_count = p.like_count
        comment_key = p.key()
        source = self.request.url

        comments = Comment.all().ancestor(comment_key).order('-created').run()

        if username:
            liked = hasattr(p, username)
        else:
            liked=""

        self.render_post(subject,
                         content,
                         created,
                         comments,
                         comment_count,
                         like_count,
                         username,
                         owner,
                         post_id,
                         source,
                         liked)


class EditPostHandler(Handler):
    '''Gets post updates and writes them to the Blog_post kind'''

    def render_form(self,
                    subject="",
                    content="",
                    created="",
                    username="",
                    owner="",
                    error="",
                    post_id=""):

        self.render("editpost.html",
                    subject=subject,
                    content=content,
                    created=created,
                    username=username,
                    owner=owner,
                    error=error,
                    post_id=post_id)

    def get(self, post_id):

        post_id = int(post_id)
        username = self.user.name

        a = Blog_post.by_id(post_id)
        subject = a.subject
        content = a.content
        created = a.created.date()
        owner = a.owner

        if a.owner == username:  # Check to ensure current user owns post
            self.render_form(subject,
                             content,
                             created,
                             username,
                             owner,
                             post_id=post_id)
        else:
            self.redirect("/")

    def post(self, post_id):

        post_id = int(post_id)
        username = self.user.name

        subject = self.request.get("subject")
        content = self.request.get("content")

        a = Blog_post.by_id(post_id)
        created = a.created.date()
        owner = a.owner

        if subject and content:
            a.subject = subject
            a.content = content
            a.put()
            self.redirect("/")
        else:
            error = "Please fill in both the Subject and Content fields."
            self.render_form(subject,
                             content,
                             created,
                             username,
                             owner,
                             error,
                             post_id)


class DeletePostHandler(Handler):
    '''Deletes posts from the Blog_post kind'''

    def get(self, post_id):

        post_id = int(post_id)

        a = Blog_post.by_id(post_id)
        db.delete(a.key())
        self.redirect('/')


class MyPostsHandler(Handler):
    '''Handles the page for displaying all posts from a user'''

    def render_posts(self, blog_posts="", username=""):
        username = self.user.name
        blog_posts = Blog_post.all().filter("owner =", username).order('-created').run()
        self.render("my_posts.html", blog_posts=blog_posts, username=username)

    def get(self):
        self.render_posts()


class CommentHandler(Handler):
    '''Gets comments and writes them to the Comment kind'''

    def render_form(self, subject="", comment="", username="", error="", post_id=""):
        self.render("comment.html",
                    subject=subject,
                    comment=comment,
                    username=username,
                    error=error,
                    post_id=post_id)

    def get(self, post_id):

        username = self.user.name
        post_id = int(post_id)

        q = Blog_post.by_id(post_id)
        subject = q.subject
        self.render_form(subject=subject, username=username, post_id=post_id)

    def post(self, post_id):

        username = self.user.name
        comment = self.request.get("comment")
        owner = username
        post_id = self.request.get("post_id")
        post_id = int(post_id)

        q = Blog_post.by_id(post_id)
        parent = q.key()  #Comment's parent is key of associated post
        subject = q.subject

        if comment:
            c = Comment(parent=parent, owner=owner, comment=comment)
            c.put()
            q.comment_count += 1
            q.put()
            self.redirect("/posts/{}".format(post_id))
        else:
            error = "Please add your comment."
            self.render_form(subject, comment, username, error, post_id)


class LikeHandler(Handler):
    '''Handles like requests.
    Each Blog_post entity has a like counter, and a dynamic attribute
    for each user that has liked it.
    When user clicks Like, handler checks for like attribute, creates
    it if it doesn't exist, and increments the counter.
    When user clicks Unlike, handler checks for like attribute, deletes
    it if it exists, and decrements the counter.
    '''

    def post(self):

        post_id = self.request.get("post_id")
        post_id = int(post_id)
        liked = self.request.get("liked")
        username = self.request.get("username")
        source = self.request.get("source")
        source = str(source)

        p = Blog_post.by_id(post_id)

        if liked == "False":
            if hasattr(p, username):
                delattr(p, username)
                p.like_count -= 1
                p.put()
                self.redirect(source)
        else:
            if hasattr(p, username):  # Has user liked post already?
                self.redirect("/")
            else:
                setattr(p, username, "liked")
                p.like_count += 1
                p.put()
                self.redirect(source)


class SignupHandler(Handler):

    def get(self):
        self.render("register.html")

    def post(self):

        name = self.request.get('username')  # Get form post parameters
        pw = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        valid_username = validate_username(name)  # Validate them
        if valid_username:
            new_username = check_username_exists(name)
        valid_password = validate_password(pw)
        valid_verify = match_passwords(verify, valid_password)
        email_exists = check_for_email(email)
        if email_exists:
            valid_email = validate_email(email_exists)
        else:
            valid_email = "no_email"

        username_error = ""  #Create error variables
        username_exists_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""

        if (valid_username and new_username and valid_password
            and valid_verify and valid_email):  # If form inputs are
                                                # valid and username is new

            u = User.register(name, pw, email)  # Register the new user
            u.put()

            self.login(u) # Login as the new user
            self.redirect("/")

        # Else, return the form, persisting the input values,
        # and show the appropriate error messages
        else:
            if not valid_username:
                username_error = "That's not a valid username."
            if valid_username:
                if not new_username:
                    username_exists_error = "That username already exists"
            if not valid_password:
                password_error = "That wasn't a valid password."
            if not valid_verify:
                verify_error = "Your passwords didn't match."
            if valid_email != "no_email":
                email_error = "That's not a valid email."

            self.render("register.html",
                        username=name,
                        password=pw,
                        verify=verify,
                        email=email,
                        username_error=username_error,
                        username_exists_error=username_exists_error,
                        password_error=password_error,
                        verify_error=verify_error,
                        email_error=email_error)


class LoginHandler(Handler):

    def get(self):
        self.render("login.html")

    def post(self):

        name = self.request.get('username')
        pw = self.request.get('password')

        valid_username = validate_username(name)
        if valid_username:
            new_username = check_username_exists(name)
        valid_password = validate_password(pw)

        username_error = ""
        username_nonexistent_error = ""
        password_error = ""

        if valid_username and not new_username and valid_password:

            u = User.by_name(name)
            self.login(u)
            self.redirect("/")

        else:
            if not valid_username:
                username_error = "That's not a valid username."
            if valid_username:
                if new_username:
                    username_nonexistent_error = "That username does not exist"
            if not valid_password:
                password_error = "That wasn't a valid password."

            self.render("login.html",
                        username=name,
                        password=pw,
                        username_error=username_error,
                        username_nonexistent_error=username_nonexistent_error,
                        password_error=password_error)


class LogoutHandler(Handler):

    def get(self):
        self.logout()
        self.redirect("/")


app = webapp2.WSGIApplication([
    ('/', BlogHandler),
    ('/post', PostHandler),
    ('/my_posts', MyPostsHandler),
    ('/signup', SignupHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/like', LikeHandler),
    webapp2.Route(r'/posts/<post_id>', handler=ReadPostHandler, name='post_id'),
    webapp2.Route(r'/edit/<post_id>', handler=EditPostHandler, name='post_id'),
    webapp2.Route(r'/delete/<post_id>', handler=DeletePostHandler, name='post_id'),
    webapp2.Route(r'/comment/<post_id>', handler=CommentHandler, name='post_id'),
], debug=True)


# Validation functions for signup and login

def validate_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    if username:
        if USER_RE.match(username):
            return username


def check_username_exists(username):
    u = User.by_name(username)
    if not u:
        return username


def validate_password(password):
    USER_RE = re.compile(r"^.{3,20}$")
    if password:
        if USER_RE.match(password):
            return password


def match_passwords(verify, password):
    if verify == password:
        return verify


def check_for_email(email):
    if email:
        return email


def validate_email(email):
    USER_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    if email:
        if USER_RE.match(email):
            return email


# Encryption functions for cookies and passwords

SECRET = secret.SECRET

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "{}|{}".format(s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def make_salt(length=5):
    return ''.join(random.choice(string.letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '{},{}'.format(salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


# Kinds

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name = ', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.hash):
            return u


def users_key(group='default'):
    '''Sets parent key for all users'''
    return db.Key.from_path('users', group)


class Blog_post(db.Expando):
    '''Use the Expando class so that we can add dynamic user
    attributes to post entities to track likes.
    '''

    owner = db.StringProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty()
    comment_count = db.IntegerProperty(default=0)
    like_count = db.IntegerProperty(default=0)

    @classmethod
    def by_id(cls, post_id):
        return Blog_post.get_by_id(post_id, parent=blog_key())


def blog_key(name='default'):
    '''Sets parent key for all blog posts'''
    return db.Key.from_path('blogs', name)


class Comment(db.Model):
    owner = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, comment_id, parent):
        return Comment.get_by_id(comment_id, parent)




