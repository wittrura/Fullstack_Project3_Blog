import os
import jinja2
import webapp2
import hmac
import random
from string import letters
import hashlib
import re

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secret = 'banana'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

##### #####
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        params['user'] = self.user
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
        'Set-Cookie',
        '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

##### #####
class Signup(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username, email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_username'] = "That's not a valid password."
            have_error = True

        elif self.password != self.verify:
            params['error_verify'] = "Passwords do not match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

##### password hashing and validation #####
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return ndb.Key('users', group)

##### #####
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

##### data models #####
def blog_key(name = 'default'):
    return ndb.Key('blogs', name)



class User(ndb.Model):
    name = ndb.StringProperty(required = True)
    pw_hash = ndb.StringProperty(required = True)
    email = ndb.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.query(User.name == name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent = users_key(), name = name, pw_hash = pw_hash, email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Post(ndb.Model):
    subject = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    created = ndb.DateTimeProperty(auto_now_add = True)
    last_modified = ndb.DateTimeProperty(auto_now_add = True)
    author = ndb.KeyProperty(kind=User)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')

        post_id = self.key.id()
        author = self.author.get()

        return render_str("post.html", p = self, post_id = post_id, author = author)

##### page handlers #####
class MainPage(Handler):
    def get(self):
        posts = Post.query().order(-Post.created)
        self.render('front.html', posts = posts)

class NewPost(Handler):
    def get(self):
        if self.user:
            self.render('form.html')
        else:
            self.redirect('/login')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        uid = self.read_secure_cookie('user_id')
        user_key = ndb.Key(User, int(uid))

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, author = user_key)
            p_key = p.put()
            self.redirect('/%s' % str(p_key.integer_id()))
        else:
            error = "subject and content are both required"
            self.render('form.html', subject = subject, content = content, error = error)

class PostPage(Handler):
    def get(self, post_id):
        key = ndb.Key(Post, int(post_id), parent=blog_key())
        post = key.get()

        if not post:
            self.error(404)
            return

        self.render('permalink.html', post = post)

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/welcome')

class Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/signup')

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/newpost', NewPost),
    ('/([0-9]+)', PostPage),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/welcome', Welcome)
], debug=True)
