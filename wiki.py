import os
import webapp2
import jinja2
import re
import random
import string
import hashlib
import logging
import time

from string import letters

from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Authentication Section

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PWD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


def valid_username(username):
    return USER_RE.match(username)


def valid_password(password):
    return PWD_RE.match(password)


def valid_email(email):
    if email:
        return EMAIL_RE.match(email)
    else:
        return True


def password_match(password, verpassword):
    return password == verpassword


# Hashing Section

def hash_str(s):
    return hashlib.md5(s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    if h == make_pw_hash(name, pw, h.split(',')[1]):
        return True


# Store last visited URL
LAST_PATH = "/"


class Handler(webapp2.RequestHandler):
    def write(self, *a, **lw):
        self.response.out.write(*a, **lw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and Users.by_id(int(uid))
        curr_path = self.request.path
        if not "logout" in curr_path:
            global LAST_PATH
            LAST_PATH = curr_path


def users_key(group='default'):
    return db.Key.from_path('users', group)


class Users(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    datemod = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls, uid):
        return Users.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = Users.all().filter('username =', name).get()
        return u


class Signup(Handler):

    def get(self):
        self.render('signup-page.html')

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username, email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-page.html', **params)
        else:
            if Users.by_name(self.username):
                msg = "That user already exists!"

                self.render('signup-page.html',
                            username=self.username,
                            error_username=msg)
                return

            hash_pw = make_pw_hash(self.username, self.password)
            u = Users(
                parent=users_key(),
                username=self.username,
                password=hash_pw,
                email=self.email
            )

            u.put()

            # Setting up cookies
            hash_uid = make_secure_val(str(u.key().id()))

            self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % str(hash_uid))
            self.redirect('/')


class Login(Handler):
    def get(self):
        self.render('login-page.html')

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')

        params = dict(username=username)

        if not valid_username(username):
            params['error_username'] = "Invalid username!"
            have_error = True

        if not valid_password(password):
            params['error_password'] = "Invalid Password!"
            have_error = True

        if have_error:
            self.render('login-page.html', **params)
            return

        query = db.GqlQuery("SELECT * "
                            "FROM Users "
                            "WHERE username = :1 "
                            "LIMIT 1",
                            username).get()
        if query:
            uid = query.key().id()
            pwd = query.password
            salt = pwd.split(',')[1]

            if pwd != make_pw_hash(username, password, salt):
                invalidlogin = "Invalid Password!"
                params['invalidlogin'] = invalidlogin
                params['username'] = username

                self.render('login-page.html', **params)
                return
        else:
            invalidlogin = "Invalid login!"
            params['invalidlogin'] = invalidlogin
            params['username'] = username

            self.render('login-page.html', **params)
            return

        hash_uid = make_secure_val(str(uid))
        self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % str(hash_uid))
        self.redirect('/')


class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect(LAST_PATH)


def wiki_key(name='default'):
    return db.Key.from_path('wiki', name)


class Wiki(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    version = db.IntegerProperty(required=True, default=1)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


# Note: The Edit Page will always render
# the latest wiki since after the edit,
# memcache is being updated.
class EditPage(Handler):
    def get(self, path):
        if self.user:
            content = memcache.get(path)
            if not content:
                self.render('edit-page.html', path=path)
            else:
                self.render('edit-page.html', path=path, content=content)
        else:
            self.redirect('/login')

    def post(self, path):
        content = self.request.get('content').strip()

        if not self.user:
            self.redirect('/login')
            return

        if content:
            query = db.GqlQuery("SELECT * "
                                "FROM Wiki "
                                "WHERE title = :1 "
                                "ORDER BY created DESC",
                                path).get()

            version = query.version + 1 if query else 1
            wk = Wiki(
                parent=wiki_key(),
                title=path,
                content=content,
                version=version
            )

            wk.put()

            memcache.set(path, content)
            self.redirect(path)
        else:
            self.render('edit-page.html', error="Content is required!")


class WikiPage(Handler):
    def get(self, path):
        quer_str = self.request.query_string

        if not quer_str:
            content = memcache.get(path)
            if not content:
                self.redirect('/_edit' + path)
            else:
                self.render('wiki-page.html', path=path, content=content)
        else:
            version = int(quer_str.split('=')[1])
            query = db.GqlQuery("SELECT * "
                                "FROM Wiki "
                                "WHERE title = :1 "
                                "AND version = :2",
                                path, version).get()

            content = query.content
            memcache.set(path, content)
            self.render('wiki-page.html', path=path, content=content)


class HistoryPage(Handler):
    def get(self, path):
        query = db.GqlQuery("SELECT * "
                            "FROM Wiki "
                            "WHERE title = :1 "
                            "AND version > 1 "
                            "ORDER BY version DESC",
                            path)

        query = list(query)
        self.render('history-page.html', path=path, history=query)


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_history' + PAGE_RE, HistoryPage),
                               ('/_edit' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage)
                               ],
                              debug=True)
