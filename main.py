import os
import re
import random
import hashlib
import hmac
from string import letters
import json
#import logging
import markdown2
import webapp2
import jinja2
from datetime import datetime, timedelta

from google.appengine.api import memcache
from google.appengine.ext import db
from google.appengine.ext.db import polymodel

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'K*g8wp$.Nr/x0bf^'

def convert_markup(content):
    content = str(jinja2.escape(content))
    content = markdown2.markdown(content)
    return content

jinja_env.filters['convert_markup'] = convert_markup

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def as_dict(self, post):
        d = {
        'subject':post.subject,
        'content':post.content,
        'created':post.created.strftime("%d %b, %Y"),
        'last_modified':post.last_modified.strftime("%d %b, %Y"),
        }
        return d

    def render_json(self, dic):
        dic = json.dumps(dic)
        self.response.headers['Content-Type'] = "application/json"
        self.write(dic)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

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
        self.user = uid and User.by_id(int(uid))

        if self.request.url.endswith(".json"):
            self.format = "json"
        else:
            self.format = "html"


##### user stuff
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
    return db.Key.from_path('users', group)

class User(polymodel.PolyModel):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(self, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(self, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(self, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(self, name, pw):
        u = self.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(User):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)


USER_RE = re.compile(r"^[a-zA-Z]{3,20}$")
def valid_username(username):
    if username != "newpost":
        return username and USER_RE.match(username)
    else:
        return None

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    if re.search("[a-zA-Z]",password) and re.search("[0-9]",password):
        return password and PASS_RE.match(password)
    else:
        return None

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class SignupHandler(Handler):
    def get(self):
        if self.user:
            self.redirect("/blog")
        else:
            self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            if self.username == "newpost":
                params['error_username'] = "You just had to try, didn't you? Well it's not gonna work, sorry"
            else:
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
            self.render('signup-form.html', **params)
        else:
            self.done()

#### Authentication stuff
class RegisterHandler(SignupHandler):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

class LogoutHandler(Handler):
    def get(self):
        self.logout()
        memcache.delete(self.user.name)
        memcache.delete(self.user.name+"time")
        self.redirect('/login')

class WelcomeHandler(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/')

class LoginHandler(Handler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

##### BlogHandler Stuff
def top_cache(uname, update = False):
    key = uname
    posts = memcache.get(key)
    cur_time = key + "time" 
    if posts is None or update:
        #logging.error("DB Query")
        posts = greetings = Post.all().filter('name =', uname).order('-created')
        posts = list(posts)
        memcache.set(key,posts)
        memcache.set(cur_time,datetime.now())
    return posts,memcache.get(cur_time)

def bottom_cache(post_id, update = False):
    key = post_id
    post = memcache.get(key)
    cur_time = key + "time"
    if post is None or update:
        #logging.error("DB Query")
        post = Post.get_by_id(int(post_id), parent=users_key())
        memcache.set(key,post)
        memcache.set(cur_time,datetime.now())
    return post,memcache.get(cur_time)

class BlogFrontHandler(Handler):
    def get(self):
        if self.user:
            posts = top_cache(self.user.name)[0]
            if self.format == "html":
                age = (datetime.now() - top_cache(self.user.name)[1]).total_seconds()
                age = "Queried " + str(int(age)) + " seconds ago"
                self.render('front.html', posts = posts, age = age)

            elif self.format == "json":
                for post in posts:
                    self.render_json(self.as_dict(post))

        else:
            self.redirect("/login")

    def post(self):
        self.redirect("/blog/newpost")

class PostPageHandler(Handler):
    def get(self, post_id):
        post = bottom_cache(post_id)[0]
        if not post or (post.name != self.user.name):
                self.error(404)
                return
        if self.format == "json":
            self.render_json(self.as_dict(post))
        elif self.format == "html":
            age = (datetime.now() - top_cache(self.user.name)[1]).total_seconds()
            age = "Queried " + str(int(age)) + " seconds ago"
            self.render("postpage.html", blog = post, age = age)

    def post(self, post_id):
        blog = Post.get_by_id(int(post_id), parent=users_key())
        active = self.request.get("active")
        if active == "delete":
            blog.delete()
            temp1 = bottom_cache(post_id,True)
            temp = top_cache(self.user.name,True)
            memcache.delete(post_id)
            memcache.delete(post_id+"time")
            self.render("deletemessage.html")
        elif active == "update":
            self.redirect("/blog/"+post_id+"/edit")
        else:
            self.render("postpage.html",blog=blog)

class NewpostHandler(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = users_key(), subject = subject, content = content, name = self.user.name, pw_hash = self.user.pw_hash)
            p.put()
            temp1 = bottom_cache(str(p.key().id()),True)
            temp = top_cache(self.user.name,True)
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class EditHandler(Handler):
    def get(self, post_id):
        post = bottom_cache(post_id)[0]
        if post.name != self.user.name:
            self.error("404")
            return
        else:
            self.render("newpost.html",subject=post.subject,content=post.content,url_id="/"+post_id)

    def post(self, post_id):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            blog = Post.get_by_id(int(post_id), parent=users_key())
            blog.subject = subject
            blog.content = content
            blog.put()
            temp = bottom_cache(post_id, True)
            temp1 = top_cache(self.user.name, True)
            self.redirect("/blog/"+str(blog.key().id()))
        else:
            error = "Sorry but we need a subject and a blog-content!"
            self.render("newpost.html",subject=subject,content=content,error=error)

class OtherHandler(Handler):
    def get(self,username):
        if User.by_name(username):
            posts = top_cache(username)[0]
            if self.format == "html":
                age = (datetime.now() - top_cache(username)[1]).total_seconds()
                age = "Queried " + str(int(age)) + " seconds ago"
                self.render('others.html', posts = posts, age = age)

            elif self.format == "json":
                for post in posts:
                    self.render_json(self.as_dict(post))
        else:
            self.error("404")

app = webapp2.WSGIApplication([('/',RegisterHandler),
                               ('/blog', BlogFrontHandler),
                               ('/blog/newpost', NewpostHandler),
                               ('/blog/([0-9]+)', PostPageHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/welcome', WelcomeHandler),
                               ('/blog/(\d+)/edit', EditHandler),
                               ('/blog.json', BlogFrontHandler),
                               ('/blog/(\d+).json', PostPageHandler),
                               ('/blog/([a-zA-Z]+)', OtherHandler),
                               ],
                              debug=True)