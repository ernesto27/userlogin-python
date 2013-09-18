import os
import webapp2
import jinja2
import hashlib
from google.appengine.ext import db
from google.appengine.api import images
import re


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Handler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)


class User(db.Model):
    username = db.StringProperty(required=True)
    email = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    avatar = db.BlobProperty()
    sex = db.StringProperty(required=True)


salt = "my secret key"

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return email or EMAIL_RE.match(email)

class Index(Handler):
    def get(self):
        self.render("register.html")


    def post(self):
        username = self.request.get("username").strip()
        email = self.request.get("email").strip()
        password1 = self.request.get("password1").strip()
        password2 = self.request.get("password2").strip()
        sex = self.request.get("sex").strip()
        accept = self.request.get("accept").strip()

        # VALIDATE FORM
        if accept == "on":
            errors = {}
            if not valid_username(username):
                errors["error_username"] = "This is not a valid username"

            if not valid_email(email):
                errors["error_email"] = "This is not a valid email"

            if not valid_password(password1):
                errors["error_pass"] = "The password must be to 3 a 20 characterers"

            if password1 != password2:
                errors["error_samepass"] = "The passwords doesn't match"


            if len(errors):
                self.render("register.html", **errors)
            else:
 
                passhash = hashlib.md5(password1+salt).hexdigest() 
                user = User(username=username, email=email,
                            password=passhash, sex=sex
                            )
                user.put()

                self.render("register.html", message="Register completed!")    
            
        else:
            self.render("register.html", conditions="Accept conditions")    


class Home(Handler):

    def get_cookies(self):
        cookies = {}
        cookies["username"] = self.request.cookies.get("username")
        cookies["email"] = self.request.cookies.get("email")
        cookies["avatar"] = self.request.cookies.get("avatar")
        cookies["key"] = self.request.cookies.get("key")
        return cookies


    def get(self):
        if self.request.cookies.get("logged") == "true":
            username = self.request.cookies.get("username")
            email = self.request.cookies.get("email")
            avatar = self.request.cookies.get("avatar")
            key = self.request.cookies.get("key")
            
            self.render("home.html", **self.get_cookies())
        else:
            self.redirect("/")
        

    def post(self):
        # CHECK VALID IMAGE TYPE
        img =  self.request.params['avatar'].filename 
        ext = img.split(".")[1]

        valid = ["jpg","jpeg","gif","png"]

        if ext in valid:
            avatar = images.resize(self.request.get('avatar'),120,120)
            username = self.request.cookies.get("username")
            user = db.GqlQuery("select * from User where username=:username", username=username)
            for u in user:
                u.avatar = avatar
                u.put()
                self.response.headers.add_header('Set-Cookie',"avatar=; Expires=Thu, 01-Jan-1970 00:00:00 GMT")
                self.redirect("home")
        else:
            #self.render("home.html", message="The avatar would be jpg, gif or png type")
            cookies_messages = self.get_cookies()
            cookies_messages["message"] = "The avatar would be jpg, gif or png type"
            self.render("home.html", **cookies_messages) 


class Login(Handler):
    def get(self):
        self.render("login.html")

    def post(self): 
        email = self.request.get("email").strip()
        password = self.request.get("password").strip()

        # VALIDATE FORM
        errors = {}
        if not valid_email(email):
            errors["error_email"] = "This is not a valid email"

        if not valid_password(password):
            errors["error_pass"] = "The password must be to 3 a 20 characterers"


        if len(errors):
            self.render("login.html", **errors)
        else:
            password = hashlib.md5(password+salt).hexdigest()
            #self.write(password)
            
            user = db.GqlQuery("select * from User where email=:email and password=:password"
                             , email=email, password=password)
            if user.count():
                for u in user:

                    self.write(u.username + "<br>")
                    self.write(str(u.key()) + "<br>")
                    self.write(u.email)

                    if u.avatar == None:
                        self.response.headers.add_header('Set-Cookie',"avatar=false")

                    self.response.headers.add_header('Set-Cookie',"logged=true")
                    self.response.headers.add_header('Set-Cookie',"username="+str(u.username))
                    self.response.headers.add_header('Set-Cookie',"email="+str(u.email))
                    self.response.headers.add_header('Set-Cookie',"key="+str(u.key()))

                self.redirect("/home")
                #self.response.headers.add_header('Set-Cookie',"logged="+str(helpers.make_secure_val("true")))

            else:
                self.render("login.html", message="The email or password is not correct")


class Logout(Handler):
    def get(self):
        self.response.headers.add_header("Set-Cookie", "logged=; Expires=Thu, 01-Jan-1970 00:00:00 GMT")
        self.response.headers.add_header("Set-Cookie", "username=; Expires=Thu, 01-Jan-1970 00:00:00 GMT")
        self.response.headers.add_header("Set-Cookie", "email=; Expires=Thu, 01-Jan-1970 00:00:00 GMT")
        self.response.headers.add_header("Set-Cookie", "avatar=; Expires=Thu, 01-Jan-1970 00:00:00 GMT")
        self.redirect("home")


class Image(webapp2.RequestHandler):
    def get(self):
        greeting = db.get(self.request.get('img_id'))
        if greeting.avatar:
            self.response.headers['Content-Type'] = 'image/png'
            self.response.out.write(greeting.avatar)
        else:
            self.error(404)



app = webapp2.WSGIApplication([('/', Index),
                               ('/login', Login) ,
                               ('/home', Home),
                               ('/logout', Logout),
                               ('/img', Image),
                              ] ,
                              debug=True)


























