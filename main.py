# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import jinja2
import webapp2

from google.appengine.ext import db

template_dir=os.path.join(os.path.dirname(__file__),"templates")
jinja_env=jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
	autoescape = True)


class Handler(webapp2.RequestHandler):
	def write(self,*a,**kw):
		self.response.out.write(*a,**kw)

	def render_str(self,template,**params):
		t=jinja_env.get_template(template)
		return t.render(params)

	def render(self,template,**kw):
		self.write(self.render_str(template,**kw))

class Blog(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)


class MainPage(Handler):
    def get(self):
    	blogs=db.GqlQuery("select * from Blog order by created desc")
    	self.render("front.html",blogs=blogs)

    def post(self):
    	self.redirect("/newpost")

class NewpostHandler(Handler):
 	def get(self):
 		self.render("newpost.html")

 	def post(self):
 		subject = self.request.get("subject")
 		content = self.request.get("content")
 		if subject and content:
 			b = Blog(subject=subject,content=content)
 			b.put()
 			self.redirect("/"+str(b.key().id()))
 		else:
 			error = "Sorry but we need a subject and a blog-content!"
 			self.render("newpost.html",subject=subject,content=content,error=error)

class PostpageHandler(Handler):
	def get(self, blog_id):
		key = db.Key.from_path("Blog",int(blog_id))
		blog = db.get(key)
		if not blog:
			self.error(404)
			return
		else:
			self.render("postpage.html",blog=blog)

	def post(self, blog_id):
		key = db.Key.from_path("Blog",int(blog_id))
		blog = db.get(key)
		active = self.request.get("active")
		if active == "delete":
			blog.delete()
			self.render("deletemessage.html")
		elif active == "update":
			self.redirect("/"+blog_id+"/edit")
		else:
			self.render("postpage.html",blog=blog)

class EditHandler(Handler):
	def get(self, blog_id):
		key = db.Key.from_path("Blog",int(blog_id))
		blog = db.get(key)
		self.render("newpost.html",subject=blog.subject,content=blog.content)

	def post(self, blog_id):
		subject = self.request.get("subject")
 		content = self.request.get("content")
 		if subject and content:
 			key = db.Key.from_path("Blog",int(blog_id))
			blog = db.get(key)
			blog.subject = subject
			blog.content = content
			blog.put()
			self.redirect("/"+str(blog.key().id()))
 		else:
 			error = "Sorry but we need a subject and a blog-content!"
 			self.render("newpost.html",subject=subject,content=content,error=error)

     
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/newpost', NewpostHandler),
    ('/(\d+)', PostpageHandler),
    ('/(\d+)/edit', EditHandler),
], debug=True)