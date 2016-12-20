# Udacity Multi-User Blog Project

[Live at https://udacity-blog-project-152717.appspot.com](https://udacity-blog-project-152717.appspot.com)

## Frameworks
- [Bootstrap](http://getbootstrap.com/)
- [Google Cloud](https://cloud.google.com/)
- [Google Cloud Datastore](https://cloud.google.com/datastore/docs/concepts/overview)
- [Jinja2](http://jinja.pocoo.org/)

## Run the project

1. [Clone this repository](https://github.com/alhuizenga/udacity_blog_project.git).
2. [Install Python](https://www.python.org/downloads/).
3. Install the [Google Cloud SDK](https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Python).
4. Run the app at http://localhost:8080/ from the root folder using dev_appserver.py.

## Secret

It's in the secret.py file.

## Features

### Comments

Stored in a separate kind called Comment. Parent for each comment is set to the key of its associated post to make it easy and fast to retrieve and display all comments for a post. Blog_post entities also have a "comment_count" attribute.

### Likes
Used Expando class to create Blog_post kind. When users click Like for a post, the Like handler adds a dynamic attribute to a blog post entity, named after the user. The handler checks for the existence of the attribute to determine whether a user has already liked a post or not, and also increments a like_counter attribute on the associated blog post.
