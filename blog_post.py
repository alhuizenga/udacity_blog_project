from google.appengine.ext import db

from keys import blog_key


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
