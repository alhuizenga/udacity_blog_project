from google.appengine.ext import db


class Comment(db.Model):
    owner = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    subject = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, comment_id, parent):
        return Comment.get_by_id(comment_id, parent)
