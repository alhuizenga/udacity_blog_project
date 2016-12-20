# Key functions for setting entity parents

from google.appengine.ext import db


def blog_key(name='default'):
    '''Sets parent key for all blog posts'''
    return db.Key.from_path('blogs', name)


def users_key(group='default'):
    '''Sets parent key for all users'''
    return db.Key.from_path('users', group)