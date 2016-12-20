# Validation functions for signup and login

import re

from user import User

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