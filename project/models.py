import base64
import os
from datetime import datetime

from flask_login import UserMixin
from sqlalchemy import Integer, String, ForeignKey, Table, DateTime, func, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from . import db

# Association Table for the many-to-many relationship between Passwords and Categories
password_categories = Table(
    "password_categories", db.metadata,
    db.Column("password_id", db.Integer, db.ForeignKey("passwords.id"), primary_key=True),
    db.Column("category_id", db.Integer, db.ForeignKey("categories.id"), primary_key=True)
)

class Users(db.Model, UserMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))
    encryption_salt: Mapped[str] = mapped_column(String(64), nullable=False)
    categories: Mapped[list["Category"]] = relationship(back_populates="user")
    passwords: Mapped[list["Passwords"]] = relationship(back_populates="user")

    def __init__(self, name, email, password, encryption_salt=None):
        self.name = name
        self.email = email
        self.password = password
        self.encryption_salt = encryption_salt or base64.urlsafe_b64encode(os.urandom(16)).decode()


class Passwords(db.Model):
    __tablename__ = "passwords"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    site: Mapped[str | None] = mapped_column(String, nullable=True)
    username: Mapped[str | None] = mapped_column(String, nullable=True)
    password: Mapped[str | None] = mapped_column(String, nullable=True)
    additional_fields: Mapped[str | None] = mapped_column(String, nullable=True)
    encrypted_payload: Mapped[str] = mapped_column(Text, nullable=False)
    favicon: Mapped[str] = mapped_column(String, nullable=True)
    date_added: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, server_default=func.now(), nullable=False)
    categories: Mapped[list["Category"]] = relationship(secondary=password_categories, back_populates="passwords")
    user: Mapped["Users"] = relationship(back_populates="passwords")


class Category(db.Model):
    __tablename__ = "categories"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    user: Mapped["Users"] = relationship(back_populates="categories")
    passwords: Mapped[list["Passwords"]] = relationship(secondary=password_categories, back_populates="categories")
