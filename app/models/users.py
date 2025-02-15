from app.database import Base
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from datetime import datetime

class Users(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    password = Column(String)
    role = Column(String)
    profile_id = Column(Integer, ForeignKey("profiles.id"))

class Profiles(Base):
    __tablename__ = 'profiles'

    id = Column(Integer, primary_key=True, index = True)
    name = Column(String)
    surname = Column(String)
    birth_date = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, onupdate=datetime.utcnow)
    is_verified = Column(Boolean, default=False)
    last_login = Column(DateTime)
    is_active = Column(Boolean)