from fastapi import FastAPI

from app.routers import users
from app.database import Base, engine

app = FastAPI()

Base.metadata.create_all(bind=engine)

app.include_router(users.router)