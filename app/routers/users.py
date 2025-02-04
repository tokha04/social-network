from fastapi import APIRouter
from app.models.users import Users, Profiles

router = APIRouter(
    prefix="/users",
    tags=["users"]
)

