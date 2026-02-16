from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("base.html", {"request": request})

@router.get("/timetable", response_class=HTMLResponse)
async def timetable(request: Request):
    return templates.TemplateResponse("timetable.html", {"request": request})

@router.get("/rating", response_class=HTMLResponse)
async def rating(request: Request):
    return templates.TemplateResponse("rating.html", {"request": request})

@router.get("/profile", response_class=HTMLResponse)
async def profile(request: Request):
    return templates.TemplateResponse("profile.html", {"request": request})