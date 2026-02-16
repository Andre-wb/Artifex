from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from routes import router

app = FastAPI(title="Artifex - Дневник")

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(router)