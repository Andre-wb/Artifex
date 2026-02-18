from fastapi import APIRouter, Depends, Query
from .youtube_search import search_youtube

router = APIRouter()

@router.get("/api/materials/search")
async def search_materials(
        q: str = Query(..., min_length=3, description="Тема для поиска"),
        max_results: int = Query(5, ge=1, le=10)
):
    """
    Ищет образовательные видео на YouTube по заданной теме.
    """
    results = search_youtube(q, max_results)
    return {"success": True, "results": results}