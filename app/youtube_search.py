"""
Модуль для взаимодействия с YouTube Data API v3.
Предоставляет функцию поиска видео по ключевым словам.
"""

import os
from googleapiclient.discovery import build
from .config import Config


def search_youtube(query: str, max_results: int = 5):
    """
    Выполняет поиск видео на YouTube по заданному запросу.
    Возвращает список словарей с информацией о видео (title, url, thumbnail, description).
    """
    try:
        youtube = build("youtube", "v3", developerKey=Config.YOUTUBE_API_KEY)
        request = youtube.search().list(
            q=query,
            part="snippet",
            type="video",
            maxResults=max_results,
            relevanceLanguage="ru"
        )
        response = request.execute()
        results = []
        for item in response.get("items", []):
            video_id = item["id"]["videoId"]
            title = item["snippet"]["title"]
            description = item["snippet"]["description"]
            thumbnail = item["snippet"]["thumbnails"]["default"]["url"]
            results.append({
                "title": title,
                "url": f"https://www.youtube.com/watch?v={video_id}",
                "thumbnail": thumbnail,
                "description": description[:100] + "..." if len(description) > 100 else description
            })
        return results
    except Exception as e:
        print(f"YouTube API error: {e}")
        return []