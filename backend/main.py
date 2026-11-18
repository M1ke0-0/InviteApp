import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager, asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import List
from uuid import UUID
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

DB_PATH = Path(os.getenv('DATABASE_PATH', 'data/invite.sqlite3'))
FRONTEND = Path(os.getenv('FRONTEND_DIST', 'frontend/dist'))
COOKIE_SECURE = os.getenv('COOKIE_SECURE', 'false').lower() == 'true'
TIMEZONE = ZoneInfo(os.getenv('APP_TIMEZONE', 'Europe/Moscow'))
DEFAULT = {
    'recipient': 'Для тебя',
    'title': 'Давай устроим\nмаленькое свидание?',
    'intro': 'Есть один замечательный план: ты, я и время, которое никуда не спешит. Осталось только сказать «да».',
    'final_title': 'Это свидание ♡',
    'final_text': 'Самое важное в этом плане — ты. Всё остальное мы уже придумали. С нетерпением жду нашей встречи!',
    'default_time': '18:00',
    'activities': [
        {'id': 'coffee', 'emoji': '☕', 'title': 'Кофе и разговоры', 'description': 'Уютное место и никаких планов спешить'},
        {'id': 'walk', 'emoji': '🌿', 'title': 'Прогулка вдвоём', 'description': 'Знакомые улицы, новые воспоминания'},
        {'id': 'dinner', 'emoji': '🍝', 'title': 'Красивый ужин', 'description': 'Что-нибудь вкусное и немного романтики'},
        {'id': 'cinema', 'emoji': '🎬', 'title': 'Вечер в кино', 'description': 'Выберем фильм. Попкорн — обязательно'}
    ]
}

@contextmanager
def db():
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    try:
        with con:
            yield con
    finally:
        con.close()

@asynccontextmanager
async def lifespan(app):
    password = os.getenv('ADMIN_PASSWORD', '')
    if len(password) < 12:
        raise RuntimeError('Задайте ADMIN_PASSWORD длиной не менее 12 символов.')
    app.state.password_salt = secrets.token_bytes(32)
    app.state.password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), app.state.password_salt, 200_000)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as con:
        con.execute('PRAGMA journal_mode=WAL')
        con.executescript('''
          CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, expires REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS attempts (ip TEXT NOT NULL, created REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS invitations (id TEXT PRIMARY KEY, value TEXT NOT NULL, created TEXT NOT NULL);
        ''')
        con.execute('INSERT OR IGNORE INTO settings VALUES (1, ?)', (json.dumps(DEFAULT, ensure_ascii=False),))
    yield

app = FastAPI(title='Для тебя · Invitation', lifespan=lifespan)

@app.middleware('http')
async def headers(request, call_next):
    if request.method in ('POST', 'PUT', 'DELETE'):
        origin = request.headers.get('origin')
        if origin and (urlsplit(origin).scheme not in ('http', 'https') or urlsplit(origin).netloc != request.headers.get('host')):
            return Response('Недопустимый источник запроса', status_code=403)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['X-Frame-Options'] = 'DENY'
    if request.url.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'
    return response

def admin(request: Request):
    token = hashlib.sha256(request.cookies.get('invite_admin', '').encode()).hexdigest()
    with db() as con:
        row = con.execute('SELECT expires FROM sessions WHERE token=?', (token,)).fetchone()
    if not row or row['expires'] < time.time():
        raise HTTPException(401, 'Войдите в админку')

def settings():
    with db() as con:
        return json.loads(con.execute('SELECT value FROM settings WHERE id=1').fetchone()['value'])

class Activity(BaseModel):
    id: str = Field(min_length=1, max_length=60, pattern=r'^[a-zA-Z0-9_-]+$')
    emoji: str = Field(min_length=1, max_length=12)
    title: str = Field(min_length=1, max_length=100)
    description: str = Field(max_length=250)

class Settings(BaseModel):
    recipient: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=250)
    intro: str = Field(min_length=1, max_length=2000)
    final_title: str = Field(min_length=1, max_length=250)
    final_text: str = Field(min_length=1, max_length=3000)
    default_time: str = Field(pattern=r'^([01]\d|2[0-3]):[0-5]\d$')
    activities: List[Activity] = Field(min_length=1, max_length=20)

    @field_validator('activities')
    @classmethod
    def unique(cls, items):
        if len({a.id for a in items}) != len(items):
            raise ValueError('ID занятий должны быть уникальными')
        return items

class Login(BaseModel):
    password: str = Field(max_length=1024)

class Booking(BaseModel):
    id: UUID
    activity_id: str = Field(max_length=60)
    date: str = Field(pattern=r'^\d{4}-\d{2}-\d{2}$')
    time: str = Field(pattern=r'^([01]\d|2[0-3]):[0-5]\d$')

@app.get('/api/health')
def health():
    with db() as con:
        con.execute('SELECT 1')
    return {'status': 'ok'}

@app.get('/api/config')
def config():
    return {**settings(), 'timezone': str(TIMEZONE), 'today': datetime.now(TIMEZONE).date().isoformat()}

@app.post('/api/admin/login')
def login(body: Login, request: Request, response: Response):
    ip = request.client.host if request.client else 'unknown'
    with db() as con:
        con.execute('DELETE FROM attempts WHERE created < ?', (time.time() - 900,))
        if con.execute('SELECT count(*) FROM attempts WHERE ip=?', (ip,)).fetchone()[0] >= 10:
            raise HTTPException(429, 'Слишком много попыток. Попробуйте через 15 минут.')
        con.execute('INSERT INTO attempts VALUES (?, ?)', (ip, time.time()))
    digest = hashlib.pbkdf2_hmac('sha256', body.password.encode(), app.state.password_salt, 200_000)
    if not hmac.compare_digest(digest, app.state.password_hash):
        raise HTTPException(401, 'Неверный пароль')
    token = secrets.token_urlsafe(48)
    with db() as con:
        con.execute('DELETE FROM sessions WHERE expires < ?', (time.time(),))
        con.execute('DELETE FROM attempts WHERE ip=?', (ip,))
        con.execute('INSERT INTO sessions VALUES (?, ?)', (hashlib.sha256(token.encode()).hexdigest(), time.time() + 43200))
    response.set_cookie('invite_admin', token, httponly=True, secure=COOKIE_SECURE, samesite='strict', max_age=43200, path='/api/admin')
    return {'ok': True}

@app.post('/api/admin/logout', dependencies=[Depends(admin)])
def logout(request: Request, response: Response):
    with db() as con:
        con.execute('DELETE FROM sessions WHERE token=?', (hashlib.sha256(request.cookies.get('invite_admin', '').encode()).hexdigest(),))
    response.delete_cookie('invite_admin', path='/api/admin')
    return {'ok': True}

@app.get('/api/admin/settings', dependencies=[Depends(admin)])
def get_settings():
    return settings()

@app.put('/api/admin/settings', dependencies=[Depends(admin)])
def save_settings(body: Settings):
    with db() as con:
        con.execute('UPDATE settings SET value=? WHERE id=1', (body.model_dump_json(),))
    return body

@app.get('/api/admin/invitations', dependencies=[Depends(admin)])
def invitations():
    with db() as con:
        return [json.loads(row['value']) for row in con.execute('SELECT value FROM invitations ORDER BY created DESC LIMIT 200')]

@app.post('/api/invitations')
def create_invitation(body: Booking):
    with db() as con:
        existing = con.execute('SELECT value FROM invitations WHERE id=?', (str(body.id),)).fetchone()
        if existing:
            return json.loads(existing['value'])
        cfg = json.loads(con.execute('SELECT value FROM settings WHERE id=1').fetchone()['value'])
        activity = next((a for a in cfg['activities'] if a['id'] == body.activity_id), None)
        if not activity:
            raise HTTPException(422, 'Занятие изменилось. Обновите страницу и выберите снова.')
        try:
            selected = datetime.fromisoformat(f'{body.date}T{body.time}').replace(tzinfo=TIMEZONE)
        except ValueError:
            raise HTTPException(422, 'Некорректная дата')
        if selected <= datetime.now(TIMEZONE):
            raise HTTPException(422, 'Выберите будущую дату и время')
        result = {'id': str(body.id), 'recipient': cfg['recipient'], 'title': cfg['final_title'], 'text': cfg['final_text'], 'activity': activity, 'date': body.date, 'time': body.time, 'timezone': str(TIMEZONE)}
        con.execute('INSERT INTO invitations VALUES (?, ?, ?)', (str(body.id), json.dumps(result, ensure_ascii=False), datetime.now(TIMEZONE).isoformat()))
    return result

if (FRONTEND / 'assets').is_dir():
    app.mount('/assets', StaticFiles(directory=FRONTEND / 'assets'), name='assets')

@app.get('/{path:path}', include_in_schema=False)
def spa(path: str):
    if path.startswith('api/'):
        raise HTTPException(404, 'Не найдено')
    if not (FRONTEND / 'index.html').is_file():
        raise HTTPException(503, 'Сначала соберите frontend: npm run build')
    return FileResponse(FRONTEND / 'index.html')
