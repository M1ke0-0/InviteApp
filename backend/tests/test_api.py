import importlib
from datetime import datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv('DATABASE_PATH', str(tmp_path / 'test.sqlite3'))
    monkeypatch.setenv('ADMIN_PASSWORD', 'test-password-1234')
    import backend.main as main
    importlib.reload(main)
    with TestClient(main.app) as c:
        yield c


def login(client):
    return client.post('/api/admin/login', json={'password': 'test-password-1234'})


def booking(client):
    cfg = client.get('/api/config').json()
    return {'id': str(uuid4()), 'activity_id': cfg['activities'][0]['id'], 'date': (datetime.now()+timedelta(days=3)).date().isoformat(), 'time': '18:30'}


def test_admin_security_and_logout(client):
    assert client.get('/api/admin/settings').status_code == 401
    assert client.put('/api/admin/settings', json={}).status_code == 401
    assert client.get('/api/admin/invitations').status_code == 401
    assert client.post('/api/admin/login', json={'password': 'wrong'}).status_code == 401
    assert login(client).status_code == 200
    assert client.get('/api/admin/settings').status_code == 200
    assert client.post('/api/admin/logout').status_code == 200
    assert client.get('/api/admin/settings').status_code == 401


def test_complete_flow_and_saved_snapshot(client):
    login(client)
    cfg = client.get('/api/admin/settings').json()
    cfg['title'] = 'Пойдём на свидание?'
    cfg['final_text'] = 'Жду встречи!'
    cfg['activities'] = [{'id':'new', 'emoji':'🎨', 'title':'Мастер-класс', 'description':'Рисуем вместе'}]
    assert client.put('/api/admin/settings', json=cfg).status_code == 200
    assert client.get('/api/config').json()['title'] == cfg['title']
    body = booking(client)
    response = client.post('/api/invitations', json=body)
    assert response.status_code == 200
    result = response.json()
    assert result['activity']['title'] == 'Мастер-класс'
    assert result['text'] == 'Жду встречи!'
    assert result['date'] == body['date'] and result['time'] == '18:30'
    assert client.post('/api/invitations', json=body).json() == result
    assert len(client.get('/api/admin/invitations').json()) == 1
    cfg['final_text'] = 'Новый текст'
    client.put('/api/admin/settings', json=cfg)
    assert client.get('/api/admin/invitations').json()[0]['text'] == 'Жду встречи!'


def test_booking_validation(client):
    body = booking(client)
    for change in [{'activity_id':'missing'}, {'date':'2020-01-01'}, {'date':'2027-02-30'}, {'time':'25:00'}, {'id':'not-uuid'}]:
        assert client.post('/api/invitations', json={**body, **change}).status_code == 422


def test_settings_validation(client):
    login(client)
    cfg = client.get('/api/admin/settings').json()
    assert client.put('/api/admin/settings', json={**cfg, 'activities':[]}).status_code == 422
    assert client.put('/api/admin/settings', json={**cfg, 'activities':[cfg['activities'][0]]*2}).status_code == 422
    assert client.put('/api/admin/settings', json={**cfg, 'default_time':'99:00'}).status_code == 422


def test_csrf_and_proxy_host(client):
    assert client.post('/api/admin/login', json={'password':'test-password-1234'}, headers={'Origin':'https://evil.example'}).status_code == 403
    assert client.post('/api/admin/login', json={'password':'test-password-1234'}, headers={'Origin':'https://testserver'}).status_code == 200


def test_login_throttle(client):
    for _ in range(10):
        assert client.post('/api/admin/login', json={'password':'wrong'}).status_code == 401
    assert login(client).status_code == 429


def test_health_and_unknown_api(client):
    assert client.get('/api/health').json() == {'status':'ok'}
    assert client.get('/api/missing').status_code == 404
