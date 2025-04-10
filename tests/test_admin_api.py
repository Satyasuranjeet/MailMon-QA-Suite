def test_get_users_unauthorized(client):
    response = client.get('/admin/users')
    assert response.status_code == 401 or response.status_code == 422
