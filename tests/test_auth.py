def test_register_user(client):
    response = client.post('/register', json={
        'email': 'lokibusss@gmail.com',
        'password': '8458076100'
    })
    assert response.status_code in (201, 409)  # user may already exist
    assert 'message' in response.get_json() or 'error' in response.get_json()

def test_invalid_email_register(client):
    response = client.post('/register', json={
        'email': 'bad-email',
        'password': '12345678'
    })
    assert response.status_code == 400
    assert 'Invalid email format' in response.get_data(as_text=True)
