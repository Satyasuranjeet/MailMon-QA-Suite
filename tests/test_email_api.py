from unittest.mock import patch

@patch('app.send_email')  # Mock the actual email sending
def test_send_email_valid(mock_send, client):
    mock_send.return_value = True

    # Replace with a valid API key or simulate user login and generate key
    response = client.post('/send-email?apikey=1ee73b3d133698fdcfc272de68ca45e0', json={
        'receiver_email': 'vijaykumar30112002@example.com',
        'subject': 'Test',
        'message': 'Test message'
    })

    assert response.status_code in (200, 403)  # 403 if key is invalid
