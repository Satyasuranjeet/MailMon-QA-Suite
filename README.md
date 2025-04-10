# 📧 Flask Email API Service with Authentication, Admin Panel & Automated Testing

A secure and feature-rich Flask-based API that enables user registration, email verification, API key generation, and sending emails. Admins can monitor API usage, set rate limits, and block/unblock users. Fully tested using PyTest and ready for CI/CD integration.

---

## 🚀 Features

- ✅ User registration with email & password
- ✅ Email verification via SMTP
- ✅ JWT-based authentication
- ✅ Secure API key generation per user
- ✅ Send emails using generated API keys
- ✅ Track email API usage per user
- ✅ Admin panel to:
  - View all users
  - Enable/disable API access
  - Set custom rate limits
- ✅ Unit & API testing using PyTest
- ✅ GitHub Actions CI/CD pipeline ready

---

## 🔧 Technologies Used

- **Framework:** Flask
- **Database:** MongoDB (via PyMongo)
- **Authentication:** JWT (Flask-JWT-Extended), Bcrypt
- **Email Service:** SMTP, MIME
- **Testing:** PyTest, Postman, Selenium (optional)
- **Dev Tools:** dotenv, CORS, GitHub Actions

---

## 🗃️ Project Structure

```
.
├── app.py
├── requirements.txt
├── .env
├── tests/
│   ├── __init__.py
│   ├── test_auth.py
│   ├── test_email_api.py
│   ├── test_admin_api.py
├── .github/
│   └── workflows/
│       └── test.yml
└── README.md
```

---

## 🔐 Environment Variables

Create a `.env` file in your root directory with:

```
MONGO_URI=mongodb+srv://<user>:<pass>@cluster.mongodb.net/db
JWT_SECRET_KEY=your_jwt_secret
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SENDER_EMAIL=youremail@example.com
SENDER_PASSWORD=yourpassword
```

---

## 📬 Sample Email API Usage

**Endpoint:** `POST /send-email`  
**Header:** `apikey: your_api_key`  
**Body:**
```json
{
  "receiver_email": "recipient@example.com",
  "subject": "Hello",
  "message": "This is a test message"
}
```

---

## 🧪 Run Tests

```bash
# Run all unit tests
pytest tests/
```

> Tests include:
- User registration & login
- Email verification
- API key handling
- Admin endpoints
- Mocked email sending

---

## ⚙️ CI/CD Pipeline

Your GitHub Actions workflow will:
- ✅ Install dependencies
- ✅ Run PyTest
- ✅ Run Newman (if Postman tests added)

---

## 👤 Admin Endpoints

| Endpoint               | Method | Description                 |
|------------------------|--------|-----------------------------|
| `/admin/users`         | GET    | View all registered users   |
| `/admin/disable-user`  | POST   | Disable user’s API access   |
| `/admin/enable-user`   | POST   | Re-enable user’s API access |
| `/admin/set-user-limit`| POST   | Set custom rate limit       |

---

## 📌 Future Plans

- Swagger/OpenAPI docs
- Dockerization
- OTP login support
- Email logs panel

---

## ✨ Author

**Satya Suranjeet Jena**  
[GitHub](https://github.com/Satyasuranjeet) • [LinkedIn](https://linkedin.com/in/satya-suranjeet-jena-b85277222)
