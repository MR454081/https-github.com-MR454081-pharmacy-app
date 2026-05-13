# Healthcare Pharmacy System

Flask-based pharmacy web app with user and admin portals.

## Features
- User auth (register/login/logout)
- Medicine browsing, search, category filters
- Cart + checkout flow
- Prescription upload for Rx medicines
- Admin dashboard, medicine CRUD, order/user management
- JSON API for mobile/desktop app integration
- SQLite database with starter data
- Responsive Bootstrap UI for mobile and desktop

## Project Structure
```text
healthcare_pharmacy/
├── app.py
├── init_db.py
├── requirements.txt
├── README.md
├── database/
│   └── pharmacy.db
├── static/
│   ├── css/style.css
│   ├── js/main.js
│   └── uploads/
│       ├── medicines/
│       └── prescriptions/
└── templates/
    ├── base.html
    ├── index.html
    ├── login.html
    ├── register.html
    ├── medicines.html
    ├── medicine_detail.html
    ├── cart.html
    ├── checkout.html
    ├── order_success.html
    └── admin/
        ├── base.html
        ├── login.html
        ├── dashboard.html
        ├── medicines.html
        ├── add_medicine.html
        ├── edit_medicine.html
        ├── orders.html
        ├── order_detail.html
        └── users.html
```

## Run
1. `pip install -r requirements.txt`
2. `python init_db.py`
3. `python app.py`
4. Open `http://127.0.0.1:5000`

## Default Admin
- Email: `admin@pharmacy.com`
- Password: `admin123`

## API Endpoints
- `GET /api/health`
- `POST /api/auth/register` (returns JWT)
- `POST /api/auth/login` (returns JWT)
- `GET /api/auth/me`
- `GET /api/medicines?q=&category=`
- `GET /api/medicines/<id>`
- `GET /api/cart` (JWT required)
- `POST /api/cart/add` with JSON: `{"medicine_id": 1, "quantity": 2}`
- `POST /api/cart/update` with JSON: `{"medicine_id": 1, "quantity": 3}`
- `POST /api/cart/remove` with JSON: `{"medicine_id": 1}`
- `POST /api/payments/create-intent` with JSON: `{"provider":"stripe"}` or `{"provider":"razorpay"}`
- `POST /api/payments/create-stripe-checkout-session`
- `POST /api/checkout` with JSON: `{"shipping_address": "...", "payment_provider":"pay_on_delivery|wallet|stripe|razorpay", "payment_reference":"..."}` (JWT required, non-Rx cart)
- `GET /api/orders` (requires login)
- `GET /api/orders/<id>` (requires login)

JWT header format:
- `Authorization: Bearer <token>`

Payment env vars:
- Stripe: `STRIPE_SECRET_KEY`
- Razorpay: `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`
- Stripe webhook: `STRIPE_WEBHOOK_SECRET`
- Razorpay webhook: `RAZORPAY_WEBHOOK_SECRET`
- Hidden admin login path: `ADMIN_ENTRY_PATH` (default: `/secure-admin-portal-9x7`)

Webhook endpoints:
- Stripe: `POST /api/webhooks/stripe`
- Razorpay: `POST /api/webhooks/razorpay`

## Flutter App
Starter app is in `mobile_app/`.

Run:
1. `cd mobile_app`
2. `flutter pub get`
3. `flutter run`

If using Android emulator, API base URL is `http://10.0.2.2:5000` (configured in `mobile_app/lib/config.dart`).

## Render Deployment (Free)
Files added for Render:
- `Procfile`
- `render.yaml`
- `runtime.txt`

### One-time steps
1. Push this project to GitHub.
2. In Render, click `New +` -> `Web Service`.
3. Connect your GitHub repo and select this project.
4. Render should auto-detect:
   - Build: `pip install -r requirements.txt`
   - Start: `gunicorn app:app`
5. Set environment variables in Render:
   - `SECRET_KEY` (required)
   - `JWT_SECRET` (required)
   - `ADMIN_ENTRY_PATH` (optional, default `/secure-admin-portal-9x7`)
   - `UPI_ID` / `UPI_NAME` (optional)
   - `STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY` (optional for Stripe)
   - `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET` (optional for Razorpay)
   - `STRIPE_WEBHOOK_SECRET`, `RAZORPAY_WEBHOOK_SECRET` (optional for webhook validation)
6. Deploy and open your Render URL.

### Important note for free hosting
- SQLite on Render free web service is ephemeral. Data can reset on redeploy/restart.
- For persistent production data, use managed Postgres.
