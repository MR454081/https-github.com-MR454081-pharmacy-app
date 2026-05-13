import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.path.join("database", "pharmacy.db")


SAMPLE_MEDICINES = [
    ("Paracetamol 500mg", "Pain Relief", "Fast relief from fever and mild pain.", 45.0, 120, 0, ""),
    ("Amoxicillin 250mg", "Antibiotic", "Antibiotic for bacterial infections.", 140.0, 80, 1, ""),
    ("Cetirizine 10mg", "Allergy", "Relieves sneezing and allergic symptoms.", 55.0, 100, 0, ""),
    ("Vitamin C Tablets", "Supplements", "Daily immunity support supplement.", 199.0, 70, 0, ""),
    ("Insulin Pen", "Diabetes", "For blood sugar management.", 699.0, 35, 1, ""),
    ("Omeprazole 20mg", "Digestive", "Acidity and reflux management.", 110.0, 90, 0, ""),
    ("Aspirin 75mg", "Cardiac", "Blood thinning support medicine.", 85.0, 75, 1, ""),
    ("Cough Syrup", "Cold & Flu", "Relief from dry and wet cough.", 130.0, 110, 0, ""),
    ("Ibuprofen 400mg", "Pain Relief", "Anti-inflammatory pain relief.", 95.0, 95, 0, ""),
    ("Metformin 500mg", "Diabetes", "Type-2 diabetes management medicine.", 160.0, 85, 1, ""),
    ("ORS Sachets", "Hydration", "Electrolyte support for dehydration.", 60.0, 150, 0, ""),
    ("Calcium + D3", "Supplements", "Bone strength nutritional support.", 240.0, 65, 0, ""),
]


def init_db() -> None:
    os.makedirs("database", exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.executescript(
        """
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            phone TEXT,
            address TEXT,
            is_admin INTEGER NOT NULL DEFAULT 0,
            wallet_balance REAL NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS medicines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            stock INTEGER NOT NULL DEFAULT 0,
            prescription_required INTEGER NOT NULL DEFAULT 0,
            image_filename TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            total_amount REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            payment_provider TEXT,
            payment_reference TEXT,
            payment_status TEXT DEFAULT 'Pending',
            shipping_address TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            medicine_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id),
            FOREIGN KEY (medicine_id) REFERENCES medicines(id)
        );

        CREATE TABLE IF NOT EXISTS prescriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            file_name TEXT NOT NULL,
            original_name TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS user_cart_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            medicine_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, medicine_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (medicine_id) REFERENCES medicines(id)
        );

        CREATE TABLE IF NOT EXISTS wallet_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            txn_type TEXT NOT NULL,
            note TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """
    )

    admin_email = "admin@pharmacy.com"
    cursor.execute("SELECT id FROM users WHERE email = ?", (admin_email,))
    if cursor.fetchone() is None:
        from werkzeug.security import generate_password_hash

        cursor.execute(
            """
            INSERT INTO users (name, email, password_hash, phone, address, is_admin, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "System Admin",
                admin_email,
                generate_password_hash("admin123"),
                "0000000000",
                "Admin Office",
                1,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    cursor.execute("SELECT COUNT(*) FROM medicines")
    if cursor.fetchone()[0] == 0:
        now = datetime.now(timezone.utc).isoformat()
        cursor.executemany(
            """
            INSERT INTO medicines
                (name, category, description, price, stock, prescription_required, image_filename, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [(m[0], m[1], m[2], m[3], m[4], m[5], m[6], now) for m in SAMPLE_MEDICINES],
        )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized at database/pharmacy.db")
