# Prestimos Obscura Forum - Installation Guide

## System Requirements

- **Python 3.8+**
- **pip** (Python package manager)
- **SQLite3** (usually included with Python)
- **Linux, macOS, or Windows** (any operating system that supports Python)

## Step 1: Extract and Navigate

```bash
tar -xzf prestimos-obscura-forum.tar.gz
cd prestimos-obscura-forum
```

## Step 2: Create Virtual Environment (Recommended)

```bash
# On Linux/macOS
python3 -m venv venv
source venv/bin/activate

# On Windows
python -m venv venv
venv\Scripts\activate
```

## Step 3: Install Dependencies

Create a `requirements.txt` file with the following content:

```
Flask==2.3.2
Werkzeug==2.3.6
```

Then install:

```bash
pip install -r requirements.txt
```

## Step 4: Set Directory Structure

Ensure the following directory structure:

```
prestimos-obscura-forum/
├── app.py                 (main application)
├── requirements.txt       (dependencies)
├── templates/             (HTML templates)
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── create_subscura.html
│   ├── subscura_detail.html
│   ├── create_topic.html
│   ├── topic_detail.html
│   ├── user_profile.html
│   └── admin_panel.html
└── static/                (CSS and assets)
    └── style.css
```

## Step 5: Initialize Database

The database will be automatically initialized when the application first runs. No manual setup is needed.

## Step 6: Change Secret Key (Important for Production!)

Edit `app.py` and change the secret key:

```python
app.secret_key = 'your-secret-key-change-this-in-production'
```

Replace with a secure, random string. For example:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

## Step 7: Run the Application

```bash
python3 app.py
```

The forum will be available at: `http://localhost:5000`

## Step 8: Create an Admin Account

1. Navigate to the registration page
2. Create a new account
3. Use the admin panel to change your role to "admin"
4. Or directly modify the database using:

```bash
sqlite3 forum.db
UPDATE users SET role = 'admin' WHERE username = 'your_username';
```

## Configuration for Production

### Using Gunicorn (Recommended for Production)

Install Gunicorn:

```bash
pip install gunicorn
```

Run with Gunicorn:

```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Using Nginx as Reverse Proxy

Create `/etc/nginx/sites-available/obscura-forum`:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/obscura-forum /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Enable HTTPS with Let's Encrypt

```bash
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

## Backup and Maintenance

### Database Backup

```bash
# Create a backup
cp forum.db forum.db.backup

# Or use SQLite backup command
sqlite3 forum.db ".backup forum.db.backup"
```

### Clean Old Sessions

The forum automatically manages user sessions through Flask's session mechanism. No manual cleanup is needed, but for long-running instances, consider implementing session cleanup.

## Troubleshooting

### "Address already in use" Error

Change the port in `app.py`:

```python
if __name__ == '__main__':
    init_db()
    app.run(debug=False, port=8000)  # Changed from 5000
```

### Database Lock Issues

Ensure only one instance of the application is running. SQLite has single-writer limitations.

### Templates Not Found

Ensure the `templates/` directory is in the same location as `app.py` and contains all HTML files.

### Static Files Not Loading

Ensure the `static/` directory exists with the CSS file at `static/style.css`.

## Next Steps

- See `ADMIN_GUIDE.md` for administrative procedures
- Configure user roles and permissions
- Set up automated backups
- Monitor forum activity and moderation