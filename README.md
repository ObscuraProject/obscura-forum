# 🌑 Obscura Forum NO-JS Script

**A fully functional, zero-JavaScript forum system with proof of work gateway and comprehensive role management.**

Built specifically for communities where users have JavaScript completely disabled. Features Reddit-like sub-forums (Sub-Scuras), 8-tier role system, administrative tools, and optional proof of work gateway for spam protection—all without requiring any client-side JavaScript.

---

## ✨ Features

### Core Functionality
- ✅ **Zero JavaScript Required** - 100% functional with JavaScript disabled
- ✅ **User Authentication** - Secure registration, login, and session management
- ✅ **Sub-Scuras (Sub-Forums)** - Reddit-inspired community-created forums
- ✅ **Topics & Discussions** - Create topics, post replies, threaded conversations
- ✅ **User Profiles** - View statistics, edit bio, change password
- ✅ **Dark Theme** - Beautiful dark UI with gold accents
- ✅ **Mobile Responsive** - Works on all devices and screen sizes

### Role-Based Access Control (8 Roles)
| Role | Icon | Description |
|------|------|-------------|
| **Admin** | 👑 Admin | Full system control, user management, moderation |
| **Staff** | 🛡️ Staff | Forum moderators with special privileges |
| **Verified Vendor** | ✅ Vendor | Trusted marketplace vendors |
| **Standard Vendor** | 🏪 Vendor | Regular marketplace vendors |
| **Verified User** | ✔️ Verified | Verified community members |
| **Standard User** | 👤 | Regular forum users (default) |
| **Verified Developer** | 💻 Dev | Verified developers |
| **Standard Developer** | ⌨️ Dev | Regular developers |

### Administrative Features
- 👤 **User Management** - Assign roles, enable/disable accounts
- 🗑️ **Content Moderation** - Delete posts, pin topics
- 📊 **Statistics Dashboard** - View user and topic counts
- 🔐 **Role Assignment** - Promote users to different roles
- 📝 **Activity Monitoring** - Track forum activity

### Security Features
- 🔒 **Proof of Work Gateway** (Optional) - SHA256-based challenge to prevent spam
- 🛡️ **Password Hashing** - Werkzeug security with bcrypt
- 🔑 **Session Management** - Secure Flask sessions
- 🚫 **SQL Injection Protection** - Parameterized queries
- ✅ **Input Validation** - Server-side form validation

---

## 📋 Requirements

- **Python 3.8+**
- **pip** (Python package manager)
- **SQLite3** (included with Python)
- **2GB RAM** (minimum)
- **500MB disk space**

---

## 🚀 Quick Start

### 1. Clone or Download
```bash
git clone https://github.com/yourusername/obscura-forum-nojs.git
cd obscura-forum-nojs
```

### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Secret Key
Edit `app.py` and change the secret key:
```python
app.secret_key = 'your-secure-random-key-here'
```

Generate a secure key:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 5. Run the Forum
```bash
python3 app.py
```

The forum will be available at: **http://localhost:5000**

---

## 📁 Project Structure

```
obscura-forum-nojs/
├── app.py                          # Main Flask application
├── requirements.txt                # Python dependencies
├── README.md                       # This file
├── INSTALL.md                      # Detailed installation guide
├── ADMIN.md                        # Administrator guide
├── POW_GUIDE.md                    # Proof of work documentation
├── forum.db                        # SQLite database (auto-created)
├── templates/                      # HTML templates (11 files)
│   ├── base.html                  # Base template
│   ├── index.html                 # Home page
│   ├── login.html                 # Login form
│   ├── register.html              # Registration form
│   ├── create_subscura.html       # Create Sub-Scura
│   ├── subscura_detail.html       # View Sub-Scura
│   ├── create_topic.html          # Create topic
│   ├── topic_detail.html          # View topic
│   ├── user_profile.html          # User profile
│   ├── edit_profile.html          # Edit profile
│   ├── admin_panel.html           # Admin panel
│   └── pow_gateway.html           # PoW gateway (optional)
├── static/                         # Static files
│   └── style.css                  # Stylesheet
└── pow_solver.py                   # PoW solver tool (optional)
```

---

## 🎯 First-Time Setup

### Create Admin Account

**Option 1: Via Database**
```bash
# 1. Register a user via web interface
# 2. Then make them admin:
sqlite3 forum.db
UPDATE users SET role = 'admin' WHERE username = 'your_username';
.quit
```

**Option 2: Direct Database Insert**
```bash
sqlite3 forum.db
INSERT INTO users (username, email, password, role) 
VALUES ('admin', 'admin@example.com', 'hashed_password', 'admin');
# Note: Password must be hashed - use registration form instead
```

---

## 🔧 Configuration

### Database Settings
The forum uses SQLite by default. The database file `forum.db` is automatically created on first run.

### Proof of Work Gateway (Optional)
To enable the PoW gateway, use `app_with_pow.py` instead:
```bash
cp app_with_pow.py app.py
```

Configure difficulty in `app.py`:
```python
POW_DIFFICULTY = 4  # Recommended: 3-5
POW_EXPIRY = 3600   # 1 hour
```

See `POW_GUIDE.md` for full documentation.

### Customize Theme
Edit `static/style.css` to change colors:
```css
:root {
    --primary-color: #1a1a2e;      /* Dark background */
    --secondary-color: #16213e;    /* Card background */
    --accent-color: #0f3460;       /* Accent color */
    --gold-color: #d4af37;         /* Highlights */
    --text-light: #eaeaea;         /* Light text */
}
```

---

## 📖 Usage Guide

### For Users

**Registration**
1. Click "Register" on home page
2. Enter username, email, and password
3. Log in with credentials

**Creating a Sub-Scura**
1. Log in to your account
2. Click "Create New Sub-Scura"
3. Enter name and description
4. Access at `s/yourname`

**Creating Topics**
1. Navigate to a Sub-Scura
2. Click "Create New Topic"
3. Enter title and content
4. Topic is now live

**Posting Replies**
1. Open a topic
2. Scroll to reply form
3. Enter your reply
4. Click "Post Reply"

### For Administrators

**Accessing Admin Panel**
1. Log in as admin
2. Click "Admin Panel" in navigation
3. Manage users and content

**Assigning Roles**
1. Go to Admin Panel → User Management
2. Select role from dropdown
3. Click "Update Role"

**Disabling Accounts**
1. Go to User Management table
2. Click "Disable" next to user
3. User cannot log in

See `ADMIN.md` for complete administrative guide.

---

## 🛡️ Security Best Practices

### For Production Deployment

1. **Change Secret Key** (CRITICAL)
   ```python
   app.secret_key = secrets.token_hex(32)
   ```

2. **Use HTTPS**
   - Install SSL certificate (Let's Encrypt recommended)
   - Configure Nginx reverse proxy

3. **Set Debug to False**
   ```python
   app.run(debug=False)
   ```

4. **Regular Backups**
   ```bash
   cp forum.db forum.db.backup.$(date +%Y%m%d)
   ```

5. **Update Dependencies**
   ```bash
   pip install --upgrade -r requirements.txt
   ```

6. **Enable PoW Gateway**
   - Helps prevent spam and automated abuse
   - See `POW_GUIDE.md`

---

## 🚀 Production Deployment

### Using Gunicorn

```bash
pip install gunicorn
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
    }
}
```

Enable and restart:
```bash
sudo ln -s /etc/nginx/sites-available/obscura-forum /etc/nginx/sites-enabled/
sudo systemctl restart nginx
```

### Enable HTTPS
```bash
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

See `INSTALL.md` for detailed production setup.

---

## 📊 Database Schema

### Main Tables

**users** - User accounts and authentication
```sql
id, username, email, password, role, created_at, is_active, bio
```

**subscuras** - Sub-forums (Sub-Scuras)
```sql
id, name, description, creator_id, created_at, members_count
```

**topics** - Discussion topics
```sql
id, title, content, author_id, subscura_id, created_at, views, is_pinned
```

**posts** - Replies to topics
```sql
id, content, author_id, topic_id, created_at, updated_at
```

**pow_challenges** - Proof of work tracking (optional)
```sql
id, challenge_token, difficulty, created_at, completed_at, is_completed
```

---

## 🔍 API Routes

### Public Routes
- `GET /` - Home page (list Sub-Scuras)
- `GET /pow` - Proof of work gateway (if enabled)
- `GET/POST /register` - User registration
- `GET/POST /login` - User login

### Authenticated Routes
- `GET /subscura/<id>` - View Sub-Scura
- `GET/POST /subscura/new` - Create Sub-Scura
- `GET /topic/<id>` - View topic
- `GET/POST /topic/new/<subscura_id>` - Create topic
- `POST /post/<topic_id>` - Create reply
- `GET /user/<id>` - View user profile
- `GET/POST /user/<id>/edit` - Edit profile
- `GET /logout` - Logout

### Admin Routes
- `GET /admin` - Admin panel
- `POST /admin/user/<id>/role` - Update user role
- `POST /admin/user/<id>/toggle` - Enable/disable user
- `POST /admin/post/<id>/delete` - Delete post

---

## 🛠️ Troubleshooting

### Forum Won't Start
```bash
# Check Python version
python3 --version  # Should be 3.8+

# Verify dependencies
pip install -r requirements.txt

# Check port availability
lsof -i :5000  # Kill any process using port 5000
```

### Database Errors
```bash
# Reset database (WARNING: deletes all data)
rm forum.db
python3 app.py

# Check database integrity
sqlite3 forum.db "PRAGMA integrity_check;"
```

### Templates Not Found
```bash
# Verify templates directory exists
ls templates/

# Check all required templates are present
ls templates/*.html
```

### CSS Not Loading
```bash
# Verify static directory
ls static/style.css

# Clear browser cache
# Ctrl+Shift+Delete (Chrome/Firefox)
```

---

## 📚 Documentation

- **README.md** - This file (quick start and overview)
- **INSTALL.md** - Detailed installation and deployment guide
- **ADMIN.md** - Complete administrator guide
- **POW_GUIDE.md** - Proof of work documentation
- **POW_IMPLEMENTATION.md** - PoW implementation details

---

## 🧪 Testing

### Quick Test Checklist

- [ ] Forum starts without errors
- [ ] Home page loads
- [ ] User can register
- [ ] User can login
- [ ] User can create Sub-Scura
- [ ] User can create topic
- [ ] User can post reply
- [ ] Admin panel accessible
- [ ] Role assignment works
- [ ] User profile displays correctly

### Load Testing
```bash
# Using Apache Bench
ab -n 100 -c 10 http://localhost:5000/

# Using wrk
wrk -t12 -c400 -d30s http://localhost:5000/
```

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Coding Standards
- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add comments for complex logic
- Test thoroughly before submitting
- **Zero JavaScript dependencies** - All features must work without JS

---

## 📝 License

This project is provided as-is for the Obscura community.

---

## 🙏 Credits

Built with ❤️ for the Obscura community.

**Technologies Used:**
- Python 3.8+
- Flask 2.3.2
- SQLite3
- Werkzeug 2.3.6
- Zero JavaScript (by design)

---

## 📞 Support

### Getting Help
1. Check documentation files (INSTALL.md, ADMIN.md, POW_GUIDE.md)
2. Review troubleshooting section above
3. Check database integrity
4. Review server logs

### Reporting Issues
When reporting issues, please include:
- Python version
- Operating system
- Error messages (full traceback)
- Steps to reproduce
- Expected vs actual behavior

---

## 🗺️ Roadmap

Future enhancements being considered:
- [ ] Direct messaging between users
- [ ] Image upload support (still no-JS)
- [ ] Text formatting for posts (server-side)
- [ ] Search functionality
- [ ] RSS feeds for Sub-Scuras
- [ ] Email notifications
- [ ] Multi-language support
- [ ] Theme customization UI

---

## ⚡ Performance

### Expected Performance
- **Concurrent Users**: 100-1000 (single server)
- **Page Load**: < 200ms (local)
- **Database Queries**: < 50ms average
- **Memory Usage**: ~100MB (typical)

### Scaling Options
- Use Gunicorn with multiple workers
- Add Nginx caching
- Migrate to PostgreSQL for > 10,000 users
- Use CDN for static files
- Implement Redis for sessions

---

## 🔐 Security Features

- ✅ Password hashing (Werkzeug + bcrypt)
- ✅ Session-based authentication
- ✅ SQL injection protection (parameterized queries)
- ✅ CSRF protection (Flask built-in)
- ✅ Input validation (server-side)
- ✅ Optional proof of work gateway
- ✅ IP tracking and logging
- ✅ Role-based access control
- ✅ No client-side code execution (zero JS)

---

## 📦 Version History

### Version 1.0.0 (Current)
- Initial release
- Core forum functionality
- 8-tier role system
- Admin panel
- Proof of work gateway (optional)
- Complete documentation
- Production-ready
- Zero JavaScript requirement

---

## 🌟 Why No JavaScript?

**Obscura Forum NO-JS Script** is designed for communities that prioritize:

### Privacy & Security
- No client-side tracking or analytics
- No third-party JavaScript libraries
- Reduced attack surface (no XSS via JS)
- User browsing patterns not tracked

### Accessibility
- Works with text-only browsers (Lynx, Links)
- Screen readers have full access
- No JavaScript-only functionality barriers
- Works on ancient hardware

### Performance
- Faster page loads (no JS parsing/execution)
- Lower bandwidth usage
- Works on slow connections
- Minimal battery drain on mobile

### User Control
- Users maintain full control of their browsers
- No forced client-side execution
- Works with NoScript/uMatrix extensions
- Compatible with Tor Browser strict mode

---

## 🎯 Design Philosophy

The Obscura Forum NO-JS Script follows these principles:

1. **Server-Side First** - All logic runs on the server
2. **Progressive Enhancement** - Base functionality requires nothing
3. **Standards Compliance** - Pure HTML forms and HTTP methods
4. **Accessibility** - WCAG 2.1 Level AA compliance
5. **Security** - Defense in depth without relying on client-side validation
6. **Privacy** - No tracking, no analytics, no external resources
7. **Performance** - Optimized for speed without JavaScript overhead

---

## 🌐 Browser Compatibility

**Works perfectly on:**
- ✅ All modern browsers (with or without JavaScript)
- ✅ Text-only browsers (Lynx, Links, w3m)
- ✅ Legacy browsers (IE 6+, Opera Mini)
- ✅ Terminal-based browsers
- ✅ Screen readers
- ✅ Tor Browser (strict mode)

**Does NOT require:**
- ❌ JavaScript
- ❌ Cookies (except for session)
- ❌ Local storage
- ❌ WebSockets
- ❌ AJAX/Fetch
- ❌ Any client-side framework

---

## 🔒 Proof of Work Gateway

The optional PoW gateway provides spam protection without JavaScript:

**How it works:**
1. User visits forum
2. Server generates SHA256 challenge
3. User solves challenge (using provided script or manual computation)
4. Server verifies solution
5. User granted 1-hour access

**Benefits:**
- Prevents automated spam
- No CAPTCHA required
- No third-party services
- No visual challenge
- Privacy-preserving

See `POW_GUIDE.md` for complete documentation.

---

## 💬 Community

Join the Obscura Forum NO-JS community:
- Share your deployments
- Report issues and bugs
- Suggest new features
- Contribute code
- Help other users

---

## 🎓 Learning Resources

New to no-JS web development?
- [Progressive Enhancement Basics](https://developer.mozilla.org/docs)
- [HTML Forms](https://developer.mozilla.org/en-US/docs/Learn/Forms)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [SQLite Tutorial](https://www.sqlitetutorial.net/)

---

## 🏆 Acknowledgments

Special thanks to:
- Flask framework team
- SQLite project
- Python community
- Obscura community
- Everyone who believes in the no-JS web

---

**🌑 Obscura Forum NO-JS Script** - A decentralized forum for knowledge sharing.

Built exclusively for communities with JavaScript disabled.

**No JavaScript. No Tracking. No Compromise.**
