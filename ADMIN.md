# Prestimos Obscura Forum - Administrator Guide

## Overview

This guide provides comprehensive information for managing and administering the Prestimos Obscura Forum. As an administrator, you have full control over user roles, content moderation, and forum settings.

## Accessing the Admin Panel

1. Log in with an admin account
2. Navigate to `http://your-forum-domain/admin`
3. You will see the Admin Panel dashboard

**Note:** Only users with the `admin` role can access this panel.

## User Role System

The forum implements 8 different user roles, each with specific permissions and displayed with unique icons:

### Role List

| Role | Icon | Description |
|------|------|-------------|
| **Admin** | 👑 Admin | Full forum control, user management, content moderation |
| **Staff** | 🛡️ Staff | Moderators with special privileges, can moderate content |
| **Verified Vendor** | ✅ Vendor | Trusted vendors with special marketplace badges |
| **Standard Vendor** | 🏪 Vendor | Regular vendors in the marketplace |
| **Verified User** | ✔️ Verified | Verified community members with trust indicators |
| **Standard User** | 👤 | Regular forum users |
| **Verified Developer** | 💻 Dev | Verified developers with special project badges |
| **Standard Developer** | ⌨️ Dev | Regular developers posting in tech forums |

## Managing Users

### Assigning User Roles

1. Go to **Admin Panel** → **User Management**
2. Find the user you want to modify in the users table
3. Select their new role from the dropdown menu:
   - Admin
   - Staff
   - Verified Vendor
   - Standard Vendor
   - Verified User
   - Standard User
   - Verified Developer
   - Standard Developer
4. Click **Update Role**
5. Confirmation message will appear

### Enabling/Disabling User Accounts

To disable a user account (prevents login and forum access):

1. Go to **User Management** table
2. Locate the user in the "Status" column
3. Click the **Disable** button (or **Enable** for already-disabled accounts)
4. The user's account status will be toggled

**When to disable accounts:**
- Spam/abuse violations
- Payment disputes for vendors
- Terms of service violations
- Temporary suspension for rule violations

### Viewing User Information

To view a user's profile:

1. Click on the username link in the User Management table
2. View their statistics:
   - Account creation date
   - Number of topics created
   - Number of posts made
   - Account status

## Content Moderation

### Viewing Topics

1. Go to **Admin Panel** → **Recent Topics**
2. Review recent forum topics
3. Click **View** to see the full topic and all replies

### Deleting Posts

1. Open the topic containing the inappropriate post
2. Locate the post in the replies section
3. Click **Delete** (available to admins only)
4. The post will be permanently removed

### Pinning Topics

To pin important topics to the top of a Sub-Scura:

1. Open the topic you want to pin
2. Click **Pin Topic** (admin-only option)
3. The topic will appear at the top of the Sub-Scura marked with 📌

## Sub-Scura Management

### Overview

Sub-Scuras are community-managed forums similar to Reddit subreddits. They can be created by any logged-in user.

### Moderating Sub-Scuras

1. Visit the Sub-Scura you want to moderate
2. As an admin, you can:
   - View all topics and threads
   - Delete inappropriate posts
   - Pin important discussions
   - Manage Sub-Scura membership

### Managing Sub-Scura Growth

Monitor Sub-Scura statistics:
- Member count
- Topic creation rate
- Activity levels

Consider promoting active Sub-Scuras or encouraging growth in important communities.

## Security Best Practices

### Change the Secret Key

When first setting up the forum, change the Flask secret key:

```python
# In app.py
app.secret_key = 'your-new-secret-key-here'
```

Use a cryptographically secure random string:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Database Backups

Regularly backup your forum database:

```bash
# Daily backup script
cp forum.db forum.db.backup.$(date +%Y%m%d)

# Keep last 30 days of backups
find . -name "forum.db.backup.*" -mtime +30 -delete
```

### Monitor Admin Actions

Keep records of admin actions:
- User role changes
- Post deletions
- Account suspensions

Consider implementing logging to track these actions.

### Password Security

- Encourage users to use strong passwords
- Implement password requirements if needed
- Passwords are hashed using Werkzeug security

## Handling User Reports

### Common Issues to Address

1. **Spam Posts** → Delete and warn user
2. **Abusive Content** → Delete and disable account if severe
3. **Duplicate Content** → Delete duplicates, keep original
4. **Off-Topic Posts** → Move or delete depending on context
5. **Commercial Spam** → Delete and consider disabling account

### Warning System

Before disabling an account:

1. Delete violating content
2. Note the violation in your records
3. Consider temporary suspension first
4. Only permanently disable after repeated violations

## Database Management

### Direct Database Access

For advanced management tasks:

```bash
sqlite3 forum.db

# View all users
SELECT id, username, email, role, is_active, created_at FROM users;

# Update user role directly
UPDATE users SET role = 'verified_user' WHERE username = 'target_user';

# View statistics
SELECT COUNT(*) as total_users FROM users;
SELECT COUNT(*) as total_topics FROM topics;
SELECT COUNT(*) as total_posts FROM posts;
```

### Database Integrity

Regularly check database integrity:

```bash
sqlite3 forum.db "PRAGMA integrity_check;"
```

## Performance Monitoring

### Identifying Slow Queries

Monitor these areas:
- Topic view counts (should be indexed)
- User post counts (aggregate them)
- Sub-Scura member counts (cache them)

### Optimization Tips

1. Use database indexing on frequently queried columns
2. Cache Sub-Scura statistics
3. Archive old posts after a certain period
4. Clean up inactive user sessions

## Scaling the Forum

### For Growing Communities

1. **Add Staff Members:**
   - Promote trusted users to Staff role
   - Distribute moderation responsibilities
   - Create a moderation team

2. **Create Sub-Scuras:**
   - Encourage community members to create topic-specific forums
   - This organizes content and engages users

3. **Upgrade Server:**
   - Monitor CPU and memory usage
   - Upgrade hosting if needed
   - Use a production server (Gunicorn + Nginx)

### Migrating to Production Server

Use Gunicorn for production:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

Set up Nginx as reverse proxy (see INSTALL.md for details).

## Emergency Procedures

### If the Forum Goes Down

1. Check if the application is running: `ps aux | grep python`
2. Check database file: `ls -la forum.db`
3. Review error logs
4. Restart the application: `python3 app.py`

### Database Corruption

If you suspect database corruption:

```bash
# Backup corrupted database
cp forum.db forum.db.corrupted

# Restore from backup
cp forum.db.backup forum.db

# Verify integrity
sqlite3 forum.db "PRAGMA integrity_check;"
```

### Mass User Ban

To disable multiple accounts:

```bash
sqlite3 forum.db
UPDATE users SET is_active = 0 WHERE id IN (123, 456, 789);
```

## Role Icon Customization

To customize role icons, edit the `get_role_icon()` function in `app.py`:

```python
def get_role_icon(role):
    """Return icon HTML for user role"""
    icons = {
        'admin': '👑 Admin',           # Gold crown for admins
        'staff': '🛡️ Staff',          # Shield for staff
        'verified_vendor': '✅ Vendor',
        'standard_vendor': '🏪 Vendor',
        'verified_user': '✔️ Verified',
        'standard_user': '👤',
        'verified_developer': '💻 Dev',
        'standard_developer': '⌨️ Dev'
    }
    return icons.get(role, '👤')
```

## Contacting Support

For technical issues:
1. Check this guide thoroughly
2. Review error logs
3. Verify system requirements are met
4. Check database backups

## Regular Maintenance Schedule

### Daily
- Monitor new posts and spam
- Check admin panel for alerts
- Review user complaints

### Weekly
- Backup database
- Review user statistics
- Check server performance

### Monthly
- Full forum audit
- Security review
- Performance optimization
- User role review

## Conclusion

As an administrator, you have significant responsibility for maintaining a healthy, secure forum community. Use these tools wisely and always prioritize user safety and community standards.