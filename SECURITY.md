# 🔒 AVA Security System - DEVITO ONLY

## ⚠️ CRITICAL SECURITY NOTICE

**Owner: Devito (Only authorized user)**

This system is protected with multiple security layers. Unauthorized access attempts are logged, monitored, and blocked.

---

## 🛡️ SECURITY FEATURES

### 1. **Owner-Only Access**
- Only Devito can authenticate
- All other users are automatically blocked
- System enforces role-based access control (RBAC)

### 2. **API Key Authentication**
- Permanent admin key for Devito: `devito-master-key-001`
- All API calls require authentication header
- Invalid keys are logged as threats

### 3. **Rate Limiting**
- Max 100 requests per 60 seconds per IP
- Automatic blocking on rate limit violation
- DDoS protection enabled

### 4. **Threat Detection & Response**
- Real-time threat monitoring
- Automatic IP blocking on suspicious activity
- 24-hour lockdown for critical threats
- Detailed threat logging and reporting

### 5. **Audit Logging**
- All admin actions logged
- Timestamp and user tracking
- Cannot be bypassed or deleted

### 6. **Security Headers**
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security enabled
- Content-Security-Policy enforced

### 7. **CORS Protection**
- Only localhost allowed (localhost:3000, localhost:8000)
- External requests automatically blocked
- No wildcard origins

---

## 🔐 ADMIN CREDENTIALS

**Username:** Devito
**Password:** [CHANGE ME - See setup instructions]

---

## 📡 ADMIN API ENDPOINTS

All endpoints require API Key header: `X-API-Key: devito-master-key-001`

### Authentication
```bash
POST /api/admin/login
{
  "username": "Devito",
  "password": "your-secure-password"
}
```

### Threat Management
```bash
# Get threat report
GET /api/admin/threats
Header: X-API-Key: devito-master-key-001

# Get blocked IPs
GET /api/admin/blocked-ips
Header: X-API-Key: devito-master-key-001

# Block an IP (manual)
POST /api/admin/block-ip
Header: X-API-Key: devito-master-key-001
{
  "ip": "192.168.1.100",
  "duration_minutes": 1440
}
```

### API Key Management
```bash
# List all API keys
GET /api/admin/api-keys
Header: X-API-Key: devito-master-key-001

# Revoke an API key
POST /api/admin/api-keys/revoke?api_key_to_revoke=XXX
Header: X-API-Key: devito-master-key-001
```

### Audit Logs
```bash
# Get audit log
GET /api/admin/audit-log?limit=100
Header: X-API-Key: devito-master-key-001
```

### System Status
```bash
# Get system status
GET /api/admin/status
Header: X-API-Key: devito-master-key-001
```

---

## ⚡ SECURITY MONITORING

### Real-time Threat Detection
```python
from ava.security import threat_log

# Get current threats
report = threat_log.get_threat_report()
print(report)
# Output: {
#   'total_threats': 42,
#   'blocked_ips': 5,
#   'recent_threats': [...]
# }
```

### Blocked IPs Management
```python
# Check if IP is blocked
is_blocked = threat_log.is_ip_blocked("192.168.1.1")

# Block an IP
threat_log.block_ip("192.168.1.1", duration_minutes=1440)

# View all blocked IPs
blocked_ips = threat_log.blocked_ips
```

---

## 🚨 THREAT RESPONSE PROTOCOL

### What happens when someone tries to hack/manipulate:

1. **First Attempt**: 
   - IP is logged
   - Warning level threat recorded
   - Request is blocked

2. **Multiple Attempts**:
   - Threat level escalated to CRITICAL
   - IP automatically blocked for 24 hours
   - All access methods disabled
   - Root access revoked

3. **Escalation**:
   - System enters lockdown mode
   - All user connections terminated
   - Admin is notified immediately
   - Audit log captures full details

### Automatic Protections:
- ✅ Invalid credentials → IP blocked
- ✅ Rate limit exceeded → IP blocked
- ✅ Unauthorized API key → IP blocked
- ✅ SQL injection attempts → IP blocked
- ✅ XSS attempts → IP blocked
- ✅ CSRF attempts → IP blocked

---

## 🔑 CHANGE OWNER PASSWORD

⚠️ **IMPORTANT**: Change the default password immediately!

### Edit `/workspaces/AVA/ava/security.py`:

```python
# Line ~30
OWNER_PASSWORD_HASH = hashlib.sha256(b"YOUR_NEW_SECURE_PASSWORD").hexdigest()
```

Then restart the system:
```bash
docker-compose restart ava-ava-1
```

---

## 📊 EXAMPLE: Monitoring Dashboard

Check threats in real-time:

```bash
# Check threat status
curl -H "X-API-Key: devito-master-key-001" http://localhost:8000/api/admin/threats

# Response:
{
  "timestamp": "2026-02-14T15:05:30.123456",
  "report": {
    "total_threats": 3,
    "blocked_ips": 2,
    "recent_threats": [
      {
        "timestamp": "2026-02-14T15:05:20.123456",
        "ip": "192.168.1.100",
        "endpoint": "/api/malicious",
        "threat_level": "CRITICAL",
        "reason": "SQL injection attempt",
        "user_agent": "curl/7.64.1"
      },
      ...
    ]
  }
}
```

---

## 🛡️ DEPLOYMENT SECURITY

### When running in production:

1. **Use HTTPS only** (not HTTP)
2. **Change admin password** before deployment
3. **Rotate API keys** regularly
4. **Monitor audit logs** daily
5. **Keep dependencies updated**
6. **Run behind WAF** (Web Application Firewall)
7. **Enable rate limiting** on reverse proxy
8. **Use strong passwords** everywhere

---

## 🔄 SYSTEM HARDENING CHECKLIST

- [x] Admin-only access control
- [x] API key authentication
- [x] Rate limiting (100 req/60s)
- [x] Threat detection & logging
- [x] Automatic IP blocking
- [x] Audit trail (immutable)
- [x] Security headers
- [x] CORS restrictions
- [x] Input validation
- [x] SQL injection protection
- [x] XSS protection
- [x] CSRF protection

---

## 📞 SUPPORT

For security concerns or suspicious activity:
1. Check `/api/admin/threats` immediately
2. Review audit logs at `/api/admin/audit-log`
3. Block suspicious IPs at `/api/admin/block-ip`

---

**Status: 🔒 MAXIMUM SECURITY ENABLED**

*System protected. Only authorized user (Devito) can access.*
