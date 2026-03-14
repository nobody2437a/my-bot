from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import json, os, secrets, string

app = Flask(__name__)

ADMIN_SECRET = "BUDDY_ADMIN_2024_SECRET"
KEYS_FILE    = "keys_db.json"

# ── DB ───────────────────────────────────────────────────────
def load_db():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE) as f:
            return json.load(f)
    return {}

def save_db(db):
    with open(KEYS_FILE, 'w') as f:
        json.dump(db, f, indent=2)

def gen_key():
    chars = string.ascii_uppercase + string.digits
    return '-'.join(
        ''.join(secrets.choice(chars) for _ in range(5))
        for _ in range(4)
    )

def is_admin(req):
    return req.headers.get('X-Admin-Secret') == ADMIN_SECRET

# ── Routes ───────────────────────────────────────────────────
@app.route('/')
def home():
    return jsonify({"status": "COC Bot Server Running", "version": "1.0"})

@app.route('/verify', methods=['POST'])
def verify():
    data = request.json or {}
    key  = data.get('key', '').strip().upper()
    if not key:
        return jsonify({"valid": False, "msg": "Key required"})
    db = load_db()
    if key not in db:
        return jsonify({"valid": False, "msg": "Invalid key! Contact admin."})
    info = db[key]
    if info.get('status') == 'revoked':
        return jsonify({"valid": False, "msg": "Key revoked! Contact admin."})
    expires   = datetime.fromisoformat(info['expires'])
    now       = datetime.now()
    if now > expires:
        return jsonify({"valid": False,
                        "msg": f"Key expired! Contact admin."})
    days_left = (expires - now).days
    db[key]['last_seen'] = now.isoformat()
    save_db(db)
    return jsonify({
        "valid":     True,
        "msg":       f"Valid! {days_left} days remaining",
        "days_left": days_left,
        "label":     info.get('label', '')
    })

@app.route('/admin/create', methods=['POST'])
def create_key():
    if not is_admin(request):
        return jsonify({"ok": False, "msg": "Unauthorized"}), 401
    data    = request.json or {}
    days    = int(data.get('days', 7))
    label   = data.get('label', '')
    key     = gen_key()
    expires = datetime.now() + timedelta(days=days)
    db      = load_db()
    db[key] = {
        "expires":   expires.isoformat(),
        "label":     label,
        "status":    "active",
        "created":   datetime.now().isoformat(),
        "days":      days,
        "last_seen": None
    }
    save_db(db)
    return jsonify({
        "ok":      True,
        "key":     key,
        "expires": expires.strftime("%Y-%m-%d %H:%M"),
        "days":    days
    })

@app.route('/admin/list', methods=['GET'])
def list_keys():
    if not is_admin(request):
        return jsonify({"ok": False, "msg": "Unauthorized"}), 401
    db  = load_db()
    now = datetime.now()
    out = []
    for key, info in db.items():
        expires   = datetime.fromisoformat(info['expires'])
        days_left = (expires - now).days
        status    = info.get('status', 'active')
        if status == 'revoked':   disp = 'revoked'
        elif days_left < 0:       disp = 'expired'
        elif days_left <= 3:      disp = 'expiring'
        else:                     disp = 'active'
        out.append({
            "key":       key,
            "label":     info.get('label', ''),
            "expires":   expires.strftime("%Y-%m-%d %H:%M"),
            "days_left": days_left,
            "status":    disp,
            "last_seen": info.get('last_seen', 'Never')
        })
    out.sort(key=lambda x: x['days_left'], reverse=True)
    return jsonify({"ok": True, "keys": out, "total": len(out)})

@app.route('/admin/revoke', methods=['POST'])
def revoke():
    if not is_admin(request):
        return jsonify({"ok": False, "msg": "Unauthorized"}), 401
    key = (request.json or {}).get('key', '').upper()
    db  = load_db()
    if key not in db:
        return jsonify({"ok": False, "msg": "Key not found"})
    db[key]['status'] = 'revoked'
    save_db(db)
    return jsonify({"ok": True, "msg": f"Key {key} revoked"})

@app.route('/admin/extend', methods=['POST'])
def extend():
    if not is_admin(request):
        return jsonify({"ok": False, "msg": "Unauthorized"}), 401
    data = request.json or {}
    key  = data.get('key', '').upper()
    days = int(data.get('days', 7))
    db   = load_db()
    if key not in db:
        return jsonify({"ok": False, "msg": "Key not found"})
    expires = datetime.fromisoformat(db[key]['expires'])
    if expires < datetime.now():
        expires = datetime.now()
    db[key]['expires'] = (expires + timedelta(days=days)).isoformat()
    db[key]['status']  = 'active'
    save_db(db)
    new_exp = datetime.fromisoformat(db[key]['expires'])
    return jsonify({"ok": True, "msg": f"+{days} days added",
                    "new_expires": new_exp.strftime("%Y-%m-%d %H:%M")})

@app.route('/admin/delete', methods=['POST'])
def delete():
    if not is_admin(request):
        return jsonify({"ok": False, "msg": "Unauthorized"}), 401
    key = (request.json or {}).get('key', '').upper()
    db  = load_db()
    if key not in db:
        return jsonify({"ok": False, "msg": "Key not found"})
    del db[key]
    save_db(db)
    return jsonify({"ok": True, "msg": f"Key {key} deleted"})

@app.route('/admin/reactivate', methods=['POST'])
def reactivate():
    if not is_admin(request):
        return jsonify({"ok": False, "msg": "Unauthorized"}), 401
    key = (request.json or {}).get('key', '').upper()
    db  = load_db()
    if key not in db:
        return jsonify({"ok": False, "msg": "Key not found"})
    db[key]['status'] = 'active'
    save_db(db)
    return jsonify({"ok": True, "msg": f"Key {key} reactivated"})

# ── Run ──────────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
