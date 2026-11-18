"""
Flask Web Application & REST API Endpoints Module
Scalable KDC Key Establishment Using Extended Euclidean RSA Management
Designed for Academic Demonstration - B.Tech Cyber Security Project
"""

import os
import functools
from flask import (
    Flask, render_template, request, redirect, 
    url_for, flash, session, jsonify
)

from database import (
    init_db, verify_admin_login, register_smart_meter, 
    get_meter, get_all_meters, get_audit_logs, get_db_connection
)
from kdc import HierarchicalKDC
from extended_euclid import extended_gcd, mod_inverse, gcd
from rsa import generate_rsa_keys
from simulator import run_kdc_simulation
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "kdc_rsa_secure_academic_demo_key_2026")


# ==========================================
# AUTHENTICATION DECORATOR & INITIALIZATION
# ==========================================

def login_required(f):
    """Decorator to enforce admin login session on protected routes."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.before_request
def initialize_system():
    """Ensure database schema and default records are initialized on first request."""
    if not getattr(app, '_db_initialized', False):
        init_db()
        app._db_initialized = True


# ==========================================
# WEB PAGE RENDERING ROUTES
# ==========================================

@app.route('/')
def index():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if verify_admin_login(username, password):
            session['logged_in'] = True
            session['username'] = username
            flash("Login successful. Welcome to Smart Grid KDC Console.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid administrative credentials.", "danger")

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM regions")
    total_regions = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM meters")
    total_meters = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM meters WHERE status = 'ACTIVE'")
    active_meters = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM meters WHERE status = 'REVOKED'")
    revoked_meters = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM keys")
    total_keys = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM keys WHERE status = 'ROTATED'")
    rotated_keys = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE result in ('FAILED', 'DENIED', 'ERROR')")
    failed_ops = cursor.fetchone()[0]

    conn.close()

    metrics = {
        'total_regions': total_regions,
        'total_meters': total_meters,
        'active_meters': active_meters,
        'revoked_meters': revoked_meters,
        'total_keys': total_keys,
        'rotated_keys': rotated_keys,
        'failed_ops': failed_ops
    }

    recent_logs = get_audit_logs(limit=8)
    return render_template('dashboard.html', metrics=metrics, logs=recent_logs)


@app.route('/meters')
@login_required
def meters():
    all_meters = get_all_meters()
    return render_template('meters.html', meters=all_meters)


@app.route('/register_meter', methods=['GET', 'POST'])
@login_required
def register_meter_page():
    if request.method == 'POST':
        meter_id = request.form.get('meter_id', '').strip()
        region_id = request.form.get('region_id', '').strip()
        location = request.form.get('location', '').strip()
        meter_type = request.form.get('meter_type', 'Smart Electricity Meter').strip()
        key_bits = int(request.form.get('key_bits', 16))

        success, msg = register_smart_meter(meter_id, region_id, location, meter_type, key_bits)
        if success:
            flash(msg, "success")
            return redirect(url_for('meters'))
        else:
            flash(msg, "danger")

    return render_template('register_meter.html')


@app.route('/meter/<meter_id>')
@login_required
def meter_details(meter_id):
    meter = get_meter(meter_id)
    if not meter:
        flash(f"Meter '{meter_id}' not found.", "danger")
        return redirect(url_for('meters'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM keys WHERE meter_id = ? ORDER BY key_version DESC", (meter_id,))
    key_history = [dict(k) for k in cursor.fetchall()]

    cursor.execute("SELECT * FROM audit_logs WHERE meter_id = ? ORDER BY id DESC LIMIT 20", (meter_id,))
    logs = [dict(l) for l in cursor.fetchall()]
    conn.close()

    return render_template('meter_details.html', meter=meter, keys=key_history, logs=logs)


@app.route('/encryption', methods=['GET', 'POST'])
@login_required
def encryption_page():
    all_meters = get_all_meters()
    result_data = None

    if request.method == 'POST':
        action = request.form.get('action')
        meter_id = request.form.get('meter_id', '').strip()

        if action == 'encrypt':
            message = request.form.get('message', '').strip()
            ok, msg, res = HierarchicalKDC.secure_encrypt_message(meter_id, message)
            if ok:
                flash(msg, "success")
                result_data = {'action': 'encrypt', 'details': res, 'original_message': message}
            else:
                flash(msg, "danger")

        elif action == 'decrypt':
            ciphertext_raw = request.form.get('ciphertext', '').strip()
            try:
                # Expecting comma separated integers like: 1413, 2227, 32
                ciphertext_blocks = [int(c.strip()) for c in ciphertext_raw.split(',') if c.strip()]
                ok, msg, decrypted_text = HierarchicalKDC.secure_decrypt_message(meter_id, ciphertext_blocks)
                if ok:
                    flash(msg, "success")
                    result_data = {'action': 'decrypt', 'decrypted_text': decrypted_text, 'ciphertext': ciphertext_blocks}
                else:
                    flash(msg, "danger")
            except ValueError:
                flash("Invalid ciphertext format. Enter comma-separated integer blocks.", "danger")

    return render_template('encryption.html', meters=all_meters, result=result_data)


@app.route('/key_management')
@login_required
def key_management():
    all_meters = get_all_meters()
    return render_template('key_management.html', meters=all_meters)


@app.route('/rsa_calculator', methods=['GET', 'POST'])
@login_required
def rsa_calculator():
    calc_data = None
    error_msg = None

    if request.method == 'POST':
        try:
            p = int(request.form.get('p', 61))
            q = int(request.form.get('q', 53))
            e = int(request.form.get('e', 17))

            if p == q:
                error_msg = "Primes p and q must be distinct (p ≠ q)."
            elif p < 2 or q < 2:
                error_msg = "p and q must be prime numbers greater than 1."
            else:
                n = p * q
                phi = (p - 1) * (q - 1)
                g = gcd(e, phi)

                if g != 1:
                    error_msg = f"Public exponent e={e} is not coprime with phi(n)={phi} (gcd={g})."
                else:
                    d, steps = mod_inverse(e, phi)
                    calc_data = {
                        'p': p,
                        'q': q,
                        'e': e,
                        'n': n,
                        'phi': phi,
                        'gcd': g,
                        'd': d,
                        'public_key': (e, n),
                        'private_key': (d, n),
                        'steps': steps
                    }
        except ValueError:
            error_msg = "Please enter valid integers for p, q, and e."

    return render_template('rsa_calculator.html', calc=calc_data, error=error_msg)


@app.route('/logs')
@login_required
def audit_logs_page():
    meter_filter = request.args.get('meter_id', '').strip()
    op_filter = request.args.get('operation', '').strip()

    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM audit_logs WHERE 1=1"
    params = []

    if meter_filter:
        query += " AND meter_id LIKE ?"
        params.append(f"%{meter_filter}%")
    if op_filter:
        query += " AND operation = ?"
        params.append(op_filter)

    query += " ORDER BY id DESC LIMIT 200"
    cursor.execute(query, params)
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return render_template('logs.html', logs=logs, meter_filter=meter_filter, op_filter=op_filter)


@app.route('/scalability')
@login_required
def scalability():
    return render_template('scalability.html')


# ==========================================
# REST API ENDPOINTS
# ==========================================

@app.route('/api/meters', methods=['GET', 'POST'])
def api_meters():
    if request.method == 'GET':
        meters_list = get_all_meters()
        return jsonify({'success': True, 'count': len(meters_list), 'meters': meters_list})

    elif request.method == 'POST':
        data = request.get_json() or {}
        meter_id = data.get('meter_id')
        region_id = data.get('region_id')
        location = data.get('location', 'Unspecified')
        meter_type = data.get('meter_type', 'Smart Electricity Meter')
        key_bits = int(data.get('key_bits', 16))

        if not meter_id or not region_id:
            return jsonify({'success': False, 'message': 'meter_id and region_id are required fields.'}), 400

        success, msg = register_smart_meter(meter_id, region_id, location, meter_type, key_bits)
        status_code = 201 if success else 400
        return jsonify({'success': success, 'message': msg, 'meter_id': meter_id}), status_code


@app.route('/api/meters/<meter_id>', methods=['GET'])
def api_get_meter(meter_id):
    meter = get_meter(meter_id)
    if meter:
        return jsonify({'success': True, 'meter': meter})
    return jsonify({'success': False, 'message': f"Meter '{meter_id}' not found."}), 404


@app.route('/api/meters/<meter_id>/rotate', methods=['POST'])
def api_rotate_key(meter_id):
    data = request.get_json() or {}
    key_bits = int(data.get('key_bits', 16))
    success, msg = HierarchicalKDC.rotate_meter_key(meter_id, key_bits)
    status_code = 200 if success else 400
    return jsonify({'success': success, 'message': msg, 'meter_id': meter_id}), status_code


@app.route('/api/meters/<meter_id>/revoke', methods=['POST'])
def api_revoke_key(meter_id):
    data = request.get_json() or {}
    reason = data.get('reason', 'Administrative revocation')
    success, msg = HierarchicalKDC.revoke_meter_key(meter_id, reason)
    status_code = 200 if success else 400
    return jsonify({'success': success, 'message': msg, 'meter_id': meter_id}), status_code


@app.route('/api/meters/<meter_id>/regenerate', methods=['POST'])
def api_regenerate_key(meter_id):
    data = request.get_json() or {}
    key_bits = int(data.get('key_bits', 16))
    success, msg = HierarchicalKDC.regenerate_revoked_key(meter_id, key_bits)
    status_code = 200 if success else 400
    return jsonify({'success': success, 'message': msg, 'meter_id': meter_id}), status_code


@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    data = request.get_json() or {}
    meter_id = data.get('meter_id')
    message = data.get('message')

    if not meter_id or message is None:
        return jsonify({'success': False, 'message': 'meter_id and message are required.'}), 400

    ok, msg, res = HierarchicalKDC.secure_encrypt_message(meter_id, message)
    status_code = 200 if ok else 400
    return jsonify({'success': ok, 'message': msg, 'data': res}), status_code


@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    data = request.get_json() or {}
    meter_id = data.get('meter_id')
    ciphertext = data.get('ciphertext')

    if not meter_id or ciphertext is None or not isinstance(ciphertext, list):
        return jsonify({'success': False, 'message': 'meter_id and list of integer ciphertext blocks are required.'}), 400

    ok, msg, decrypted_text = HierarchicalKDC.secure_decrypt_message(meter_id, ciphertext)
    status_code = 200 if ok else 400
    return jsonify({'success': ok, 'message': msg, 'decrypted_text': decrypted_text}), status_code


@app.route('/api/logs', methods=['GET'])
def api_logs():
    limit = int(request.args.get('limit', 100))
    logs = get_audit_logs(limit=limit)
    return jsonify({'success': True, 'count': len(logs), 'logs': logs})


@app.route('/api/topology', methods=['GET'])
def api_topology():
    tree = HierarchicalKDC.get_hierarchy_tree()
    return jsonify({'success': True, 'topology': tree})

@app.route('/run_simulation_benchmark', methods=['POST'])
@login_required
def run_simulation_benchmark():
    data = request.get_json() or {}
    count = int(data.get('count', 1000))
    mode = data.get('mode', 'HIERARCHICAL')
    
    # Enforce safe bounds for web execution
    if count > 10000:
        count = 10000

    results = run_kdc_simulation(num_meters=count, architecture_mode=mode, key_bits=16)
    return jsonify(results)
if __name__ == '__main__':
    # Initialize DB before launch
    init_db()
    print("==================================================")
    print("  SMART GRID HIERARCHICAL KDC SERVER RUNNING     ")
    print("  URL: http://127.0.0.1:5000                     ")
    print("==================================================")
    app.run(host='127.0.0.1', port=5000, debug=True)