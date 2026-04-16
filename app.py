from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import sqlite3
import bcrypt
import re
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_PATH = 'usuarios.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            correo TEXT NOT NULL UNIQUE,
            celular TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            fecha_registro DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def validar_password(password):
    errores = []
    if len(password) < 10:
        errores.append("Debe tener mínimo 10 caracteres")
    if not re.search(r'[A-Z]', password):
        errores.append("Debe contener al menos una mayúscula")
    if not re.search(r'[a-z]', password):
        errores.append("Debe contener al menos una minúscula")
    if not re.search(r'[0-9]', password):
        errores.append("Debe contener al menos un número")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        errores.append("Debe contener al menos un carácter especial")
    return errores

def validar_correo(correo):
    patron = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(patron, correo))

def validar_celular(celular):
    return bool(re.match(r'^\d{10}$', celular))

@app.route('/')
def index():
    return render_template('menu.html')

@app.route('/registro', methods=['GET'])
def registro_form():
    return render_template('registro.html')

@app.route('/registro', methods=['POST'])
def registro_submit():
    nombre   = request.form.get('nombre', '').strip()
    correo   = request.form.get('correo', '').strip()
    celular  = request.form.get('celular', '').strip()
    password = request.form.get('password', '')
    confirmar = request.form.get('confirmar_password', '')

    errores = []

    if not nombre:
        errores.append("El nombre no puede estar vacío")
    if not correo:
        errores.append("El correo no puede estar vacío")
    elif not validar_correo(correo):
        errores.append("El correo electrónico no tiene un formato válido")
    if not celular:
        errores.append("El celular no puede estar vacío")
    elif not validar_celular(celular):
        errores.append("El celular debe tener exactamente 10 dígitos")

    pw_errores = validar_password(password)
    errores.extend(pw_errores)

    if password != confirmar:
        errores.append("Las contraseñas no coinciden")

    if errores:
        return jsonify({'success': False, 'errores': errores}), 400

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        conn = get_db()
        conn.execute(
            'INSERT INTO usuarios (nombre, correo, celular, password_hash) VALUES (?, ?, ?, ?)',
            (nombre, correo, celular, password_hash)
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'mensaje': f'¡Usuario {nombre} registrado exitosamente!'})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'errores': ['Este correo ya está registrado']}), 400
    except Exception as e:
        return jsonify({'success': False, 'errores': ['Error interno del servidor']}), 500

@app.route('/usuarios')
def listar_usuarios():
    conn = get_db()
    usuarios = conn.execute('SELECT id, nombre, correo, celular, fecha_registro FROM usuarios ORDER BY fecha_registro DESC').fetchall()
    conn.close()
    return render_template('usuarios.html', usuarios=usuarios)

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', '5000'))
    app.run(host='0.0.0.0', port=port, debug=False)
