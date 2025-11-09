from flask_sqlalchemy import SQLAlchemy
from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash, make_response
from datetime import datetime, timedelta # <--- TIMEDELTA AÑADIDO
import os
from werkzeug.utils import secure_filename
import re
from xhtml2pdf import pisa
import io
from io import BytesIO, StringIO
from flask import send_file
from flask_mail import Mail, Message
from sqlalchemy.sql import exists
from sqlalchemy import and_, not_, exists
from sqlalchemy.orm import aliased
from sqlalchemy import and_, not_, exists, func
import pandas as pd
import secrets
import mercadopago
from dotenv import load_dotenv
# Importaciones para OAuth y Flask-Login
import base64
import pyotp
import qrcode
from gtts import gTTS
import pygame
import tempfile
from authlib.integrations.flask_client import OAuth
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from functools import wraps

load_dotenv()

# 1. Crear la instancia de Flask
app = Flask(__name__)

# 2. Configuración de la aplicación
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

app.config.update({
    'SECRET_KEY': 'clave_secreta_super_segura',
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SECURE': False,  # True en producción con HTTPS
    'SESSION_COOKIE_SAMESITE': 'Lax',
})

pygame.mixer.init()

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'seedhubagronomia@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'seedhubagronomia@gmail.com'

app.config['MERCADOPAGO_PUBLIC_KEY'] = os.getenv('MERCADOPAGO_PUBLIC_KEY')
app.config['MERCADOPAGO_ACCESS_TOKEN'] = os.getenv('MERCADOPAGO_ACCESS_TOKEN')

print("Google Client ID:", app.config['GOOGLE_CLIENT_ID'])
print("Google Client Secret:", app.config['GOOGLE_CLIENT_SECRET'])

# 3. Inicializar extensiones
db = SQLAlchemy(app)
mail = Mail(app)

# 4. Configurar Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Debes iniciar sesión para ver esta página."
login_manager.login_message_category = "error"

# 5. Configurar OAuth
oauth = OAuth(app)
# Configuración alternativa de OAuth
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'email profile'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)


# 7. Modelos
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
           
           
@login_manager.user_loader
def load_user(user_id):
    """
    Cargador de usuario mejorado
    """
    # Primero intentar determinar el tipo desde la sesión
    user_type = session.get('tipo_usuario', '').lower()
    
    print(f"DEBUG UserLoader - Tipo: {user_type}, UserID: {user_id}")

    if user_type == 'productor':
        user = Productor.query.get(int(user_id))
    elif user_type == 'admin':
        user = Administrador.query.get(int(user_id))
    else:
        # Por defecto o para 'cliente', buscar en Usuario
        user = Usuario.query.get(int(user_id))

    print(f"DEBUG UserLoader - Usuario encontrado: {user}")
    return user

def enviar_email_confirmacion(destinatario, nombre, pedido_id, productos, total):
    """Envía un correo de confirmación de compra exitosa."""
    msg = Message(
        subject=f'Confirmación de tu pedido #{pedido_id} en AgronoMia',
        recipients=[destinatario]
    )
    msg.html = render_template(
        'email_confirmacion_compra.html',
        nombre=nombre,
        pedido_id=pedido_id,
        productos=productos,
        total=total
    )
    mail.send(msg)

# --- NUEVA FUNCIÓN PARA ENVIAR CORREO DE RESET ---
def enviar_email_reset(usuario, token, tipo_usuario):
    msg = Message(
        subject='Restablecer tu contraseña de AgronoMia',
        recipients=[usuario.email]
    )
    link = url_for('reset_password', token=token, _external=True)
    
    msg.html = render_template(
        'email_reset.html',
        nombre=usuario.nombre,
        link_reset=link,
        tipo_usuario=tipo_usuario
    )
    mail.send(msg)
# --- FIN DE NUEVA FUNCIÓN ---


@app.route('/debug-auth')
def debug_auth():
    info = {
        'session_usuario_id': session.get('usuario_id'),
        'session_tipo_usuario': session.get('tipo_usuario'),
        'current_user': str(current_user),
        'is_authenticated': current_user.is_authenticated,
        'current_user_id': current_user.get_id() if current_user.is_authenticated else None,
        'session_data': dict(session)
    }
    
    return f"""
    <h1>Debug Authentication</h1>
    <pre>{info}</pre>
    <br>
    <a href="{url_for('panel_cliente')}">Ir a Panel Cliente</a> |
    <a href="{url_for('inicio')}">Ir a Inicio</a>
    """

class Usuario(db.Model, UserMixin):
    __tablename__ = 'usuario'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    tipo_usuario = db.Column(db.String(50), nullable=False)
    
    # --- CAMPOS ACTUALIZADOS (Combinando 2FA y Verificación) ---
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)
    is_verified = db.Column(db.Boolean, default=False, nullable=False) # <-- CAMPO DE VERIFICACIÓN
    otp_secret = db.Column(db.String(32), nullable=True)
    otp_enabled = db.Column(db.Boolean, default=False, nullable=True) 
    # ------------------------------------------------------------
    
    direcciones = db.relationship('Direccion', back_populates='usuario', cascade="all, delete-orphan")
    pedidos = db.relationship('Pedido', back_populates='usuario', cascade="all, delete-orphan")
    contacto = db.relationship('Contacto', back_populates='usuario', cascade="all, delete-orphan")
    pagos = db.relationship('Pago', back_populates='usuario', cascade="all, delete-orphan")
    carrito_items = db.relationship('Carrito', back_populates='usuario', cascade="all, delete-orphan")
    mensajes_enviados = db.relationship('Mensaje', foreign_keys='Mensaje.cliente_id', back_populates='cliente', cascade="all, delete-orphan")

class Administrador(db.Model, UserMixin):
    __tablename__ = 'administrador'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)
    otp_secret = db.Column(db.String(32), nullable=True)
    otp_enabled = db.Column(db.Boolean, default=False, nullable=True)
    
    def get_id(self):
        return str(self.id)

class Productor(db.Model, UserMixin):
    __tablename__ = 'productor'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    descripcion = db.Column(db.Text, nullable=True) 
    ubicacion = db.Column(db.String(200), nullable=True)
    imagen = db.Column(db.String(200), nullable=True)
    publicado = db.Column(db.Boolean, default=False, nullable=False)
    
    productos = db.relationship('Producto', back_populates='productor', cascade="all, delete-orphan")
    mensajes_recibidos = db.relationship('Mensaje', foreign_keys='Mensaje.productor_id', back_populates='productor', cascade="all, delete-orphan")

class Producto(db.Model):
    __tablename__ = 'producto'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    precio = db.Column(db.Float, nullable=False)
    imagen = db.Column(db.String(200), nullable=False)
    categoria_id = db.Column(db.Integer, db.ForeignKey('categoria.id'), nullable=False)
    productor_id = db.Column(db.Integer, db.ForeignKey('productor.id'), nullable=False)
    activo = db.Column(db.Boolean, default=True)
    
    # --- CAMPOS AGREGADOS ---
    tiempo_germinacion = db.Column(db.Integer, nullable=True)
    epoca_siembra = db.Column(db.String(100), nullable=True)
    cantidad_semillas = db.Column(db.Integer, nullable=True)
    # ------------------------

    productor = db.relationship('Productor', back_populates='productos')
    categoria = db.relationship('Categoria', back_populates='productos')
    
    pedido_items = db.relationship('PedidoItem', back_populates='producto', cascade="all, delete-orphan")
    mensajes = db.relationship('Mensaje', back_populates='producto', cascade="all, delete-orphan")
    carrito_items = db.relationship('Carrito', back_populates='producto', cascade="all, delete-orphan")

class Categoria(db.Model):
    __tablename__ = 'categoria'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    productos = db.relationship('Producto', back_populates='categoria')


class Pedido(db.Model):
    __tablename__ = 'pedido'
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    total = db.Column(db.Float, nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    estado = db.Column(db.String(50), default="Pendiente")
    
    usuario = db.relationship('Usuario', back_populates='pedidos')
    items = db.relationship('PedidoItem', back_populates='pedido', cascade="all, delete-orphan")
    pagos = db.relationship('Pago', back_populates='pedido', cascade="all, delete-orphan")

class Carrito(db.Model):
    __tablename__ = 'carrito'
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    producto_id = db.Column(db.Integer, db.ForeignKey('producto.id'), nullable=False)
    cantidad = db.Column(db.Integer, nullable=False)
    
    usuario = db.relationship('Usuario', back_populates='carrito_items')
    producto = db.relationship('Producto', back_populates='carrito_items')
    
class Contacto(db.Model):
    __tablename__ = 'contacto'
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    mensaje = db.Column(db.Text, nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    respuesta = db.Column(db.Text)
    
    usuario = db.relationship('Usuario', back_populates='contacto')

class Direccion(db.Model):
    __tablename__ = 'direccion'
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    direccion = db.Column(db.String(200), nullable=False)
    
    usuario = db.relationship('Usuario', back_populates='direcciones')

class MetodoPago(db.Model):
    __tablename__ = 'metodo_pago'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)
    pagos = db.relationship('Pago', back_populates='metodo_pago', cascade="all, delete-orphan")
    
class Pago(db.Model):
    __tablename__ = 'pago'
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    pedido_id = db.Column(db.Integer, db.ForeignKey('pedido.id'), nullable=False)
    metodo_pago_id = db.Column(db.Integer, db.ForeignKey('metodo_pago.id'), nullable=False)
    monto = db.Column(db.Float, nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    estado = db.Column(db.String(50), default="Completado")
    
    usuario = db.relationship('Usuario', back_populates='pagos')
    pedido = db.relationship('Pedido', back_populates='pagos')
    metodo_pago = db.relationship('MetodoPago', back_populates='pagos')

class PedidoItem(db.Model):
    __tablename__ = 'pedido_item'
    id = db.Column(db.Integer, primary_key=True)
    pedido_id = db.Column(db.Integer, db.ForeignKey('pedido.id'), nullable=False)
    producto_id = db.Column(db.Integer, db.ForeignKey('producto.id'), nullable=False)
    cantidad = db.Column(db.Integer, nullable=False)
    
    pedido = db.relationship('Pedido', back_populates='items')
    producto = db.relationship('Producto', back_populates='pedido_items')

class Mensaje(db.Model):
    __tablename__ = 'mensaje'
    id = db.Column(db.Integer, primary_key=True)
    producto_id = db.Column(db.Integer, db.ForeignKey('producto.id'))
    cliente_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    productor_id = db.Column(db.Integer, db.ForeignKey('productor.id'), nullable=False)
    remitente_tipo = db.Column(db.String(10), nullable=False)
    contenido = db.Column(db.Text, nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    leido = db.Column(db.Boolean, default=False)
    oculto_para_cliente = db.Column(db.Boolean, default=False)
    oculto_para_productor = db.Column(db.Boolean, default=False)
    
    producto = db.relationship('Producto', back_populates='mensajes')
    cliente = db.relationship('Usuario', back_populates='mensajes_enviados')
    productor = db.relationship('Productor', back_populates='mensajes_recibidos')
    
def crear_admin():
    """Crea un administrador por defecto si no existe."""
    admin_email = "admin@agronomia.com"
    admin_password = "securepassword"
    if not Administrador.query.filter_by(email=admin_email).first():
        nuevo_admin = Administrador(nombre="Admin", email=admin_email, password=admin_password)
        db.session.add(nuevo_admin)
        db.session.commit()
        print("✅ Administrador creado")
         
@app.route('/')
def inicio():
    tipo_usuario = session.get('tipo_usuario') 
    cantidad_carrito = 0
    
    if tipo_usuario == 'Cliente' and 'usuario_id' in session: 
        cantidad_carrito = db.session.query(db.func.sum(Carrito.cantidad)).filter_by(usuario_id=session['usuario_id']).scalar() or 0
    
    return render_template('inicio.html', 
                           cantidad_carrito=cantidad_carrito, 
                           tipo_usuario=tipo_usuario)
    
@app.route('/verificar_cuenta/<token>')
def verificar_cuenta(token):
    """
    Ruta a la que el usuario llega desde el enlace en su correo.
    """
    # Buscar el token en usuarios (los admin no se registran así)
    usuario = Usuario.query.filter(
        Usuario.reset_token == token, 
        Usuario.reset_token_expiration > datetime.utcnow()
    ).first()
    
    if not usuario:
        flash("El enlace de verificación no es válido o ha expirado.", "error")
        return redirect(url_for('login'))
        
    try:
        # ¡Marcar como verificado y limpiar el token!
        usuario.is_verified = True
        usuario.reset_token = None
        usuario.reset_token_expiration = None
        db.session.commit()
        
        flash("¡Tu cuenta ha sido verificada exitosamente! Ya puedes iniciar sesión.", "success")
        return redirect(url_for('login'))
        
    except Exception as e:
        db.session.rollback()
        flash("Error al verificar la cuenta. Inténtalo de nuevo.", "error")
        return redirect(url_for('login'))
    
@app.route('/habilitar-2fa')
@login_required
def habilitar_2fa():
    """
    Página donde el usuario escanea el QR para configurar 2FA.
    """
    # Determinar qué usuario está logueado
    if session.get('tipo_usuario') == 'Administrador':
        user = Administrador.query.get(session['admin_id'])
    else: # Cliente o Productor
        user = Usuario.query.get(session['usuario_id'])
    
    if not user:
        return redirect(url_for('login'))
        
    if user.otp_enabled:
        flash("Ya tienes la autenticación de dos factores habilitada.", "info")
        # Redirigir al panel correspondiente
        if session.get('tipo_usuario') == 'Productor':
            return redirect(url_for('panel_productor'))
        elif session.get('tipo_usuario') == 'Administrador':
            return redirect(url_for('panel_admin'))
        else:
            return redirect(url_for('panel_cliente'))

    # Generar un nuevo secreto
    otp_secret = pyotp.random_base32()
    # Guardar temporalmente en la sesión hasta que se verifique
    session['otp_secret_temp'] = otp_secret

    # Generar el URI para la app de autenticación
    totp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(
        name=user.email,
        issuer_name="AgronoMia"
    )

    # Generar el QR code en memoria
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    
    # Codificar imagen como Base64 para mostrar en HTML
    qr_code_data = base64.b64encode(buf.getvalue()).decode('utf-8')
    
    return render_template(
        'habilitar_2fa.html',
        qr_code_data=qr_code_data,
        otp_secret=otp_secret # Para mostrar si no pueden escanear
    )

@app.route('/verificar-2fa', methods=['POST'])
@login_required
def verificar_2fa():
    """
    Verifica el primer código que el usuario introduce después de escanear.
    Si es correcto, activa 2FA permanentemente.
    """
    otp_code = request.form.get('otp_code')
    otp_secret = session.get('otp_secret_temp')

    if not otp_secret:
        flash("Error en la sesión. Por favor, intenta habilitar 2FA de nuevo.", "error")
        return redirect(url_for('habilitar_2fa'))

    # Verificar el código
    totp = pyotp.TOTP(otp_secret)
    if totp.verify(otp_code):
        # El código es correcto. Guardar el secreto en la BD y activarlo.
        try:
            if session.get('tipo_usuario') == 'Administrador':
                user = Administrador.query.get(session['admin_id'])
            else:
                user = Usuario.query.get(session['usuario_id'])
            
            user.otp_secret = otp_secret
            user.otp_enabled = True
            db.session.commit()
            
            session.pop('otp_secret_temp', None) # Limpiar sesión
            
            flash("¡Autenticación de dos factores habilitada exitosamente!", "success")
            # Redirigir al panel correspondiente
            if session.get('tipo_usuario') == 'Productor':
                return redirect(url_for('panel_productor'))
            elif session.get('tipo_usuario') == 'Administrador':
                return redirect(url_for('panel_admin'))
            else:
                return redirect(url_for('panel_cliente'))
                
        except Exception as e:
            db.session.rollback()
            flash(f"Error al guardar la configuración: {e}", "error")
            return redirect(url_for('habilitar_2fa'))
    else:
        # El código es incorrecto
        flash("Código de verificación incorrecto. Inténtalo de nuevo.", "error")
        # Es necesario regenerar el QR y el secreto
        return redirect(url_for('habilitar_2fa'))


@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    """
    Página que pide el código de 6 dígitos después del login.
    """
    if '2fa_user_id' not in session:
        # Si el usuario no está en el "limbo" de 2FA, no debe estar aquí
        return redirect(url_for('login'))

    user_id = session['2fa_user_id']
    user_type = session['2fa_user_type']

    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        
        # Cargar el usuario correcto (Admin o Usuario)
        if user_type == 'Administrador':
            user = Administrador.query.get(user_id)
        else:
            user = Usuario.query.get(user_id)
        
        if not user or not user.otp_secret:
            flash("Error de autenticación.", "error")
            session.pop('2fa_user_id', None)
            session.pop('2fa_user_type', None)
            return redirect(url_for('login'))

        # Verificar el código
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(otp_code):
            # ¡ÉXITO! Iniciar sesión real
            session.pop('2fa_user_id', None)
            session.pop('2fa_user_type', None)
            
            if user_type == 'Administrador':
                session['tipo_usuario'] = "Administrador"
                session['admin_id'] = user.id
                return redirect(url_for('panel_admin'))
            else:
                login_user(user) # Inicia sesión con Flask-Login
                session['usuario_id'] = user.id
                session['tipo_usuario'] = user.tipo_usuario
                if user.tipo_usuario == "Productor":
                    productor = Productor.query.filter_by(email=user.email).first()
                    if productor:
                        session['productor_id'] = productor.id
                    return redirect(url_for('panel_productor'))
                
                return redirect(url_for('panel_cliente'))
        else:
            flash("Código de 6 dígitos incorrecto.", "error")
            return render_template('login_2fa.html')
            
    return render_template('login_2fa.html')

# --- FIN DE RUTAS 2FA ---

@app.route('/login/google')
def login_google():
    rol = request.args.get('rol', 'Cliente')
    session['rol_google'] = rol  # Guarda el rol temporalmente en la sesión
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri, prompt='select_account')

@app.route('/login/google/authorize')
def authorize_google():
    try:
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.get('https://www.googleapis.com/oauth2/v2/userinfo').json()
        user_email = user_info['email']
        user_name = user_info.get('name', 'Usuario Google')

        rol = session.pop('rol_google', 'Cliente')
        tipo_usuario = 'Productor' if rol == 'Productor' else 'Cliente'

        usuario_existente = Usuario.query.filter_by(email=user_email).first()

        if usuario_existente:
            # --- LÓGICA DE VERIFICACIÓN ACTUALIZADA ---
            if not usuario_existente.is_verified:
                usuario_existente.is_verified = True
                db.session.commit()
            # --- FIN DE LÓGICA ---
            
            login_user(usuario_existente)
            session['usuario_id'] = usuario_existente.id
            session['tipo_usuario'] = usuario_existente.tipo_usuario
            if usuario_existente.tipo_usuario == 'Productor':
                productor = Productor.query.filter_by(email=user_email).first()
                if productor:
                    session['productor_id'] = productor.id
            flash('¡Has iniciado sesión correctamente con Google!', 'success')
        else:
            random_password = secrets.token_hex(16)
            # --- LÓGICA DE VERIFICACIÓN ACTUALIZADA ---
            nuevo_usuario = Usuario(
                nombre=user_name,
                email=user_email,
                password=random_password,
                tipo_usuario=tipo_usuario,
                is_verified=True  # <-- Verificado automáticamente por Google
            )
            # --- FIN DE LÓGICA ---
            db.session.add(nuevo_usuario)
            db.session.commit()
            login_user(nuevo_usuario)
            session['usuario_id'] = nuevo_usuario.id
            session['tipo_usuario'] = tipo_usuario
            if tipo_usuario == 'Productor':
                nuevo_productor = Productor(nombre=user_name, email=user_email)
                db.session.add(nuevo_productor)
                db.session.commit()
                session['productor_id'] = nuevo_productor.id
            flash('¡Bienvenido! Tu cuenta ha sido creada con Google.', 'success')
        
        if session['tipo_usuario'] == 'Productor':
            return redirect(url_for('panel_productor'))
        else:
            return redirect(url_for('panel_cliente'))

    except Exception as e:
        print(f"❌ Error en OAuth: {e}")
        db.session.rollback()
        flash('Error al iniciar sesión con Google. Inténtalo de nuevo.', 'danger')
        return redirect(url_for('login'))

@app.route('/debug-db')
def debug_db():
    try:
        # Verificar conexión a la BD
        db.session.execute('SELECT 1')
        print("✅ Conexión a la BD funciona")
        
        # Contar usuarios
        total_usuarios = Usuario.query.count()
        print(f"✅ Total de usuarios en BD: {total_usuarios}")
        
        # Listar usuarios
        usuarios = Usuario.query.all()
        for usuario in usuarios:
            print(f"Usuario: {usuario.id} - {usuario.nombre} - {usuario.email}")
        
        return f"""
        <h1>Debug Base de Datos</h1>
        <p>Conexión: ✅ OK</p>
        <p>Total usuarios: {total_usuarios}</p>
        <ul>
            {"".join([f'<li>{u.id} - {u.nombre} - {u.email}</li>' for u in usuarios])}
        </ul>
        """
    except Exception as e:
        print(f"❌ Error en BD: {e}")
        return f"<h1>Error en BD: {e}</h1>"

@app.route('/semillas')
def semillas():
    categoria_id = request.args.get('categoria_id')
    if categoria_id:
        productos = Producto.query.filter_by(categoria_id=categoria_id, activo=True).all()
    else:
        productos = Producto.query.filter_by(activo=True).all()
    
    categorias = Categoria.query.all()
    cantidad_carrito = 0
    if 'usuario_id' in session and session.get('tipo_usuario') == 'cliente':
        cantidad_carrito = db.session.query(db.func.sum(Carrito.cantidad)).filter_by(usuario_id=session['usuario_id']).scalar() or 0
    
    return render_template('semillas.html', productos=productos, categorias=categorias, cantidad_carrito=cantidad_carrito)

@app.route('/productos')
def productos():
    productos = Producto.query.filter_by(activo=True).all()
    categorias = Categoria.query.all()
    cantidad_carrito = 0
    
    # Obtener el tipo de usuario de la sesión
    tipo_usuario = session.get('tipo_usuario', None) # <--- LÍNEA CORREGIDA

    # Calcular la cantidad del carrito solo si el usuario es un Cliente
    if tipo_usuario == 'Cliente' and 'usuario_id' in session:
        cantidad_carrito = db.session.query(db.func.sum(Carrito.cantidad)).filter_by(usuario_id=session['usuario_id']).scalar() or 0
    
    return render_template('productos.html', 
                           productos=productos, 
                           categorias=categorias, 
                           tipo_usuario=tipo_usuario, 
                           cantidad_carrito=cantidad_carrito)

@app.route('/contacto')
def contacto():
    cantidad_carrito = 0
    if 'usuario_id' in session and session.get('tipo_usuario') == 'cliente':
        cantidad_carrito = db.session.query(db.func.sum(Carrito.cantidad)).filter_by(usuario_id=session['usuario_id']).scalar() or 0
    return render_template('contacto.html', cantidad_carrito=cantidad_carrito)


@app.route('/enviar_mensaje', methods=['POST'])
def enviar_mensaje():
    if 'usuario_id' not in session:
        return redirect(url_for('login')) 
    nombre = request.form['nombre']
    email = request.form['email']
    mensaje = request.form['mensaje']

    nuevo_mensaje = Contacto(usuario_id=session['usuario_id'], mensaje=mensaje)
    db.session.add(nuevo_mensaje)
    db.session.commit()

    flash("Tu mensaje fue enviado con éxito.", "success")
    return redirect(url_for('contacto'))



@app.route('/productores')
def productores():
    lista_productores = Productor.query.all()
    tipo_usuario = session.get('tipo_usuario', None)
    cantidad_carrito = 0
    if tipo_usuario:
        tipo_usuario = tipo_usuario.capitalize()
    if tipo_usuario == 'Cliente' and 'usuario_id' in session:
        cantidad_carrito = db.session.query(db.func.sum(Carrito.cantidad)).filter_by(usuario_id=session['usuario_id']).scalar() or 0
    return render_template('productores.html', 
                           productores=lista_productores, 
                           tipo_usuario=tipo_usuario, 
                           cantidad_carrito=cantidad_carrito)

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':  
        nombre = request.form['nombre']
        email = request.form['email']
        password = request.form['password']
        tipo_usuario = "Cliente" 

        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{8,}$", password):
            flash("La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un carácter especial.", "error")
            return redirect(url_for('registro'))  

        if Usuario.query.filter_by(email=email).first():
            return render_template('registro.html', correo_duplicado=True, nombre=nombre, email=email)

        try:
            # --- LÓGICA DE REGISTRO ACTUALIZADA ---
            token = secrets.token_urlsafe(32)
            expiracion = datetime.utcnow() + timedelta(hours=24) # 24 horas para verificar

            nuevo_usuario = Usuario(
                nombre=nombre, 
                email=email, 
                password=password, 
                tipo_usuario=tipo_usuario,
                is_verified=False, # <-- Se establece en Falso
                reset_token=token, # <-- Usamos el token para verificar
                reset_token_expiration=expiracion
            )
            db.session.add(nuevo_usuario)
            db.session.commit()

            # Enviar el correo de verificación
            enviar_email_verificacion(nuevo_usuario, token)

            # Ya no se usa registro_exitoso=True, se usa un flash
            flash("¡Registro casi listo! Revisa tu correo electrónico para verificar tu cuenta.", "success")
            return redirect(url_for('login'))
            # --- FIN DE LÓGICA ACTUALIZADA ---
            
        except Exception as e:
            db.session.rollback()
            print(f"Error en registro: {e}")
            return render_template('registro.html', registro_fallido=True)

    return render_template('registro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if session.get('tipo_usuario') == 'Productor':
            return redirect(url_for('panel_productor'))
        elif session.get('tipo_usuario') == 'Administrador':
            return redirect(url_for('panel_admin'))
        else:
            return redirect(url_for('panel_cliente'))
        
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        
        # 1. Buscar en Administrador
        admin = Administrador.query.filter_by(email=email, password=password).first()
        if admin:
            if admin.otp_enabled:
                session['2fa_user_id'] = admin.id
                session['2fa_user_type'] = 'Administrador'
                return redirect(url_for('login_2fa'))
            else:
                session['tipo_usuario'] = "Administrador"
                session['admin_id'] = admin.id
                return redirect(url_for('panel_admin'))

        # 2. Buscar en Usuario (Cliente/Productor)
        usuario = Usuario.query.filter_by(email=email, password=password).first()
        if usuario:
            
            # --- ¡AQUÍ ESTÁ LA VERIFICACIÓN! ---
            if not usuario.is_verified:
                flash("Tu cuenta no ha sido verificada. Revisa tu correo electrónico para el enlace de verificación.", "error")
                return redirect(url_for('login'))
            # ------------------------------------
                
            if usuario.otp_enabled:
                session['2fa_user_id'] = usuario.id
                session['2fa_user_type'] = usuario.tipo_usuario
                return redirect(url_for('login_2fa'))
            else:
                login_user(usuario)
                session['usuario_id'] = usuario.id
                session['tipo_usuario'] = usuario.tipo_usuario

                if usuario.tipo_usuario == "Productor":
                    productor = Productor.query.filter_by(email=usuario.email).first()
                    if productor:
                        session['productor_id'] = productor.id
                    return redirect(url_for('panel_productor'))
                
                return redirect(url_for('panel_cliente'))
        
        # 3. Si ninguno coincide
        flash("Correo o contraseña incorrectos", "error")
        
    return render_template('login.html')

# --- INICIO: NUEVAS RUTAS PARA RESETEO DE CONTRASEÑA ---

@app.route('/solicitar_reset', methods=['GET', 'POST'])
def solicitar_reset():
    """Página para que el usuario ingrese su email y solicite el reseteo."""
    if current_user.is_authenticated:
        return redirect(url_for('inicio'))
        
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        
        usuario = Usuario.query.filter_by(email=email).first()
        admin = Administrador.query.filter_by(email=email).first()
        
        user_to_reset = None
        tipo_usuario = None
        
        if usuario:
            user_to_reset = usuario
            tipo_usuario = usuario.tipo_usuario
        elif admin:
            user_to_reset = admin
            tipo_usuario = "Administrador"

        if user_to_reset:
            try:
                token = secrets.token_urlsafe(32)
                expiracion = datetime.utcnow() + timedelta(hours=1)
                
                user_to_reset.reset_token = token
                user_to_reset.reset_token_expiration = expiracion
                
                db.session.commit()
                
                enviar_email_reset(user_to_reset, token, tipo_usuario)
                
            except Exception as e:
                db.session.rollback()
                print(f"Error al generar token o enviar email: {e}")
                flash("Ocurrió un error inesperado. Inténtalo de nuevo.", "error")
                return redirect(url_for('solicitar_reset'))

        flash("Si tu correo está registrado, recibirás un enlace para restablecer tu contraseña.", "success")
        return redirect(url_for('login'))

    return render_template('solicitar_reset.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Página donde el usuario ingresa la nueva contraseña."""
    if current_user.is_authenticated:
        return redirect(url_for('inicio'))

    now = datetime.utcnow()
    usuario = Usuario.query.filter(Usuario.reset_token == token, Usuario.reset_token_expiration > now).first()
    admin = Administrador.query.filter(Administrador.reset_token == token, Administrador.reset_token_expiration > now).first()
    
    user_to_update = None
    if usuario:
        user_to_update = usuario
    elif admin:
        user_to_update = admin
    
    if not user_to_update:
        flash("El enlace de reseteo no es válido o ha expirado.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Las contraseñas no coinciden.", "error")
            return render_template('reset_password.html', token=token)

        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{8,}$", password):
            flash("La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un carácter especial.", "error")
            return render_template('reset_password.html', token=token)
        
        try:
            user_to_update.password = password
            user_to_update.reset_token = None
            user_to_update.reset_token_expiration = None
            
            db.session.commit()
            
            flash("¡Tu contraseña ha sido actualizada! Ya puedes iniciar sesión.", "success")
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error al actualizar contraseña: {e}")
            flash("Ocurrió un error al actualizar tu contraseña.", "error")
            return render_template('reset_password.html', token=token)

    return render_template('reset_password.html', token=token)

# --- FIN DE NUEVAS RUTAS ---


@app.route('/panel_cliente')
@login_required
def panel_cliente():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    
    usuario = Usuario.query.get(session['usuario_id'])
    direccion = Direccion.query.filter_by(usuario_id=session['usuario_id']).first()
    cantidad_carrito = db.session.query(db.func.sum(Carrito.cantidad)).filter_by(usuario_id=session['usuario_id']).scalar() or 0
    
    response = make_response(render_template('panel_cliente.html', 
                                             usuario=usuario, 
                                             direccion=direccion, 
                                             cantidad_carrito=cantidad_carrito))

    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


@app.route('/perfil_cliente')
def perfil_cliente():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    
    usuario = Usuario.query.get(session['usuario_id'])
    return render_template('perfil_cliente.html', usuario=usuario)


@app.route('/panel_productor')
def panel_productor():
    if 'usuario_id' not in session or session.get('tipo_usuario') != 'Productor':
        return redirect(url_for('login'))
    usuario = Usuario.query.get(session['usuario_id'])
    productor_id = session.get('productor_id')

    
    total_pedidos = Pedido.query.join(PedidoItem).join(Producto).filter(Producto.productor_id == productor_id).distinct(Pedido.id).count()
    total_productos = db.session.query(db.func.sum(PedidoItem.cantidad)).join(Producto).filter(Producto.productor_id == productor_id).scalar() or 0
    total_ingresos = db.session.query(db.func.sum(PedidoItem.cantidad * Producto.precio)).join(Producto).filter(Producto.productor_id == productor_id).scalar() or 0

   
    from sqlalchemy import extract, func
    import calendar
    from datetime import datetime, timedelta

    hoy = datetime.today()
    ventas_labels = []
    ventas_data = []

    for i in range(5, -1, -1): 
        mes = (hoy.month - i - 1) % 12 + 1
        anio = hoy.year if hoy.month - i > 0 else hoy.year - 1
        nombre_mes = calendar.month_abbr[mes].capitalize()
        ventas_labels.append(f"{nombre_mes} {anio}")

        suma_mes = db.session.query(
            func.coalesce(func.sum(PedidoItem.cantidad * Producto.precio), 0)
        ).join(Producto).join(Pedido).filter(
            Producto.productor_id == productor_id,
            extract('month', Pedido.fecha) == mes,
            extract('year', Pedido.fecha) == anio
        ).scalar() or 0

        ventas_data.append(float(suma_mes))

    return render_template(
        'panel_productor.html',
        usuario=usuario,
        total_pedidos=total_pedidos,
        total_productos=total_productos,
        total_ingresos=total_ingresos,
        ventas_labels=ventas_labels,
        ventas_data=ventas_data
    )

@app.route('/panel_admin')
def panel_admin():
    q = request.args.get('q', '').strip()
    filtro = request.args.get('filtro', '')

    total_usuarios = Usuario.query.count()
    pedidos_activos = Pedido.query.filter(Pedido.estado != 'Entregado').count()
    total_productos = Producto.query.count()
    mensajes_pendientes = Contacto.query.filter(Contacto.respuesta == None).count()

    resultados = []
    if q:
        if filtro == "usuarios":
            resultados = Usuario.query.filter(
                (Usuario.nombre.ilike(f"%{q}%")) | (Usuario.email.ilike(f"%{q}%"))
            ).all()
        elif filtro == "pedidos":
            resultados = Pedido.query.join(Usuario).filter(
                (Pedido.id == q) |
                (Usuario.nombre.ilike(f"%{q}%")) |
                (Pedido.estado.ilike(f"%{q}%"))
            ).all()
        elif filtro == "productos":
            resultados = Producto.query.filter(
                (Producto.nombre.ilike(f"%{q}%")) |
                (Producto.descripcion.ilike(f"%{q}%"))
            ).all()
        else:
            usuarios = Usuario.query.filter(
                (Usuario.nombre.ilike(f"%{q}%")) | (Usuario.email.ilike(f"%{q}%"))
            ).all()
            pedidos = Pedido.query.join(Usuario).filter(
                (Pedido.id == q) |
                (Usuario.nombre.ilike(f"%{q}%")) |
                (Pedido.estado.ilike(f"%{q}%"))
            ).all()
            productos = Producto.query.filter(
                (Producto.nombre.ilike(f"%{q}%")) |
                (Producto.descripcion.ilike(f"%{q}%"))
            ).all()
            resultados = usuarios + pedidos + productos

    return render_template(
        'panel_admin.html',
        total_usuarios=total_usuarios,
        pedidos_activos=pedidos_activos,
        total_productos=total_productos,
        mensajes_pendientes=mensajes_pendientes,
        resultados=resultados,
        q=q,
        filtro=filtro
    )


@app.route('/publicar_productor/<int:productor_id>', methods=['POST'])
def publicar_productor(productor_id):
    productor = Productor.query.get_or_404(productor_id)
    # Cambia el estado booleano al contrario del actual
    productor.publicado = not productor.publicado
    db.session.commit()
    
    estado = "publicado" if productor.publicado else "ocultado"
    flash(f"El productor '{productor.nombre}' ha sido {estado}.", "success")
    
    return redirect(url_for('gestionar_productores'))

@app.route('/exportar_reporte')
def exportar_reporte():
    tipo = request.args.get('tipo')
    if not tipo:
        return "<h2 style='color:#c62828;text-align:center;margin-top:40px;'>Debes especificar el tipo de reporte (usuarios, pedidos o productos).</h2>", 400

    output = io.BytesIO()

    if tipo == 'usuarios':
        usuarios = Usuario.query.all()
        data = [{
            'ID': u.id,
            'Nombre': u.nombre,
            'Email': u.email,
            'Tipo de usuario': u.tipo_usuario
        } for u in usuarios]
        df = pd.DataFrame(data)
        filename = "usuarios.xlsx"

    elif tipo == 'pedidos':
        pedidos = Pedido.query.all()
        data = [{
            'ID': p.id,
            'Usuario': p.usuario_id,
            'Total': p.total,
            'Estado': p.estado,
            'Fecha': p.fecha.strftime('%d/%m/%Y %H:%M')
        } for p in pedidos]
        df = pd.DataFrame(data)
        filename = "pedidos.xlsx"

    elif tipo == 'productos':
        productos = Producto.query.all()
        data = [{
            'ID': prod.id,
            'Nombre': prod.nombre,
            'Descripción': prod.descripcion,
            'Precio': prod.precio,
            'Productor': prod.productor_id,
            'Categoría': prod.categoria_id,
            'Activo': prod.activo
        } for prod in productos]
        df = pd.DataFrame(data)
        filename = "productos.xlsx"

    else:
        return "<h2 style='color:#c62828;text-align:center;margin-top:40px;'>Tipo de reporte no válido.</h2>", 400

    df.to_excel(output, index=False)
    output.seek(0)
    return send_file(
        output,
        download_name=filename,
        as_attachment=True,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

# Ruta logout: POST, limpia sesión y redirige a login con headers anti-cache
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    session.clear()
    resp = redirect(url_for('login'))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@app.after_request
def add_security_headers(response):
    content_type = response.headers.get('Content-Type', '')
    if 'text/html' in content_type:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

@app.route('/carrito')
def carrito():
    if 'usuario_id' not in session:
        flash("⚠️ Debes iniciar sesión para ver tu carrito.", "error")
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    carrito_items = Carrito.query.filter_by(usuario_id=usuario_id).all()
    productos_en_carrito = []
    total = 0

    for item in carrito_items:
        producto = Producto.query.get(item.producto_id)
        if producto:
            producto.cantidad = item.cantidad  
            productos_en_carrito.append(producto)
            total += producto.precio * item.cantidad

    return render_template('carrito.html', productos=productos_en_carrito, total=total)


def calcular_total_carrito(usuario_id):
    carrito_items = Carrito.query.filter_by(usuario_id=usuario_id).all()
    if not carrito_items:
        return 0  
    total = sum(item.producto.precio * item.cantidad for item in carrito_items)
    return total

@app.route('/pago', methods=['GET', 'POST'])
def pago():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    carrito_items = Carrito.query.filter_by(usuario_id=usuario_id).all()
    if not carrito_items:
        flash("Tu carrito está vacío", "error")
        return redirect(url_for('carrito'))

    productos = []
    total = 0
    for item in carrito_items:
        producto = Producto.query.get(item.producto_id)
        if producto:
            producto.cantidad = item.cantidad
            productos.append(producto)
            total += producto.precio * item.cantidad

    if request.method == 'POST':
        nombre = request.form.get('nombre')
        correo = request.form.get('correo')
        direccion = request.form.get('direccion')
        codigo_postal = request.form.get('codigo_postal', '09500')

        if not all([nombre, correo, direccion]):
            flash("Por favor, completa todos los campos requeridos", "error")
            return redirect(url_for('pago'))

        try:
            nuevo_pedido = Pedido(
                usuario_id=usuario_id,
                total=total,
                estado='pendiente'
            )
            db.session.add(nuevo_pedido)
            db.session.flush()  # Para obtener el ID

            mp_token = app.config['MERCADOPAGO_ACCESS_TOKEN']
            sdk = mercadopago.SDK(mp_token)
            BASE_URL = "https://wepobo.pythonanywhere.com/"  

            preference_data = {
                "items": [
                    {
                        "title": f"Compra AgronoMia - {len(productos)} productos",
                        "quantity": 1,
                        "unit_price": float(total),
                        "currency_id": "MXN",
                        "description": "Productos agrícolas"
                    }
                ],
                "payer": {
                    "name": nombre.split()[0] if nombre else "Cliente",
                    "surname": " ".join(nombre.split()[1:]) if nombre and len(nombre.split()) > 1 else "Usuario",
                    "email": correo,
                },
                "shipments": {
                    "receiver_address": {
                        "zip_code": codigo_postal,
                        "street_name": direccion[:100] if direccion else "Av. Mexico",
                        "city": {"name": "Ciudad de México"},
                        "state": {"name": "Ciudad de México"},
                        "country": "MX"
                    }
                },
                "back_urls": {
                    "success": f"{BASE_URL}/pago/exitoso",
                    "failure": f"{BASE_URL}/pago/fallido", 
                    "pending": f"{BASE_URL}/pago/pendiente"
                },
                "auto_return": "approved",
                "external_reference": f"pedido_{nuevo_pedido.id}",
                "notification_url": f"{BASE_URL}/webhook/mercadopago",
            }

            for producto in productos:
                pedido_item = PedidoItem(
                    pedido_id=nuevo_pedido.id,
                    producto_id=producto.id,
                    cantidad=producto.cantidad
                )
                db.session.add(pedido_item)
            db.session.commit()

            preference_response = sdk.preference().create(preference_data)
            if preference_response["status"] in [200, 201]:
                preference = preference_response["response"]
                session['compra_pendiente'] = {
                    'pedido_id': nuevo_pedido.id,
                    'total': total,
                    'nombre': nombre,
                    'correo': correo,
                    'direccion': direccion,
                    'productos': [{'id': p.id, 'cantidad': p.cantidad} for p in productos],
                    'usuario_id': usuario_id
                }
                return redirect(preference["init_point"])
            else:
                error_msg = preference_response.get("response", {}).get("message", "Error desconocido")
                flash(f"Error al conectar con Mercado Pago: {error_msg}", "error")
                return redirect(url_for('pago'))

        except Exception as e:
            db.session.rollback()
            flash(f"Error al procesar el pago: {str(e)}", "error")
            return redirect(url_for('pago'))

    return render_template('metodos_pago.html', total=total)


@app.route('/historial_pedidos')
def historial_pedidos():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    pedidos = Pedido.query.filter_by(usuario_id=session['usuario_id']).order_by(Pedido.fecha.desc()).all()


    return render_template('historial_pedidos.html', pedidos=pedidos)


@app.route('/guardar_perfil', methods=['POST'])
def guardar_perfil():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    usuario = Usuario.query.get(usuario_id)

    usuario.nombre = request.form['nombre']
    usuario.email = request.form['email']

    if request.form['password'].strip():
        usuario.password = request.form['password']

    direccion_existente = Direccion.query.filter_by(usuario_id=usuario_id).first()
    if direccion_existente:
        direccion_existente.direccion = request.form['direccion']
    else:
        nueva_direccion = Direccion(usuario_id=usuario_id, direccion=request.form['direccion'])
        db.session.add(nueva_direccion)

    db.session.commit()

    flash("✔ Cambios guardados correctamente.", "success") 

    return redirect(url_for('perfil_cliente'))


@app.route('/registrar_productor', methods=['POST'])
def registrar_productor():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    nombre = request.form['nombre']
    email = request.form['email']
    descripcion = request.form['descripcion']
    ubicacion = request.form['ubicacion']

    imagen = request.files.get('imagen')
    imagen_nombre = None
    if imagen and imagen.filename:
        imagen_nombre = secure_filename(imagen.filename)
        imagen.save(os.path.join(app.config['UPLOAD_FOLDER'], imagen_nombre))

  
    productor = Productor.query.filter_by(email=email).first()
    if productor:
        productor.nombre = nombre
        productor.descripcion = descripcion
        productor.ubicacion = ubicacion
        productor.publicado = True  
        if imagen_nombre:
            productor.imagen = imagen_nombre
        db.session.commit()
        flash("✔ Perfil actualizado correctamente.", "success")
    else:
        nuevo_productor = Productor(
            nombre=nombre,
            email=email,
            descripcion=descripcion,
            ubicacion=ubicacion,
            imagen=imagen_nombre if imagen_nombre else "default.png",
            publicado=True  
        )
        db.session.add(nuevo_productor)
        db.session.commit()
        flash("✔ Perfil creado correctamente.", "success")

    return redirect(url_for('panel_productor'))

@app.route('/pedidos_productor')
def pedidos_productor():
    # 1. Verificar que el productor haya iniciado sesión
    if 'productor_id' not in session:
        flash("Inicie sesión como productor para ver sus pedidos.", "error")
        return redirect(url_for('login'))

    productor_id = session.get('productor_id')

    # 2. Consultar solo pedidos pendientes que contengan productos de este productor
    pedidos_query = db.session.query(Pedido).join(PedidoItem).join(Producto).filter(
        Producto.productor_id == productor_id,
        Pedido.estado == "Pendiente"
    ).distinct().order_by(Pedido.fecha.desc()).all()

    pedidos_filtrados = []
    for pedido in pedidos_query:
        # 3. Para cada pedido, calcular el resumen y total SOLO de sus productos
        items_del_productor = []
        total_para_productor = 0
        
        for item in pedido.items:
            # Comprobar si el producto en el item del pedido es del productor actual
            if item.producto.productor_id == productor_id:
                items_del_productor.append(f"{item.producto.nombre} (x{item.cantidad})")
                total_para_productor += item.producto.precio * item.cantidad
        
        # 4. Añadir la información procesada a la lista que se enviará a la plantilla
        if items_del_productor:
            pedido.cliente_nombre = pedido.usuario.nombre if pedido.usuario else 'Cliente Desconocido'
            direccion = Direccion.query.filter_by(usuario_id=pedido.usuario_id).first()
            pedido.direccion_entrega = direccion.direccion if direccion else "No registrada"
            
            pedido.productos_resumen = ', '.join(items_del_productor)
            pedido.total_para_productor = total_para_productor # Nuevo atributo con el total específico
            pedidos_filtrados.append(pedido)

    return render_template('pedidos_productor.html', pedidos=pedidos_filtrados)


def obtener_cantidad_carrito(usuario_id):
    cantidad = db.session.query(db.func.sum(Carrito.cantidad)).filter_by(usuario_id=usuario_id).scalar()
    return cantidad or 0

@app.route('/pedidos_cliente')
def pedidos_cliente():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    pedidos = Pedido.query.filter_by(usuario_id=session['usuario_id']).order_by(Pedido.fecha.desc()).all()
    cantidad_carrito = obtener_cantidad_carrito(session['usuario_id'])
    return render_template('pedidos_cliente.html', pedidos=pedidos, cantidad_carrito=cantidad_carrito)


@app.route('/gestion_usuarios')
def gestion_usuarios():
    usuarios = Usuario.query.all()  
    return render_template('gestion_usuarios.html', usuarios=usuarios)

@app.route('/eliminar_usuario/<int:user_id>', methods=['POST'])
def eliminar_usuario(user_id):
    usuario = Usuario.query.get(user_id)
    if usuario:
        db.session.delete(usuario)
        db.session.commit()
    return redirect(url_for('gestion_usuarios'))

@app.route('/editar_usuario/<int:user_id>', methods=['POST'])
def editar_usuario(user_id):
    usuario = Usuario.query.get_or_404(user_id)
    usuario.nombre = request.form['nombre']
    usuario.email = request.form['email']
    usuario.password = request.form['password']
    usuario.tipo_usuario = request.form['tipo_usuario']
    db.session.commit()
    flash("Usuario actualizado correctamente.", "success")
    return redirect(url_for('gestion_usuarios'))

@app.route('/admin_pedidos')
def admin_pedidos():
    pedidos = Pedido.query.all()  
    return render_template('admin_pedidos.html', pedidos=pedidos)

@app.route('/admin_productos')
def admin_productos():
    productos = Producto.query.all() 
    return render_template('admin_productos.html', productos=productos)



@app.route('/admin_productos_productor')
def admin_productos_productor():
    if 'usuario_id' not in session or session.get('tipo_usuario') != 'Productor':
        return redirect(url_for('login'))
    productor_id = session.get('productor_id')
    if not productor_id:
        flash("No se encontró el productor asociado a este usuario.", "error")
        return redirect(url_for('inicio'))
    
   
    productos = Producto.query.filter_by(productor_id=productor_id, activo=True).all()

   
    productos_eliminables = (
        Producto.query
        .filter_by(productor_id=productor_id, activo=True)
        .filter(
            exists().where(
                (PedidoItem.producto_id == Producto.id) &
                (PedidoItem.pedido_id == Pedido.id) &
                (Pedido.estado != 'Entregado')
            )
        )
        .all()
    )

    categorias = Categoria.query.all()
    return render_template(
        'admin_productos_productor.html',
        productos=productos,
        productos_eliminables=productos_eliminables,
        categorias=categorias
    )


@app.route('/agregar_producto', methods=['POST'])
def agregar_producto():
    if 'usuario_id' not in session or session.get('tipo_usuario') != 'Productor':
        return redirect(url_for('login'))

    productor_id = session.get('productor_id')
    if not productor_id:
        flash("✖ No se encontró el productor asociado a este usuario.", "error")
        return redirect(url_for('admin_productos_productor'))

    nombre = request.form['nombre']
    descripcion = request.form['descripcion']
    precio = float(request.form['precio'])
    categoria_id = int(request.form['categoria_id'])
    imagen = request.files['imagen']

    # Campos de semillas (maneja si están vacíos)
    tiempo_germinacion = request.form.get('tiempo_germinacion')
    epoca_siembra = request.form.get('epoca_siembra')
    cantidad_semillas = request.form.get('cantidad_semillas')

    filename = None
    if imagen and allowed_file(imagen.filename):
        filename = secure_filename(imagen.filename)
        imagen.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    nuevo_producto = Producto(
        nombre=nombre,
        descripcion=descripcion,
        precio=precio,
        categoria_id=categoria_id,
        imagen=filename,
        productor_id=productor_id,
        tiempo_germinacion=int(tiempo_germinacion) if tiempo_germinacion else None,
        epoca_siembra=epoca_siembra if epoca_siembra else None,
        cantidad_semillas=int(cantidad_semillas) if cantidad_semillas else None
    )
    db.session.add(nuevo_producto)
    db.session.commit()
    flash("✔ Producto agregado correctamente", "success") 
    return redirect(url_for('admin_productos_productor'))




@app.route('/editar_producto/<int:producto_id>', methods=['GET', 'POST'])
def editar_producto(producto_id):
    producto = Producto.query.get(producto_id)

    if request.method == 'POST':
        producto.nombre = request.form['nombre']
        producto.precio = float(request.form['precio'])
        db.session.commit()
        return redirect(url_for('admin_productos_productor'))

    return render_template('editar_producto.html', producto=producto)

@app.route('/eliminar_carrito/<int:producto_id>', methods=['POST'])
def eliminar_carrito(producto_id):
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    item = Carrito.query.filter_by(usuario_id=usuario_id, producto_id=producto_id).first()
    if item:
        db.session.delete(item)
        db.session.commit()
        flash("❌ Producto eliminado del carrito.", "info")
    else:
        flash("⚠️ El producto no estaba en el carrito.", "warning")

    return redirect(url_for('carrito'))

@app.route('/agregar_carrito/<int:producto_id>', methods=['POST'])
def agregar_carrito(producto_id):
    if 'usuario_id' not in session:
        flash("⚠️ Debes iniciar sesión para agregar productos al carrito.", "error")
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    producto = Producto.query.get(producto_id)

    if producto:
      
        item_en_carrito = Carrito.query.filter_by(usuario_id=usuario_id, producto_id=producto_id).first()

        if item_en_carrito:
            item_en_carrito.cantidad += 1 
        else:
            nuevo_item = Carrito(usuario_id=usuario_id, producto_id=producto_id, cantidad=1)
            db.session.add(nuevo_item)  

        try:
            db.session.commit()
            flash('✅ Producto agregado al carrito', 'success')
        except Exception as e:
            db.session.rollback()  
            flash(f"❌ Error al agregar producto al carrito: {str(e)}", "error")

    return redirect(url_for('productos'))


@app.route('/metodos_pago', methods=['GET', 'POST'])
def metodos_pago():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    tarjetas = Tarjeta.query.filter_by(usuario_id=usuario_id).all()
 
    tarjetas_json = [
        {
            "id": t.id,
            "numero": t.numero,
            "propietario": t.propietario,
            "fecha_expiracion": t.fecha_expiracion
        }
        for t in tarjetas
    ]
    return render_template('metodos_pago.html', tarjetas=tarjetas, tarjetas_json=tarjetas_json)


@app.route('/detalle_pedido/<int:pedido_id>')
def detalle_pedido(pedido_id):
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    pedido = Pedido.query.get_or_404(pedido_id)
    cantidad_carrito = obtener_cantidad_carrito(session['usuario_id'])
    return render_template('detalle_pedido.html', pedido=pedido, cantidad_carrito=cantidad_carrito)

@app.route('/quitar_carrito/<int:producto_id>', methods=['POST'])
def quitar_carrito(producto_id):
    if 'usuario_id' not in session:
        return redirect(url_for('login'))
    usuario_id = session['usuario_id']
    item = Carrito.query.filter_by(usuario_id=usuario_id, producto_id=producto_id).first()
    if item:
        db.session.delete(item)
        db.session.commit()
        flash('❌ Se eliminó el producto exitosamente', 'success')
    else:
        flash("⚠️ El producto no estaba en el carrito.", "warning")

    return redirect(url_for('carrito'))


@app.route('/marcar_entregado/<int:pedido_id>')
def marcar_entregado(pedido_id):
    pedido = Pedido.query.get_or_404(pedido_id)
    pedido.estado = "Entregado"
    db.session.commit()
    return redirect(url_for('pedidos_productor'))



@app.route('/eliminar_producto/<int:producto_id>', methods=['POST'])
def eliminar_producto(producto_id):
    producto = Producto.query.get_or_404(producto_id)
    
    PedidoItem.query.filter_by(producto_id=producto_id).delete()
   
    db.session.delete(producto)
    db.session.commit()
    flash('Producto eliminado correctamente.', 'success')
    return redirect(url_for('admin_productos_productor'))


@app.route('/actualizar_producto/<int:producto_id>', methods=['GET', 'POST'])
def actualizar_producto(producto_id):
    # --- Vista para el Productor ---
    producto = Producto.query.get_or_404(producto_id)
    # Valida que el producto pertenezca al productor en sesión
    if 'productor_id' not in session or producto.productor_id != session['productor_id']:
        flash("✖ No tienes permiso para editar este producto.", "error")
        return redirect(url_for('admin_productos_productor'))

    categorias = Categoria.query.all()
    if request.method == 'POST':
        # Actualización de datos básicos
        producto.nombre = request.form['nombre']
        producto.descripcion = request.form['descripcion']
        producto.precio = float(request.form['precio'])
        producto.categoria_id = int(request.form['categoria_id'])

        # Actualización de los nuevos campos para semillas
        producto.tiempo_germinacion = int(request.form.get('tiempo_germinacion')) if request.form.get('tiempo_germinacion') else None
        producto.epoca_siembra = request.form.get('epoca_siembra') if request.form.get('epoca_siembra') else None
        producto.cantidad_semillas = int(request.form.get('cantidad_semillas')) if request.form.get('cantidad_semillas') else None

        # Manejo de la imagen
        imagen = request.files.get('imagen')
        if imagen and allowed_file(imagen.filename):
            filename = secure_filename(imagen.filename)
            imagen.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            producto.imagen = filename
            
        db.session.commit()
        flash("✔ Producto actualizado correctamente.", "success")
        return redirect(url_for('admin_productos_productor'))
        
    return render_template('actualizar_producto_productor.html', producto=producto, categorias=categorias)


@app.route('/descargar_factura_pdf/<int:pedido_id>')
def descargar_factura_pdf(pedido_id):
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    pedido = Pedido.query.get_or_404(pedido_id)
    
    # Verificación de seguridad: el pedido debe pertenecer al usuario en sesión
    if pedido.usuario_id != session['usuario_id']:
        flash("No tienes permiso para descargar esta factura.", "error")
        return redirect(url_for('historial_pedidos'))

    # ... (el resto de tu lógica para generar el PDF sigue igual)
    items = PedidoItem.query.filter_by(pedido_id=pedido.id).all()
    productos = []
    for item in items:
        producto = Producto.query.get(item.producto_id)
        if producto:
            productos.append({
                'nombre': producto.nombre,
                'cantidad': item.cantidad,
                'precio': producto.precio,
                'subtotal': producto.precio * item.cantidad
            })
    
    total = pedido.total
    # ... (lógica de método de pago)
    metodo_pago_nombre = "Mercado Pago"

    html = render_template('factura_pdf.html', pedido=pedido, productos=productos, total=total, metodo_pago=metodo_pago_nombre)

    result = io.BytesIO()
    pisa.CreatePDF(html, dest=result)
    result.seek(0)
    return send_file(result, mimetype='application/pdf', as_attachment=True, download_name=f'factura_agronomia_{pedido.id}.pdf')

@app.route('/agregar_usuario', methods=['GET', 'POST'])
def agregar_usuario():
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email']
        password = request.form['password']
        tipo_usuario = request.form['tipo_usuario']
        nuevo_usuario = Usuario(nombre=nombre, email=email, password=password, tipo_usuario=tipo_usuario)
        db.session.add(nuevo_usuario)
        db.session.commit()
        flash("Usuario agregado correctamente.", "success")
        return redirect(url_for('gestion_usuarios'))
    return render_template('agregar_usuario.html')

@app.route('/eliminar_pedido/<int:pedido_id>', methods=['POST'])
def eliminar_pedido(pedido_id):
    pedido = Pedido.query.get_or_404(pedido_id)
    
    PedidoItem.query.filter_by(pedido_id=pedido.id).delete()
    db.session.delete(pedido)
    db.session.commit()
    flash("Pedido eliminado correctamente.", "success")
    return redirect(url_for('admin_pedidos'))


@app.route('/agregar_producto_productor', methods=['GET'])
def agregar_producto_productor():
    if 'usuario_id' not in session or session.get('tipo_usuario') != 'Productor':
        flash("✖ Acceso no autorizado.", "error")
        return redirect(url_for('login'))
    
    categorias = Categoria.query.all()
    return render_template('agregar_producto_productor.html', categorias=categorias)


@app.route('/agregar_producto_admin', methods=['GET', 'POST'])
def agregar_producto_admin():
    productores = Productor.query.all()
    categorias = Categoria.query.all()
    if request.method == 'POST':
        nombre = request.form['nombre']
        descripcion = request.form['descripcion']
        precio = float(request.form['precio'])
        imagen = request.files['imagen']
        productor_id = int(request.form['productor_id'])
        categoria_id = int(request.form['categoria_id'])
        
        # Nuevos campos para semillas (maneja valores vacíos)
        tiempo_germinacion = request.form.get('tiempo_germinacion')
        epoca_siembra = request.form.get('epoca_siembra')
        cantidad_semillas = request.form.get('cantidad_semillas')

        filename = None
        if imagen and allowed_file(imagen.filename):
            filename = secure_filename(imagen.filename)
            imagen.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        nuevo_producto = Producto(
            nombre=nombre,
            descripcion=descripcion,
            precio=precio,
            imagen=filename,
            productor_id=productor_id,
            categoria_id=categoria_id,
            # Asignación de nuevos campos
            tiempo_germinacion=int(tiempo_germinacion) if tiempo_germinacion else None,
            epoca_siembra=epoca_siembra if epoca_siembra else None,
            cantidad_semillas=int(cantidad_semillas) if cantidad_semillas else None
        )
        db.session.add(nuevo_producto)
        db.session.commit()
        flash("Producto agregado correctamente.", "success")
        return redirect(url_for('admin_productos'))
    return render_template('agregar_producto_admin.html', productores=productores, categorias=categorias)


@app.route('/actualizar_producto_admin/<int:producto_id>', methods=['GET', 'POST'])
def actualizar_producto_admin(producto_id):
    # --- Vista para el Administrador ---
    producto = Producto.query.get_or_404(producto_id)
    productores = Productor.query.all()
    categorias = Categoria.query.all()
    if request.method == 'POST':
        # Actualización de datos básicos
        producto.nombre = request.form['nombre']
        producto.descripcion = request.form['descripcion']
        producto.precio = float(request.form['precio'])
        producto.productor_id = int(request.form['productor_id'])
        producto.categoria_id = int(request.form['categoria_id'])

        # Actualización de los nuevos campos para semillas (maneja valores vacíos)
        producto.tiempo_germinacion = int(request.form.get('tiempo_germinacion')) if request.form.get('tiempo_germinacion') else None
        producto.epoca_siembra = request.form.get('epoca_siembra') if request.form.get('epoca_siembra') else None
        producto.cantidad_semillas = int(request.form.get('cantidad_semillas')) if request.form.get('cantidad_semillas') else None
        
        # Manejo de la imagen
        imagen = request.files.get('imagen')
        if imagen and allowed_file(imagen.filename):
            filename = secure_filename(imagen.filename)
            imagen.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            producto.imagen = filename
            
        db.session.commit()
        flash("✔ Producto actualizado correctamente.", "success")
        return redirect(url_for('admin_productos'))
        
    return render_template('actualizar_producto_admin.html', producto=producto, productores=productores, categorias=categorias)


@app.route('/eliminar_producto_admin/<int:producto_id>', methods=['POST'])
def eliminar_producto_admin(producto_id):
    producto = Producto.query.get_or_404(producto_id)
    
    PedidoItem.query.filter_by(producto_id=producto_id).delete()
   
    db.session.delete(producto)
    db.session.commit()
    flash("Producto eliminado permanentemente.", "success")
    return redirect(url_for('admin_productos'))

def enviar_email_ticket(destinatario, total, referencia):
    """Función para enviar un correo con los datos del ticket de pago."""
    msg = Message(
        subject='Instrucciones para tu pago en AgronoMia',
        recipients=[destinatario]
    )
    msg.html = render_template(
        'email_ticket.html',
        total=total,
        referencia=referencia
    )
    mail.send(msg)


   
    items = PedidoItem.query.filter_by(pedido_id=pedido.id).all()
    productos = []
    for item in items:
        producto = Producto.query.get(item.producto_id)
        if producto:
            productos.append({
                'nombre': producto.nombre,
                'cantidad': item.cantidad,
                'precio': producto.precio,
                'subtotal': producto.precio * item.cantidad
            })

    total = pedido.total

    datos = session.get('ticket_transferencia')
    if not datos:
        flash("Datos de transferencia no encontrados.", "error")
        return redirect(url_for('pago'))

    html = render_template('ticket_transferencia.html',
        pedido=pedido,
        numero_tarjeta=datos['numero_tarjeta'],
        propietario=datos['propietario'],
        productos=productos,
        total=total
    )
    result = io.BytesIO()
    pisa.CreatePDF(html, dest=result)
    result.seek(0)
    return send_file(result, mimetype='application/pdf', as_attachment=True, download_name='ticket_transferencia.pdf')

# --- FUNCIÓN AÑADIDA PARA VERIFICACIÓN DE CUENTA ---
def enviar_email_verificacion(usuario, token):
    """Envía un correo de verificación de cuenta."""
    msg = Message(
        subject='Verifica tu cuenta de AgronoMia',
        recipients=[usuario.email]
    )
    link = url_for('verificar_cuenta', token=token, _external=True)
    
    # --- PARA DEPURACIÓN EN LOCALHOST (MIRA TU TERMINAL) ---
    print("="*50)
    print(f"ENLACE DE VERIFICACIÓN (copia y pégalo en tu navegador):")
    print(link)
    print("="*50)
    # --------------------------------------------------------
    
    msg.html = render_template(
        'email_verificacion.html',
        nombre=usuario.nombre,
        link_verificacion=link
    )
    
    try:
        mail.send(msg)
        print(f"Correo de verificación enviado a {usuario.email}")
    except Exception as e:
        print(f"Error al enviar correo de verificación: {e}")
# --- FIN DE FUNCIÓN AÑADIDA ---

@app.route('/eliminar_tarjeta/<int:tarjeta_id>', methods=['POST'])
def eliminar_tarjeta(tarjeta_id):
    tarjeta = Tarjeta.query.get_or_404(tarjeta_id)
    if tarjeta.usuario_id == session['usuario_id']:
        db.session.delete(tarjeta)
        db.session.commit()
        flash("✔ Tarjeta eliminada correctamente.", "success")
    return redirect(url_for('panel_cliente'))

@app.route('/agregar_tarjeta', methods=['GET', 'POST'])
def agregar_tarjeta():
    if request.method == 'POST':
        numero = request.form['numero_tarjeta']
        propietario = request.form['propietario']
        fecha_expiracion = request.form['fecha_expiracion']
        try:
            nueva_tarjeta = Tarjeta(
                usuario_id=session['usuario_id'],
                numero=numero,
                propietario=propietario,
                fecha_expiracion=fecha_expiracion
            )
            db.session.add(nueva_tarjeta)
            db.session.commit()
            flash("✔ Tarjeta agregada exitosamente.", "success")
        except Exception as e:
            db.session.rollback()
            flash("✖ Ocurrió un error al agregar la tarjeta.", "error")
        return redirect(url_for('agregar_tarjeta'))
    return render_template('agregar_tarjeta.html')


@app.route('/desactivar_producto/<int:producto_id>', methods=['POST'])
def desactivar_producto(producto_id):
    producto = Producto.query.get_or_404(producto_id)
    producto.activo = False
    db.session.commit()
    flash('Producto desactivado correctamente.', 'success')
    return redirect(url_for('admin_productos_productor'))

@app.route('/desactivar_producto_admin/<int:producto_id>', methods=['POST'])
def desactivar_producto_admin(producto_id):
    producto = Producto.query.get_or_404(producto_id)
    producto.activo = False
    db.session.commit()
    flash('Producto desactivado correctamente.', 'success')
    return redirect(url_for('admin_productos'))


@app.route('/admin_mensajes')
def admin_mensajes():
    # Esta consulta ahora une las tablas Contacto y Usuario para obtener los datos del remitente
    mensajes = db.session.query(
        Contacto, 
        Usuario.nombre.label('usuario_nombre'), 
        Usuario.email.label('usuario_email')
    ).join(Usuario, Contacto.usuario_id == Usuario.id).order_by(Contacto.id.desc()).all()
    
    return render_template('admin_mensajes.html', mensajes=mensajes)

@app.route('/eliminar_mensaje/<int:mensaje_id>', methods=['POST'])
def eliminar_mensaje(mensaje_id):
    mensaje = Contacto.query.get_or_404(mensaje_id)
    db.session.delete(mensaje)
    db.session.commit()
    flash('Mensaje eliminado correctamente.', 'success')
    return redirect(url_for('admin_mensajes'))


@app.route('/responder_mensaje/<int:mensaje_id>', methods=['POST'])
def responder_mensaje(mensaje_id):
    mensaje = Contacto.query.get_or_404(mensaje_id)
    respuesta = request.form.get('respuesta')
    if respuesta:
        mensaje.respuesta = respuesta
        db.session.commit()
        flash('Respuesta enviada correctamente.', 'success')
    else:
        flash('La respuesta no puede estar vacía.', 'danger')
    return redirect(url_for('admin_mensajes'))

@app.route('/enviar_mensaje_cliente/<int:productor_id>/<int:producto_id>', methods=['GET', 'POST'])
@login_required
def enviar_mensaje_cliente(productor_id, producto_id):
    """
    Renderiza la interfaz de 'enviar_mensaje_cliente.html' para que un cliente
    inicie una conversación con un productor sobre un producto específico.
    """
    if session.get('tipo_usuario') != 'Cliente':
        flash("Acción no permitida.", "danger")
        return redirect(url_for('inicio'))
        
    producto = Producto.query.get_or_404(producto_id)

    if request.method == 'POST':
        contenido = request.form.get('contenido')
        if not contenido:
            flash("El mensaje no puede estar vacío.", "danger")
            return redirect(request.url)

        nuevo_mensaje = Mensaje(
            producto_id=producto_id,
            cliente_id=session['usuario_id'],
            productor_id=productor_id,
            remitente_tipo='cliente',
            contenido=contenido
        )
        db.session.add(nuevo_mensaje)
        db.session.commit()
        flash("Mensaje enviado correctamente al productor.", "success")
        return redirect(url_for('bandeja_mensajes_cliente'))

    # Para el método GET, renderizamos la plantilla que ya tienes
    return render_template('enviar_mensaje_cliente.html', producto=producto)

@app.route('/conversacion/cliente/<int:productor_id>/<int:producto_id>', methods=['GET', 'POST']) # <-- AÑADIR POST
@login_required
def conversacion_cliente(productor_id, producto_id):
    if session.get('tipo_usuario') != 'Cliente':
        return redirect(url_for('login'))

    cliente_id = session['usuario_id']
    producto = Producto.query.get_or_404(producto_id)

    # Lógica para cuando el cliente envía un mensaje (POST)
    if request.method == 'POST':
        contenido = request.form.get('contenido')
        if contenido:
            nuevo_mensaje = Mensaje(
                producto_id=producto_id,
                cliente_id=cliente_id,
                productor_id=productor_id,
                remitente_tipo='cliente', # <-- El remitente es el cliente
                contenido=contenido
            )
            db.session.add(nuevo_mensaje)
            db.session.commit()
            flash("Mensaje enviado.", "success")
        else:
            flash("El mensaje no puede estar vacío.", "danger")
        return redirect(url_for('conversacion_cliente', productor_id=productor_id, producto_id=producto_id))

    # Lógica para mostrar la conversación (GET)
    
    db.session.query(Mensaje).filter(
        Mensaje.cliente_id == cliente_id,
        Mensaje.productor_id == productor_id,
        Mensaje.producto_id == producto_id,
        Mensaje.remitente_tipo == 'productor'
    ).update({'leido': True})
    db.session.commit()
    
    mensajes = Mensaje.query.filter_by(
        cliente_id=session['usuario_id'],
        productor_id=productor_id,
        producto_id=producto_id,
        oculto_para_cliente=False # Asegurarse de no mostrar si se ocultó
    ).order_by(Mensaje.fecha.asc()).all()
    
    return render_template('enviar_mensaje_productor.html', 
                           mensajes=mensajes, 
                           producto=producto,
                           productor_id=productor_id,
                           cliente_id=cliente_id)
    
@app.route('/bandeja_mensajes_productor')
def bandeja_mensajes_productor():
    if 'productor_id' not in session or session.get('tipo_usuario') != 'Productor':
        return redirect(url_for('login'))

    productor_id = session['productor_id']
    ver_archivados = request.args.get('ver') == 'archivados'

    # Subconsulta para contar mensajes no leídos por conversación
    unread_count_subquery = db.session.query(
        Mensaje.cliente_id,
        Mensaje.producto_id,
        func.count(Mensaje.id).label('unread_count')
    ).filter(
        Mensaje.productor_id == productor_id,
        Mensaje.remitente_tipo == 'cliente',
        Mensaje.leido == False
    ).group_by(Mensaje.cliente_id, Mensaje.producto_id).subquery()
    
    # Consulta principal
    conversaciones = db.session.query(
        Mensaje.cliente_id,
        Mensaje.producto_id,
        Usuario.nombre.label('cliente_nombre'),
        Producto.nombre.label('producto_nombre'),
        func.coalesce(unread_count_subquery.c.unread_count, 0).label('unread_count')
    ).join(Usuario, Mensaje.cliente_id == Usuario.id)\
     .join(Producto, Mensaje.producto_id == Producto.id)\
     .outerjoin(unread_count_subquery, and_(
         Mensaje.cliente_id == unread_count_subquery.c.cliente_id,
         Mensaje.producto_id == unread_count_subquery.c.producto_id
     ))\
     .filter(Mensaje.productor_id == productor_id)\
     .filter(Mensaje.oculto_para_productor == ver_archivados)\
     .group_by(Mensaje.cliente_id, Mensaje.producto_id, Usuario.nombre, Producto.nombre, unread_count_subquery.c.unread_count).all()

    mensajes_admin = Contacto.query.filter_by(usuario_id=session['usuario_id']).order_by(Contacto.fecha.desc()).all()

    return render_template('bandeja_mensajes_productor.html', 
                           conversaciones=conversaciones,
                           mensajes_admin=mensajes_admin,
                           vista_archivados=ver_archivados)

@app.route('/desarchivar_conversacion/<int:id_uno>/<int:id_dos>', methods=['POST'])
@login_required
def desarchivar_conversacion(id_uno, id_dos):
    tipo_usuario = session.get('tipo_usuario')
    
    if tipo_usuario == 'Cliente':
        productor_id, producto_id = id_uno, id_dos
        db.session.query(Mensaje).filter_by(
            cliente_id=session['usuario_id'], productor_id=productor_id, producto_id=producto_id
        ).update({'oculto_para_cliente': False})
        db.session.commit()
        flash("Conversación restaurada.", "success")
        return redirect(url_for('bandeja_mensajes_cliente', ver='archivados'))

    elif tipo_usuario == 'Productor':
        cliente_id, producto_id = id_uno, id_dos
        db.session.query(Mensaje).filter_by(
            productor_id=session['productor_id'], cliente_id=cliente_id, producto_id=producto_id
        ).update({'oculto_para_productor': False})
        db.session.commit()
        flash("Conversación restaurada.", "success")
        return redirect(url_for('bandeja_mensajes_productor', ver='archivados'))

    return redirect(url_for('inicio'))

@app.route('/enviar_mensaje_productor', methods=['GET', 'POST'])
def enviar_mensaje_productor():
    if 'usuario_id' not in session or session.get('tipo_usuario') != 'Productor':
        return redirect(url_for('login'))
    if request.method == 'POST':
        mensaje = request.form.get('mensaje')
        if mensaje:
            nuevo_mensaje = Contacto(usuario_id=session['usuario_id'], mensaje=mensaje)
            db.session.add(nuevo_mensaje)
            db.session.commit()
            flash('Mensaje enviado correctamente.', 'success')
            return redirect(url_for('bandeja_mensajes_productor'))
        else:
            flash('El mensaje no puede estar vacío.', 'danger')
    return render_template('contacto.html')

@app.route('/conversacion/productor/<int:cliente_id>/<int:producto_id>', methods=['GET', 'POST']) # <-- AÑADIR POST
@login_required
def conversacion_productor(cliente_id, producto_id):
    if session.get('tipo_usuario') != 'Productor':
        return redirect(url_for('login'))

    productor_id = session['productor_id']
    producto = Producto.query.get_or_404(producto_id)

    # Lógica para cuando el productor envía un mensaje (POST)
    if request.method == 'POST':
        contenido = request.form.get('contenido')
        if contenido:
            nuevo_mensaje = Mensaje(
                producto_id=producto_id,
                cliente_id=cliente_id,
                productor_id=productor_id,
                remitente_tipo='productor', # <-- El remitente es el productor
                contenido=contenido
            )
            db.session.add(nuevo_mensaje)
            db.session.commit()
            flash("Respuesta enviada.", "success")
        else:
            flash("El mensaje no puede estar vacío.", "danger")
        # Redirigir a la misma página para recargar la conversación
        return redirect(url_for('conversacion_productor', cliente_id=cliente_id, producto_id=producto_id))

    # Lógica para mostrar la conversación (GET)
    db.session.query(Mensaje).filter(
        Mensaje.cliente_id == cliente_id,
        Mensaje.productor_id == productor_id,
        Mensaje.producto_id == producto_id,
        Mensaje.remitente_tipo == 'cliente'
    ).update({'leido': True})
    db.session.commit()
    
    
    mensajes = Mensaje.query.filter_by(
        cliente_id=cliente_id,
        productor_id=session['productor_id'],
        producto_id=producto_id,
        oculto_para_productor=False # Asegurarse de no mostrar si se ocultó
    ).order_by(Mensaje.fecha.asc()).all()
    
    return render_template('enviar_mensaje_cliente.html', 
                           mensajes=mensajes,
                           producto=producto,
                           productor_id=productor_id,
                           cliente_id=cliente_id)

@app.route('/bandeja_mensajes_cliente')
def bandeja_mensajes_cliente():
    if 'usuario_id' not in session or session.get('tipo_usuario') != 'Cliente':
        return redirect(url_for('login'))

    ver_archivados = request.args.get('ver') == 'archivados'

    # Subconsulta para contar mensajes no leídos por conversación
    unread_count_subquery = db.session.query(
        Mensaje.productor_id,
        Mensaje.producto_id,
        func.count(Mensaje.id).label('unread_count')
    ).filter(
        Mensaje.cliente_id == session['usuario_id'],
        Mensaje.remitente_tipo == 'productor',
        Mensaje.leido == False
    ).group_by(Mensaje.productor_id, Mensaje.producto_id).subquery()

    # Consulta principal que une la información de la conversación con el contador
    conversaciones_productor = db.session.query(
        Mensaje.productor_id,
        Mensaje.producto_id,
        Productor.nombre.label('productor_nombre'),
        Producto.nombre.label('producto_nombre'),
        func.coalesce(unread_count_subquery.c.unread_count, 0).label('unread_count')
    ).join(Productor, Mensaje.productor_id == Productor.id)\
     .join(Producto, Mensaje.producto_id == Producto.id)\
     .outerjoin(unread_count_subquery, and_(
        Mensaje.productor_id == unread_count_subquery.c.productor_id,
        Mensaje.producto_id == unread_count_subquery.c.producto_id
     ))\
     .filter(Mensaje.cliente_id == session['usuario_id'])\
     .filter(Mensaje.oculto_para_cliente == ver_archivados)\
     .group_by(Mensaje.productor_id, Mensaje.producto_id, Productor.nombre, Producto.nombre, unread_count_subquery.c.unread_count).all()

    mensajes_admin = Contacto.query.filter_by(usuario_id=session['usuario_id']).order_by(Contacto.fecha.desc()).all()
    
    return render_template('bandeja_mensajes_cliente.html', 
                           conversaciones_productor=conversaciones_productor, 
                           mensajes_admin=mensajes_admin,
                           vista_archivados=ver_archivados)


@app.route('/ocultar_conversacion/<int:id_uno>/<int:id_dos>', methods=['POST'])
@login_required
def ocultar_conversacion(id_uno, id_dos):
    tipo_usuario = session.get('tipo_usuario')
    
    if tipo_usuario == 'Cliente':
        productor_id, producto_id = id_uno, id_dos
        cliente_id = session['usuario_id']
        # Marcar todos los mensajes de esta conversación como ocultos para el cliente
        db.session.query(Mensaje).filter_by(
            cliente_id=cliente_id,
            productor_id=productor_id,
            producto_id=producto_id
        ).update({'oculto_para_cliente': True})
        db.session.commit()
        flash("Conversación archivada.", "success")
        return redirect(url_for('bandeja_mensajes_cliente'))

    elif tipo_usuario == 'Productor':
        cliente_id, producto_id = id_uno, id_dos
        productor_id = session['productor_id']
        # Marcar todos los mensajes de esta conversación como ocultos para el productor
        db.session.query(Mensaje).filter_by(
            cliente_id=cliente_id,
            productor_id=productor_id,
            producto_id=producto_id
        ).update({'oculto_para_productor': True})
        db.session.commit()
        flash("Conversación archivada.", "success")
        return redirect(url_for('bandeja_mensajes_productor'))

    return redirect(url_for('inicio'))

@app.route('/registro_admin', methods=['GET', 'POST'])
def registro_admin():
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email'].strip().lower()  
        password = request.form['password']


        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{8,}$", password):
            flash("La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un carácter especial.", "error")
            return redirect(url_for('registro_admin'))

        if Usuario.query.filter_by(email=email).first():
            return render_template('registro_admin.html', correo_duplicado=True, nombre=nombre, email=email)

        try:
            nuevo_usuario = Usuario(nombre=nombre, email=email, password=password, tipo_usuario="Productor")
            db.session.add(nuevo_usuario)
            db.session.commit()
 
            nuevo_productor = Productor(nombre=nombre, email=email)
            db.session.add(nuevo_productor)
            db.session.commit()
            return render_template('registro_admin.html', registro_exitoso=True)
        except Exception as e:
            db.session.rollback()
            return render_template('registro_admin.html', registro_fallido=True)

    return render_template('registro_admin.html')

@app.route('/registro_productores', methods=['GET', 'POST'])
def registro_productores():
    if request.method == 'POST':
        nombre = request.form['nombre']
        email = request.form['email'].strip().lower()  
        password = request.form['password']

        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{8,}$", password):
            flash("La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un carácter especial.", "error")
            return redirect(url_for('registro_productores'))

        if Usuario.query.filter_by(email=email).first():
            return render_template('registro_productores.html', correo_duplicado=True, nombre=nombre, email=email)

        try:
            # --- LÓGICA DE REGISTRO ACTUALIZADA ---
            token = secrets.token_urlsafe(32)
            expiracion = datetime.utcnow() + timedelta(hours=24) # 24 horas para verificar

            nuevo_usuario = Usuario(
                nombre=nombre, 
                email=email, 
                password=password, 
                tipo_usuario="Productor",
                is_verified=False, # <-- Se establece en Falso
                reset_token=token, # <-- Usamos el token para verificar
                reset_token_expiration=expiracion
            )
            db.session.add(nuevo_usuario)
            db.session.commit()
 
            nuevo_productor = Productor(nombre=nombre, email=email)
            db.session.add(nuevo_productor)
            db.session.commit()
            
            # Enviar el correo de verificación
            enviar_email_verificacion(nuevo_usuario, token)
            
            # Ya no se usa registro_exitoso=True
            flash("¡Registro casi listo! Revisa tu correo electrónico para verificar tu cuenta.", "success")
            return redirect(url_for('login'))
            # --- FIN DE LÓGICA ACTUALIZADA ---
            
        except Exception as e:
            db.session.rollback()
            print(f"Error en registro productor: {e}")
            return render_template('registro_productores.html', registro_fallido=True)

    return render_template('registro_productores.html')


@app.route('/perfil_productor')
def perfil_productor():
    if 'usuario_id' not in session or session.get('tipo_usuario') != 'Productor':
        return redirect(url_for('login'))
    
    productor_id = session.get('productor_id')
    productor = Productor.query.get_or_404(productor_id)
    
    return render_template('perfil_productor.html', productor=productor)

@app.route('/actualizar_perfil_productor', methods=['POST'])
def actualizar_perfil_productor():
    if 'usuario_id' not in session or session.get('tipo_usuario') != 'Productor':
        return redirect(url_for('login'))
    
    productor_id = session.get('productor_id')
    productor = Productor.query.get_or_404(productor_id)
    
    # Actualizar datos
    productor.nombre = request.form['nombre']
    productor.email = request.form['email']
    productor.ubicacion = request.form['ubicacion']
    productor.descripcion = request.form['descripcion']
    
    # Manejar imagen
    imagen = request.files.get('imagen')
    if imagen and imagen.filename:
        if allowed_file(imagen.filename):
            filename = secure_filename(imagen.filename)
            imagen.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            productor.imagen = filename
    
    db.session.commit()
    flash("Perfil actualizado correctamente", "success")
    return redirect(url_for('perfil_productor'))


@app.route('/gestionar_productores')
def gestionar_productores():
    productores = Productor.query.all()
    return render_template('gestionar_productores.html', productores=productores)


@app.route('/eliminar_productor/<int:productor_id>', methods=['POST'])
def eliminar_productor(productor_id):
    productor = Productor.query.get_or_404(productor_id)
    db.session.delete(productor)
    db.session.commit()
    flash("Productor eliminado correctamente.", "success")
    return redirect(url_for('gestionar_productores'))

@app.route('/editar_productor/<int:productor_id>', methods=['POST'])
def editar_productor(productor_id):
    productor = Productor.query.get_or_404(productor_id)
    productor.nombre = request.form['nombre']
    productor.email = request.form['email']
    productor.ubicacion = request.form.get('ubicacion', '')
    productor.descripcion = request.form.get('descripcion', '')

    # === LÓGICA PARA ACTUALIZAR LA IMAGEN ===
    imagen = request.files.get('imagen')
    if imagen and imagen.filename: # Verifica si se subió un archivo nuevo
        if allowed_file(imagen.filename):
            filename = secure_filename(imagen.filename)
            imagen.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            productor.imagen = filename # Actualiza el campo de la imagen
        else:
            flash("Tipo de archivo de imagen no permitido.", "error")
            return redirect(url_for('gestionar_productores'))
    # === FIN DE LA LÓGICA DE IMAGEN ===

    db.session.commit()
    flash("Productor actualizado correctamente.", "success")
    return redirect(url_for('gestionar_productores'))

@app.route('/actualizar_estado_pedido/<int:pedido_id>', methods=['POST'])
def actualizar_estado_pedido(pedido_id):
    pedido = Pedido.query.get_or_404(pedido_id)
    nuevo_estado = request.form.get('estado')
    if nuevo_estado:
        pedido.estado = nuevo_estado
        db.session.commit()
        flash("Estado del pedido actualizado correctamente.", "success")
    else:
        flash("No se recibió un estado válido.", "error")
    return redirect(url_for('admin_pedidos'))

@app.route('/pago/exitoso')
def pago_exitoso():
    payment_id = request.args.get('payment_id')
    external_reference = request.args.get('external_reference') # Ej: 'pedido_66'
    
    if not external_reference:
        flash("No se pudo confirmar el pedido.", "error")
        return redirect(url_for('carrito'))

    # --- INICIO DE LA CORRECCIÓN ---
    pedido = None
    try:
        # 1. Separamos el string por el guion bajo: ['pedido', '66']
        # 2. Tomamos el último elemento: '66'
        pedido_id_str = external_reference.split('_')[-1]
        
        # 3. Convertimos '66' a un entero
        pedido_id = int(pedido_id_str)
        
        # 4. Buscamos el pedido
        pedido = Pedido.query.get(pedido_id)
        
    except (ValueError, IndexError, TypeError):
        # Si algo falla (ej. la referencia no tiene '_', o no es un número)
        flash("Error al procesar la referencia del pedido.", "error")
        return redirect(url_for('carrito'))
    # --- FIN DE LA CORRECCIÓN ---

    if pedido:
        pedido.estado = 'aprobado'
        db.session.commit()
    
        # Mueve la limpieza del carrito aquí para que solo ocurra si el pedido se confirma
        Carrito.query.filter_by(usuario_id=current_user.id).delete()
        db.session.commit()
        
        flash("✅ Pago procesado exitosamente con Mercado Pago", "success")
        return redirect(url_for('historial_pedidos'))
    else:
        flash("No se encontró el pedido asociado al pago.", "error")
        return redirect(url_for('carrito'))

@app.route('/pago/fallido')
def pago_fallido():
    session.pop('compra_pendiente', None)
    flash("❌ El pago fue rechazado o falló", "error")
    return redirect(url_for('carrito'))


@app.route('/webhook/mercadopago', methods=['POST'])
def mp_webhook():
    try:
        data = request.json
        if data.get('type') == 'payment':
            payment_id = data['data']['id']
            sdk = mercadopago.SDK(app.config['MERCADOPAGO_ACCESS_TOKEN'])
            payment_info = sdk.payment().get(payment_id)
            if payment_info['response']['status'] == 'approved':
                pass
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"Error en webhook: {e}")
        return jsonify({"status": "error"}), 500

#rutas para accesibilidad
@app.route('/texto_a_voz', methods=['POST'])
def texto_a_voz():
    """Convierte texto a voz usando gTTS"""
    try:
        data = request.get_json()
        texto = data.get('texto', '')
        
        if not texto:
            return jsonify({'error': 'No se proporcionó texto'}), 400
        
        # Crear archivo de audio en memoria usando BytesIO
        tts = gTTS(text=texto, lang='es', slow=False)
        audio_buffer = BytesIO()
        tts.write_to_fp(audio_buffer)
        audio_buffer.seek(0)
        
        # Convertir a base64 para enviar al frontend
        audio_base64 = base64.b64encode(audio_buffer.read()).decode('utf-8')
        
        return jsonify({
            'audio': audio_base64,
            'status': 'success'
        })
        
    except Exception as e:
        print(f"Error en texto_a_voz: {e}")
        return jsonify({'error': 'Error al generar audio'}), 500

@app.route('/reproducir_audio', methods=['POST'])
def reproducir_audio():
    """Reproduce audio desde base64"""
    try:
        data = request.get_json()
        audio_base64 = data.get('audio', '')
        
        if not audio_base64:
            return jsonify({'error': 'No se proporcionó audio'}), 400
        
        # Decodificar base64 y reproducir
        audio_data = base64.b64decode(audio_base64)
        audio_buffer = BytesIO(audio_data)
        
        # Detener cualquier audio previo
        pygame.mixer.music.stop()
        
        # Cargar y reproducir nuevo audio
        pygame.mixer.music.load(audio_buffer)
        pygame.mixer.music.play()
        
        return jsonify({'status': 'reproduciendo'})
        
    except Exception as e:
        print(f"Error en reproducir_audio: {e}")
        return jsonify({'error': 'Error al reproducir audio'}), 500

@app.route('/detener_audio', methods=['POST'])
def detener_audio():
    """Detiene la reproducción de audio"""
    try:
        pygame.mixer.music.stop()
        return jsonify({'status': 'detenido'})
    except Exception as e:
        print(f"Error al detener audio: {e}")
        return jsonify({'error': 'Error al detener audio'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        crear_admin()  
        print("✅ Tablas creadas y administrador registrado 🚀")

    
    app.run(debug=True)