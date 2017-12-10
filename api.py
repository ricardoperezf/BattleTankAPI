# BY RICARDO PÉREZ
# WEB SERVICES PROJECT #1 AND 2.
import os
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from flask_cors import CORS, cross_origin
import redis

# INITIALIZATION
app = Flask(__name__)
auth = HTTPBasicAuth()
CORS(app)
app.config['SECRET_KEY'] = 'abcdefghijklmnopqrstuvwxyz'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

db = SQLAlchemy(app)
r = redis.StrictRedis('localhost')

########################################################################################################################
#   VARIABLES GLOBALES

vector_position_tank = []
element_tank1 = {}
element_tank2 = {}
# VAR DE CANTIDAD DE VIDAS
life_tank2 = 3
life_tank1 = 3
# VECTOR DE VIDAS DEL TANK1 Y TANK2.
vector_lives_tank1 = [
    {
        'tank1': {
            'lives_t1': life_tank1,
            'percentage_t1': 100
        }
    }
]
element_lives_tank1 = {}
vector_lives_tank2 = [
    {
        'tank2': {
            'lives_t2': life_tank2,
            'percentage_t2': 100
        }
    }
]
element_lives_tank2 = {}
# VECTORES DE REDIS PARA LOG'S
logs_redis = []
vector_redis = []


########################################################################################################################
#   CLASE USER QUE PERMITIRÁ ALMACENAR EL REGISTRO DE USUARIOS CON EL USUARIO Y LA PASSWORD ENCRIPTADA.
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hashed = db.Column(db.String(64))

    # MÉTODO QUE SE ENCARGA DE VERIFICAR EL TOKEN SI HA EXPIRADO O INVALIDO, SINO ENTONCES LO DEVOLVERÁ CON EL USUARIO
    # QUE PERTENECE.
    @staticmethod
    def verification_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # EXPIRO.
        except BadSignature:
            return None  # INVALIDO.
        user = User.query.get(data['id'])
        return user

    def verify_password(self, password):  # VERIFY WITH THE PASSWORD ENCRYPTED.
        return pwd_context.verify(password, self.password_hashed)

    def token(self, expiration=900):  # GENERAR TOKEN CON EXPIRACIÓN DE 900s.
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    def hash(self, password):  # ENCRYPTAR LA CONTRASEÑA.
        self.password_hashed = pwd_context.encrypt(password)


# MÉTODO DE AUTH PARA VERFICAR USERNAME CON PASSWORD O TOKEN
@auth.verify_password
def verify_password(username_or_token, password):
    # BUSCA PRIMERO EL TOKEN SINO EXISTE ENTONCES TRATA DE BUSCARLO POR EL BASIC.
    user = User.verification_token(username_or_token)
    if not user:
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


# METODO PUBLICO QUE PERMITE REGISTRARSE CON UN USUARIO Y CONTRASEÑA.
@app.route('/api/users', methods=['POST'])
def register_new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    print("\n" + str(username) + " " + str(password) + "\n")
    if username is None or password is None:
        abort(400)  # MISSING USERNAME OR PASSWORD.
    if User.query.filter_by(username=username).first() is not None:
        abort(400)  # ALREADY EXISTING USER.
    user = User(username=username)
    user.hash(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'username': user.username}), 201


# MÉTODO PRIVADO DE INICIO DE SESIÓN PARA ENTRAR AL JUEGO.
@app.route('/api/resource')
@auth.login_required
def sign_in_game():
    return jsonify({'data': 'Hola, %s!!' % g.user.username})


# MÉTODO PRIVADO QUE PERMITE GENERAR UN TOKEN.
@app.route('/api/token')
@auth.login_required
def get_token():
    token = g.user.token()
    return jsonify({'token': token.decode('ascii')})


########################################################################################################################
#   LÓGICA DEL BACK-END EN QUE INVOLUCRA LAS POSICIONES DEL TANK 1 Y 2.
#   VIDAS DEL TANK1 Y 2.
#   LOG'S.

#   MÉTODO QUE PERMITE ENVIAR LA POSICIÓN ACTUAL Y RECIBIRLA DEL TANK2, ADEMÁS LA CANTIDAD DE VIDA ENVIARLA Y RECIBIRLA.
@app.route('/api/v1/users/tank', methods=['POST', 'GET'])
def position_tank():
    global vector_position_tank, element_tank1, element_tank2
    if request.method == "POST":
        json_data = request.get_json()

        x_position_tank1 = json_data['tank1']['x_t1']
        y_position_tank1 = json_data['tank1']['y_t1']

        x_position_tank2 = json_data['tank2']['x_t2']
        y_position_tank2 = json_data['tank2']['y_t2']

        element_tank1 = {
            'tank1': {
                'x': x_position_tank1,
                'y': y_position_tank1
            }
        }
        element_tank2 = {
            'tank2': {
                'x': x_position_tank2,
                'y': y_position_tank2
            }
        }
        # print("ELEMENTOS EN JSON")
        # print(element_tank1)
        # print(element_tank2)
        # print("\n")
        vector_position_tank.append(element_tank1)
        vector_position_tank.append(element_tank2)
        return jsonify("Playing!")
    else:
        return jsonify(vector_position_tank)


# MÉTODO QUE PERMITE RECIBIR LA CANTIDAD DE VIDA ACTUAL Y RECIBIRLA DEL TANK1, ADEMÁS ENVIARLA.
@app.route('/api/v1/users/tank/tank1/lives', methods=['POST', 'GET'])
def lives_tank1():
    global vector_lives_tank1, element_lives_tank1, life_tank1
    if request.method == "POST":
        json_data = request.get_json()

        percentage_life_tank1 = json_data['tank1']['percentage_t1']
        count_life_tank1 = json_data['tank1']['lives_t1']

        print("\n\n\n\n\n")
        print("T1 " + str(percentage_life_tank1) + " \t" + str(count_life_tank1))
        # RESTARLE UNA VIDA AL TANK1 O 2 POR CALIBRE ALTO RECIBIDO.
        if count_life_tank1 == 3 and percentage_life_tank1 == 100:
            life_tank1 -= 1

        # RESTARLE UNA VIDA AL TANK1 O 2 POR CALIBRE MEDIO (YA CUANDO SE HAYAN HECHO LOS DOS DISPAROS DE 50% DE DAÑO).
        if count_life_tank1 == 1 and percentage_life_tank1 == 100:
            life_tank1 -= 1

        # RESTARLE UNA VIDA AL TANK1 O 2 POR CALIBRE BAJO, YA CUANDO LLEGUE A 50 DISPAROS * 4 PARA PERDER LA VIDA.
        if count_life_tank1 == 0:
            life_tank1 = 0

        element_lives_tank1 = {
            'tank1': {
                'lives_t1': life_tank1,
                'percentage_t1': percentage_life_tank1
            }
        }

        print("VIDAS EN JSON")
        print(element_lives_tank1)
        print("\n\n\n")
        vector_lives_tank1.append(element_lives_tank1)
        return jsonify("Lives updated!")
    else:
        return jsonify(vector_lives_tank1)


# MÉTODO QUE PERMITE RECIBIR LA CANTIDAD DE VIDA ACTUAL Y RECIBIRLA DEL TANK2, ADEMÁS ENVIARLA.
@app.route('/api/v1/users/tank/tank2/lives', methods=['POST', 'GET'])
def lives_tank2():
    global vector_lives_tank2, element_lives_tank2, life_tank2
    if request.method == "POST":
        json_data = request.get_json()

        percentage_life_tank2 = json_data['tank2']['percentage_t2']
        count_life_tank2 = json_data['tank2']['lives_t2']
        print("\n\n\n\n\n")
        print("T2 " + str(percentage_life_tank2) + "\t" + str(count_life_tank2) + "\n\n")

        # RESTARLE UNA VIDA AL TANK1 O 2 POR CALIBRE ALTO RECIBIDO.
        if count_life_tank2 == 3 and percentage_life_tank2 == 100:
            life_tank2 -= 1

        # RESTARLE UNA VIDA AL TANK1 O 2 POR CALIBRE MEDIO (YA CUANDO SE HAYAN HECHO LOS DOS DISPAROS DE 50% DE DAÑO).
        if count_life_tank2 == 1 and percentage_life_tank2 == 100:
            life_tank2 -= 1

            # RESTARLE UNA VIDA AL TANK1 O 2 POR CALIBRE BAJO, YA CUANDO LLEGUE A 50 DISPAROS * 4 PARA PERDER LA VIDA.
        if count_life_tank2 == 0:
            life_tank2 = 0

        element_lives_tank2 = {
            'tank2': {
                'lives_t2': life_tank2,
                'percentage_t2': percentage_life_tank2
            }
        }
        print("VIDAS EN JSON")
        print(element_lives_tank2)
        print("\n\n\n")
        vector_lives_tank2.append(element_lives_tank2)
        return jsonify("Lives updated!")

    else:
        return jsonify(vector_lives_tank2)


# MÉTODO QUE PERMITE GUARDAR LOS LOG'S Y DEVOLVERLOS
@app.route('/api/v1/users/tank/logs', methods=['POST', 'GET'])
def logs():
    global vector_redis, logs_redis
    if request.method == "POST":
        json_data = request.get_json()
        event = json_data['event']
        logs_redis = "logsBattleTank"
        r.lpush(logs_redis, event)
        return "Log registred"
    else:
        logs = r.lrange(logs_redis, 0, -1)
        for log in logs:
            if "b'" in str(log):
                new_log = str(log).replace("b'", "")
            if "'" in new_log:
                new_log = str(new_log).replace("'", "")
            vector_redis.append({'event': new_log})
            print(new_log)
        return jsonify(vector_redis)


if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(host="0.0.0.0", port=5000)
