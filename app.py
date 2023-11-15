from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:135724655@localhost/ApiDw2_sebo'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.secret_key = os.environ.get('SECRET_KEY', 'Chave-secreta-xzc1225566898741aa')

db = SQLAlchemy(app)

def create_admin():
    with app.app_context():  # Adiciona o contexto da aplicação
        # Verifique se já existe um administrador
        if Admin.query.first() is None:
            senha = bcrypt.hashpw('senha'.encode('utf-8'), bcrypt.gensalt())
            admin = Admin(name='administrador', password=senha.decode('utf-8'), type='Admin')
            db.session.add(admin)
            db.session.commit()
            print("Administrador criado com sucesso.")
        else:
            print("Já existe um administrador.")

if __name__ == '__main__':
    with app.app_context():
        print("Dentro do contexto de aplicação Flask.")
        db.create_all()
        create_admin()
    app.run(port=5000, host='localhost', debug=True)

