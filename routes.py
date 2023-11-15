from flask import jsonify, request, session
from app import app, db
from models import User, Admin, Item, Category
import bcrypt

#---------------------Registrar Usuário-------------------------------------------------#
@app.route('/users/signup', methods=['POST'])
def criar_usuario():
    criar_user = request.get_json()

    if all(key in criar_user for key in ['name', 'email', 'password', 'status', 'type']):
        user_type = criar_user['type']

        if user_type not in ['Comprador', 'Vendedor']:
            return jsonify({'error': 'Tipo de usuário inválido!'})

        senha_criptografa = bcrypt.hashpw(criar_user['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user = User(name=criar_user['name'], email=criar_user['email'], password=senha_criptografa,
                    status=criar_user['status'], type=user_type)

        db.session.add(user)
        db.session.commit()

        return jsonify({'message': 'Usuário criado com sucesso!', 'user': user.name, 'email': user.email,
                        'status': user.status, 'type': user.type})

    return jsonify({'error': 'Verifique se os campos estão inseridos corretamente!'})



#--------------------------Login de Usuario-----------------------------------------------#
@app.route('/users/login', methods=['POST'])

def login_usuario():
    login = request.get_json()

    email = login.get('email')
    senha = login.get('password')

    user = User.query.filter_by(email=email).first()

    if user and bcrypt.checkpw(senha.encode('utf-8'), user.password.encode('utf-8')):
        session['email'] = email
        return jsonify({'id': user.id, 'user': user.name, 'message': 'Login feito com sucesso!'})

    return jsonify({'message': 'Dados Inválidos!'})


#-------------------------Logout de usuario---------------------------------------------#

@app.route('/users/logout', methods=['POST'])
def logout_usuario():
    if 'name' in session:
        session.pop('name', None)
        return jsonify({'message': 'Usuário saiu da sessão!'})

    return jsonify({'message': 'Nenhum usuário logado!'})


#-------------------------Editar Usuario--------------------------------------#
@app.route('/users/<int:id>', methods=['PUT'])
def editar_usuario(id):
    if 'name' not in session:
        return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

    editar_user = request.get_json()
    user = User.query.get(id)

    if user:
        user.name = editar_user.get('name', user.name)
        user.email = editar_user.get('email', user.email)

        if 'password' in editar_user:
            user.password = bcrypt.hashpw(editar_user['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        user.status = editar_user.get('status', user.status)

        if 'type' in editar_user:
            user_type = editar_user['type']
            if user_type not in ['Comprador', 'Vendedor']:
                return jsonify({'error': 'Tipo de usuário inválido!'})
            user.type = user_type

        db.session.commit()
        return jsonify({'message': 'Usuário editado com sucesso!'})

    return jsonify({'message': 'Usuário não encontrado!'})


#--------------------------Deletar Usuário------------------------------------------#
@app.route('/users/<int:id>', methods=['DELETE'])
def excluir_usuario(id):
    if 'name' not in session:
        return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

    user = User.query.get(id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'Usuário excluído com sucesso!'})

    return jsonify({'message': 'Usuário não encontrado!'})


#--------------------------Login de Admin----------------------------------------#

@app.route('/admin/login', methods=['POST'])
def login_admin():
    login = request.get_json()
    administrador = login.get('name')
    senha = login.get('password')

    # Buscar o administrador pelo nome
    admin = Admin.query.filter_by(name=administrador).first()

    # Verificar se o administrador existe e se a senha está correta
    if admin and bcrypt.checkpw(senha.encode('utf-8'), admin.password.encode('utf-8')):
        session['name'] = administrador
        return jsonify({'id': admin.id, 'admin': admin.name, 'message': 'Login feito com sucesso!'})

    return jsonify({'message': 'Dados Inválidos!'})



#-------------------------Logout de Admin--------------------------------#
@app.route('/admin/logout', methods=['POST'])
def logout_admin():
    if 'name' in session:
        session.pop('name', None)
        return jsonify({'message': 'Administrador saiu da sessão!'})

    return jsonify({'message': 'Nenhum Administrador logado!'})


#-----------------------Listar Usuarios (compradores, vendedores)-------------------------------#
@app.route('/admin/users', methods=['GET'])
def mostrar_usuario():
    if 'name' not in session:
        return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

    admin = Admin.query.filter_by(name=session['name']).first()
    if admin.type != 'Admin':
        return jsonify({'message': 'Acesso restrito a Admins!'})

    usuarios = User.query.all()
    usuarios_json = [
        {'id': u.id, 'user': u.name, 'email': u.email, 'password': u.password, 'status': u.status, 'type': u.type}
        for u in usuarios]
    return jsonify(usuarios_json)
