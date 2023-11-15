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


#--------------------------Criar Itens-------------------------------#
@app.route('/items', methods=['POST'])
def criar_itens():
    if 'name' not in session:
        return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

    user = User.query.filter_by(name=session['name']).first()
    if user.type != 'Vendedor':  # Alterado para verificar a string 'Vendedor'
        return jsonify({'message': 'Acesso restrito a vendedores!'})

    item_data = request.get_json()

    if all(key in item_data for key in
           ['title', 'author', 'category_id', 'price', 'description', 'status', 'date']):
        item = Item(
            title=item_data['title'],
            author=item_data['author'],
            category_id=item_data['category_id'],
            price=item_data['price'],
            description=item_data['description'],
            status=item_data['status'],
            date=item_data['date'],
            saller_id=user.id  # Usando o id do usuário logado
        )
        db.session.add(item)
        db.session.commit()

        return jsonify({'message': 'Item criado com sucesso!', 'title': item.title, 'author': item.author,
                        'category_id': item.category_id, 'price': item.price, 'description': item.description,
                        'status': item.status, 'date': item.date, 'saller_id': item.saller_id})

    return jsonify({'error': 'Verifique se os campos estão sendo inseridos corretamente!'})


#------------------------Listar Itens----------------------------------------#

@app.route('/items', methods=['GET'])
def mostrar_itens():
    if 'name' not in session:
        return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

    items = Item.query.all()
    items_json = [{'id': i.id, 'title': i.title, 'author': i.author, 'category_id': i.category_id, 'price': i.price,
                   'description': i.description, 'status': i.status, 'date': i.date, 'saller_id': i.saller_id} for i
                  in items]
    return jsonify(items_json)


#--------------------------Listar Item Específico--------------------------------------#

@app.route('/items/<int:id>', methods=['GET'])
def mostrar_item_especifico(id):
    if 'name' not in session:
        return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

    item = Item.query.get(id)
    if item:
        return jsonify({'id': item.id, 'title': item.title, 'author': item.author, 'category_id': item.category_id,
                        'price': item.price, 'description': item.description, 'status': item.status,
                        'date': item.date, 'saller_id': item.saller_id})

    return jsonify({'message': 'Item não encontrado!'})


#-------------------------Editar Item----------------------------------------#

@app.route('/items/<int:id>', methods=['PUT'])
def editar_item(id):
    if 'name' not in session:
        return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

    user = User.query.filter_by(name=session['name']).first()
    if user.type != 'Vendedor':  # Alterado para verificar a string
        return jsonify({'message': 'Acesso restrito a vendedores!'})

    item_data = request.get_json()
    item = Item.query.get(id)

    # Verifica se o item existe e se pertence ao usuário vendedor logado
    if item and item.saller_id == user.id:
        item.title = item_data.get('title', item.title)
        item.author = item_data.get('author', item.author)
        item.category_id = item_data.get('category_id', item.category_id)
        item.price = item_data.get('price', item.price)
        item.description = item_data.get('description', item.description)
        item.status = item_data.get('status', item.status)
        item.date = item_data.get('date', item.date)
        # Não atualiza o saller_id, pois ele não deve mudar

        db.session.commit()
        return jsonify({'message': 'Item editado com sucesso!'})

    elif not item:
        return jsonify({'message': 'Item não encontrado!'})
    else:
        return jsonify({'message': 'Você não tem permissão para editar este item!'})

#--------------------------Deletar Item-------------------------------------#

from flask import jsonify, request
from app import app, db
from models import User, Item

@app.route('/items/<int:id>', methods=['DELETE'])
def excluir_item(id):
    if 'name' not in session:
        return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

    user = User.query.filter_by(name=session['name']).first()
    if user.type != 'Vendedor':  # Verifica se o usuário é do tipo 'Vendedor'
        return jsonify({'message': 'Acesso restrito a vendedores!'})

    item = Item.query.get(id)

    if item and item.saller_id == user.id:  # Verifica se o item pertence ao usuário
        db.session.delete(item)
        db.session.commit()
        return jsonify({'message': 'Item excluído com sucesso!'})
    elif not item:
        return jsonify({'message': 'Item não encontrado!'})
    else:
        return jsonify({'message': 'Você não tem permissão para excluir este item!'})



#--------------------------Criar Categoria-----------------------------------------#

@app.route('/categories', methods=['POST'])
def criar_categoria():
    if 'name' not in session:
        return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

    user = User.query.filter_by(name=session['name']).first()
    if user.type != 'Vendedor':  # Alterado para verificar a string 'Vendedor'
        return jsonify({'message': 'Acesso restrito a vendedores!'})

    categoria_data = request.get_json()

    if 'name' in categoria_data and 'description' in categoria_data:
        categoria = Category(name=categoria_data['name'], description=categoria_data['description'])
        db.session.add(categoria)
        db.session.commit()

        return jsonify({'message': 'Categoria criada com sucesso!', 'category': categoria.name,
                        'description': categoria.description})

    return jsonify({'error': 'Verifique se os campos estão inseridos corretamente!'})



#--------------------------Editar Categoria------------------------------------#

@app.route('/categories/<int:id>', methods=['PUT'])
def editar_categoria(id):
    if 'name' not in session:
        return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

    user = User.query.filter_by(name=session['name']).first()
    if user.type != 'Vendedor':  # Alterado para verificar a string 'Vendedor'
        return jsonify({'message': 'Acesso restrito a vendedores!'})

    categoria_data = request.get_json()
    categoria = Category.query.get(id)

    if categoria:
        categoria.name = categoria_data.get('name', categoria.name)
        categoria.description = categoria_data.get('description', categoria.description)
        db.session.commit()

        return jsonify({'message': 'Categoria editada com sucesso!'})

    return jsonify({'message': 'Categoria não encontrada!'})


#--------------------------Listar Categoria--------------------------------------------#
@app.route('/categories/', methods=['GET'])
def mostrar_categoria():
    categorias = Category.query.all()
    categorias_json = [{'id': c.id, 'category': c.name, 'description': c.description} for c in categorias]
    return jsonify(categorias_json)


#--------------------------Deletar Categoria---------------------------------------#
@app.route('/categories/<int:id>', methods=['DELETE'])
def excluir_categoria(id):
    if 'name' not in session:
        return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

    user = User.query.filter_by(name=session['name']).first()
    if user.type != 'Vendedor':
        return jsonify({'message': 'Acesso restrito a vendedores!'})

    categoria = Category.query.get(id)
    if categoria:
        db.session.delete(categoria)
        db.session.commit()
        return jsonify({'message': 'Categoria excluída com sucesso!'})

    return jsonify({'message': 'Categoria não encontrada!'})

