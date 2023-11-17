from flask import session, jsonify, request
from app import app, db, api
from models import Admin, Category, Transacao, User, Item
import bcrypt
from datetime import datetime
from flask_restx import Resource, fields


# ---------------------Registrar Usuário-------------------------------------------------
@api.route('/users/signup', methods=['POST'])
class CriarUsuario(Resource):
    @api.doc(
        description="Cria um novo usuário",
        responses={
            201: 'Usuário criado com sucesso',
            400: 'Dados de entrada inválidos ou campos faltando'
        },
        body=api.model('CriarUsuarioModel', {
            'name': fields.String(required=True, description='Nome do usuário'),
            'email': fields.String(required=True, description='Email do usuário'),
            'password': fields.String(required=True, description='Senha do usuário'),
            'status': fields.String(required=True, description='Status do usuário'),
            'type': fields.String(required=True, description='Tipo do usuário', enum=['Comprador', 'Vendedor'])
        })
    )
    def post(self):
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

    # --------------------------Login de Usuario-----------------------------------------------#


@api.route('/users/login', methods=['POST'])
class LoginUsuario(Resource):
    user_login_model = api.model('UserLoginModel', {
        'name': fields.String(required=True, description='Nome do usuário'),
        'password': fields.String(required=True, description='Senha do usuário')
    })

    @api.doc(
        description="Efetua o login de um usuário. O usuário deve fornecer seu nome e senha.",
        responses={
            200: 'Login feito com sucesso',
            401: 'Dados Inválidos'
        },
        body=user_login_model  # Modelo para o corpo da requisição
    )
    def post(self):
        login = request.get_json()

        usuario = login.get('name')
        senha = login.get('password')

        user = User.query.filter_by(name=usuario).first()

        if user and bcrypt.checkpw(senha.encode('utf-8'), user.password.encode('utf-8')):
            session['name'] = usuario
            return jsonify({'id': user.id, 'user': user.name, 'message': 'Login feito com sucesso!'})

        return jsonify({'message': 'Dados Inválidos!'})


# -------------------------Logout de usuario---------------------------------------------#
@api.route('/users/logout', methods=['POST'])
class LogoutUser(Resource):
    @api.doc(responses={
        200: 'Logout bem-sucedido',
        401: 'Não autorizado, nenhum usuário logado'
    })
    def post(self):
        if 'name' in session:
            session.pop('name', None)
            return jsonify({'message': 'Usuário saiu da sessão!'})

        return jsonify({'message': 'Nenhum usuário logado!'})


# -------------------------Editar Usuario--------------------------------------#
@api.route('/users/<int:id>')
class UserOperations(Resource):
    @api.doc(
        description="Edita um usuário existente pelo ID",
        responses={
            200: 'Usuário editado com sucesso',
            401: 'Não autorizado - necessário estar logado',
            404: 'Usuário não encontrado'
        },
        params={'id': 'ID do usuário'},
        body=api.model('UserEditModel', {
            'name': fields.String(description='Nome do Usuário'),
            'email': fields.String(description='Email do Usuário'),
            'password': fields.String(description='Senha do Usuário'),
            'status': fields.String(description='Status do Usuário'),
            'type': fields.String(description='Tipo do Usuário', enum=['Comprador', 'Vendedor'])
        })
    )
    def put(self, id):

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

    # --------------------------Deletar Usuário------------------------------------------#
    @api.doc(
        description="Exclui um usuário pelo ID",
        responses={
            200: 'Usuário excluído com sucesso',
            401: 'Não autorizado - necessário estar logado',
            404: 'Usuário não encontrado'
        },
        params={'id': 'ID do usuário a ser excluído'}
    )
    def delete(self, id):
        if 'name' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.get(id)
        if user:
            db.session.delete(user)
            db.session.commit()
            return jsonify({'message': 'Usuário excluído com sucesso!'})

        return jsonify({'message': 'Usuário não encontrado!'})


# --------------------------Login de Admin----------------------------------------#

@api.route('/admin/login', methods=['POST'])
class LoginAdm(Resource):
    @api.doc(
        description="Efetua o login de um administrador",
        responses={
            200: 'Login feito com sucesso',
            401: 'Dados Inválidos'
        },
        body=api.model('LoginAdminModel', {
            'name': fields.String(required=True, description='Nome do administrador'),
            'password': fields.String(required=True, description='Senha do administrador')
        })
    )
    def post(self):
        login = request.get_json()
        administrador = login.get('name')
        senha = login.get('password')

        admin = Admin.query.filter_by(name=administrador).first()

        if admin and bcrypt.checkpw(senha.encode('utf-8'), admin.password.encode('utf-8')):
            session['name'] = administrador
            return jsonify({'id': admin.id, 'admin': admin.name, 'message': 'Login feito com sucesso!'})

        return jsonify({'message': 'Dados Inválidos!'})


# -------------------------Logout de Admin--------------------------------#
@api.route('/admin/logout', methods=['POST'])
class LogoutAdm(Resource):
    @api.doc(
        description="Efetua o logout de um administrador",
        responses={
            200: 'Logout de administrador bem-sucedido',
            401: 'Nenhum Administrador logado'
        }
    )
    def post(self):
        if 'name' in session:
            session.pop('name', None)
            return jsonify({'message': 'Administrador saiu da sessão!'})

        return jsonify({'message': 'Nenhum Administrador logado!'})


# -----------------------Listar Usuarios (compradores, vendedores)-------------------------------#
@api.route('/admin/users', methods=['GET'])
class MostarUser(Resource):
    @api.doc(
        description="Mostra a lista de todos os usuários",
        responses={
            200: 'Lista de usuários retornada com sucesso',
            401: 'Não autorizado - necessário estar logado como Admin'
        }
    )
    def get(self):
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


# --------------------------Criar Itens-------------------------------#
@api.route('/items', methods=['POST', 'GET'])
class ItemOperations(Resource):
    @api.doc(
        description="Cria um novo item",
        responses={
            201: 'Item criado com sucesso',
            401: 'Não autorizado - necessário estar logado como vendedor',
            400: 'Dados de entrada inválidos'
        },
        body=api.model('CriarItemModel', {
            'title': fields.String(required=True, description='Título do item'),
            'author': fields.String(required=True, description='Autor do item'),
            'category_id': fields.Integer(required=True, description='ID da categoria do item'),
            'price': fields.Float(required=True, description='Preço do item'),
            'description': fields.String(required=True, description='Descrição do item'),
            'status': fields.String(required=True, description='Status do item'),
            'date': fields.DateTime(description='Data de criação do item')
        })
    )
    def post(self):
        if 'name' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.filter_by(name=session['name']).first()
        if user.type != 'Vendedor':
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
                date=datetime.now(),
                saller_id=user.id
            )
            db.session.add(item)
            db.session.commit()

            return jsonify({'message': 'Item criado com sucesso!', 'title': item.title, 'author': item.author,
                            'category_id': item.category_id, 'price': item.price, 'description': item.description,
                            'status': item.status, 'date': item.date, 'saller_id': item.saller_id})

        return jsonify({'error': 'Verifique se os campos estão sendo inseridos corretamente!'})

    # ------------------------Listar Itens----------------------------------------#
    @api.doc(
        description="Lista todos os itens",
        responses={
            200: 'Lista de itens retornada com sucesso',
            401: 'Não autorizado - necessário estar logado'
        }
    )
    def get(self):
        if 'name' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        items = Item.query.all()
        items_json = [{'id': i.id, 'title': i.title, 'author': i.author, 'category_id': i.category_id, 'price': i.price,
                       'description': i.description, 'status': i.status, 'date': i.date, 'saller_id': i.saller_id} for i
                      in items]
        return jsonify(items_json)


# --------------------------Listar Item Específico--------------------------------------#

@api.route('/items/<int:id>', methods=['GET', 'PUT', 'DELETE'])
class SpecificItemOperations(Resource):
    @api.doc(
        description="Obtém detalhes de um item específico pelo ID",
        responses={
            200: 'Detalhes do item retornados com sucesso',
            401: 'Não autorizado - necessário estar logado',
            404: 'Item não encontrado'
        },
        params={'id': 'ID do item'}
    )
    def get(self, id):
        if 'name' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        item = Item.query.get(id)
        if item:
            return jsonify({'id': item.id, 'title': item.title, 'author': item.author, 'category_id': item.category_id,
                            'price': item.price, 'description': item.description, 'status': item.status,
                            'date': item.date, 'saller_id': item.saller_id})

        return jsonify({'message': 'Item não encontrado!'})


# -------------------------Editar Item----------------------------------------#
    @api.doc(
        description="Edita um item existente pelo ID",
        responses={
            200: 'Item editado com sucesso',
            401: 'Não autorizado - necessário estar logado como vendedor',
            403: 'Permissão negada - não é possível editar itens de outros vendedores',
            404: 'Item não encontrado'
        },
        params={'id': 'ID do item'},
        body=api.model('ItemEditModel', {
            'title': fields.String(description='Título do item'),
            'author': fields.String(description='Autor do item'),
            'category_id': fields.Integer(description='ID da categoria do item'),
            'price': fields.Float(description='Preço do item'),
            'description': fields.String(description='Descrição do item'),
            'status': fields.String(description='Status do item')
        })
    )
    def put(self, id):
        if 'name' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.filter_by(name=session['name']).first()
        if user.type != 'Vendedor':
            return jsonify({'message': 'Acesso restrito a vendedores!'})

        item_data = request.get_json()
        item = Item.query.get(id)

        if item and item.saller_id == user.id:
            item.title = item_data.get('title', item.title)
            item.author = item_data.get('author', item.author)
            item.category_id = item_data.get('category_id', item.category_id)
            item.price = item_data.get('price', item.price)
            item.description = item_data.get('description', item.description)
            item.status = item_data.get('status', item.status)
            item.date = item_data.get(datetime.now())

            db.session.commit()
            return jsonify({'message': 'Item editado com sucesso!'})

        elif not item:
            return jsonify({'message': 'Item não encontrado!'})
        else:
            return jsonify({'message': 'Você não tem permissão para editar este item!'})


# --------------------------Deletar Item-------------------------------------#
    @api.doc(
        description="Exclui um item pelo ID",
        responses={
            200: 'Item excluído com sucesso',
            401: 'Não autorizado - necessário estar logado como vendedor',
            403: 'Permissão negada - não é possível excluir itens de outros vendedores',
            404: 'Item não encontrado'
        },
        params={'id': 'ID do item a ser excluído'}
    )
    def delete(self, id):
        if 'name' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.filter_by(name=session['name']).first()
        if user.type != 'Vendedor':
            return jsonify({'message': 'Acesso restrito a vendedores!'})

        item = Item.query.get(id)

        if item and item.saller_id == user.id:
            db.session.delete(item)
            db.session.commit()
            return jsonify({'message': 'Item excluído com sucesso!'})
        elif not item:
            return jsonify({'message': 'Item não encontrado!'})
        else:
            return jsonify({'message': 'Você não tem permissão para excluir este item!'})


# --------------------------Criar Categoria-----------------------------------------#


@api.route('/categories', methods=['POST', 'GET'])
class CategoryOperations(Resource):
    @api.doc(
        description="Cria uma nova categoria",
        responses={
            201: 'Categoria criada com sucesso',
            401: 'Não autorizado - necessário estar logado como vendedor',
            400: 'Dados de entrada inválidos'
        },
        body=api.model('CriarCategoryModel', {
            'name': fields.String(required=True, description='Nome da categoria'),
            'description': fields.String(required=True, description='Descrição da categoria')
        })
    )
    def post(self):
        if 'name' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.filter_by(name=session['name']).first()
        if user.type != 'Vendedor':
            return jsonify({'message': 'Acesso restrito a vendedores!'})

        categoria_data = request.get_json()

        if 'name' in categoria_data and 'description' in categoria_data:
            categoria = Category(name=categoria_data['name'], description=categoria_data['description'])
            db.session.add(categoria)
            db.session.commit()

            return jsonify({'message': 'Categoria criada com sucesso!', 'category': categoria.name,
                            'description': categoria.description})

        return jsonify({'error': 'Verifique se os campos estão inseridos corretamente!'})

    @api.doc(
        description="Lista todas as categorias",
        responses={
            200: 'Lista de categorias retornada com sucesso',
            401: 'Não autorizado - necessário estar logado'
        }
    )
    def get(self):
        categorias = Category.query.filter_by(deleted=False).all()
        categorias_json = [{'id': c.id, 'category': c.name, 'description': c.description} for c in categorias]
        return jsonify(categorias_json)



# --------------------------Deletar Categoria---------------------------------------#
@api.route('/categories/<int:id>', methods=['DELETE', 'PUT'])
class SpecificCategoryOperations(Resource):
    @api.doc(
        description="Deleta uma categoria específica pelo ID",
        responses={
            200: 'Categoria deletada com sucesso',
            401: 'Não autorizado - necessário estar logado como vendedor',
            404: 'Categoria não encontrada'
        },
        params={'id': 'ID da categoria'}
    )
    def delete(self, id):
        if 'name' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.filter_by(name=session['name']).first()
        if user.type != 'Vendedor':
            return jsonify({'message': 'Acesso restrito a vendedores!'})

        categoria = Category.query.get(id)
        if categoria:
            categoria.deleted = True
            db.session.commit()
            return jsonify({'message': 'Categoria deletada com sucesso!'})

        return jsonify({'message': 'Categoria não encontrada!'})

    @api.doc(
        description="Edita uma categoria específica pelo ID",
        responses={
            200: 'Categoria editada com sucesso',
            401: 'Não autorizado - necessário estar logado como vendedor',
            404: 'Categoria não encontrada'
        },
        params={'id': 'ID da categoria'},
        body=api.model('CategoryEditModel', {
            'name': fields.String(description='Nome da categoria'),
            'description': fields.String(description='Descrição da categoria')
        })
    )
    def put(self, id):
        if 'name' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.filter_by(name=session['name']).first()
        if user.type != 'Vendedor':
            return jsonify({'message': 'Acesso restrito a vendedores!'})

        categoria_data = request.get_json()
        categoria = Category.query.get(id)

        if categoria:
            categoria.name = categoria_data.get('name', categoria.name)
            categoria.description = categoria_data.get('description', categoria.description)
            db.session.commit()

            return jsonify({'message': 'Categoria editada com sucesso!'})

        return jsonify({'message': 'Categoria não encontrada!'})
# -------------------------Criar transação-------------------------------------#


@api.route('/comprar/<int:item_id>', methods=['POST'])
class ComprarItem(Resource):
    @api.doc(
        description="Efetua a compra de um item pelo ID",
        responses={
            200: 'Item comprado com sucesso',
            401: 'Não autorizado - necessário estar logado para comprar itens',
            404: 'Item não encontrado',
            403: 'Item não está disponível para compra'
        },
        params={'item_id': 'ID do item a ser comprado'},
    )
    def post(self, item_id):
        if 'name' not in session:
            return jsonify({'message': 'É necessário estar logado para comprar itens!'})

        comprador = User.query.filter_by(name=session['name']).first()
        item = Item.query.get(item_id)

        if not item:
            return jsonify({'message': 'Item não encontrado!'})

        if item.status != 'Disponível':
            return jsonify({'message': 'Item não está disponível para compra!'})

        # Realizar a transação
        vendedor = User.query.get(item.saller_id)
        item.status = 'Vendido'
        item.date_vendido = datetime.now()

        # Registrar transação
        nova_transacao = Transacao(
            comprador_id=comprador.id,
            vendedor_id=vendedor.id,
            item_id=item_id,
            valor=item.price,
            data_transacao=datetime.now()
        )
        db.session.add(nova_transacao)
        db.session.commit()

        return jsonify({'message': 'Item comprado com sucesso!'})


# ---------------------------------- Transações de comprador


@api.route('/minhas_transacoes', methods=['GET'])
class ListarTransacoes(Resource):
    @api.doc(
        description="Lista todas as transações do usuário logado como comprador",
        responses={
            200: 'Lista de transações retornada com sucesso',
            401: 'Não autorizado - necessário estar logado'
        }
    )
    def get(self):

        if 'name' not in session:
            return jsonify({'message': 'É necessário estar logado para listar transações!'})

        comprador = User.query.filter_by(name=session['name']).first()
        transacoes = Transacao.query.filter_by(comprador_id=comprador.id).all()
        transacoes_json = [{'id': t.id, 'item_id': t.item_id, 'valor': t.valor} for t in transacoes]
        return jsonify(transacoes_json)


# ---------------------------------- Transações de vendedor


@api.route('/minhas_vendas', methods=['GET'])
class ListarVendas(Resource):
    @api.doc(
        description="Lista todas as vendas do usuário logado como vendedor",
        responses={
            200: 'Lista de vendas retornada com sucesso',
            401: 'Não autorizado - necessário estar logado'
        }
    )
    def get(self):
        if 'name' not in session:
            return jsonify({'message': 'É necessário estar logado para listar transações!'})

        vendedor = User.query.filter_by(name=session['name']).first()
        transacoes = Transacao.query.filter_by(vendedor_id=vendedor.id).all()
        transacoes_json = [{'id': t.id, 'item_id': t.item_id, 'valor': t.valor} for t in transacoes]
        return jsonify(transacoes_json)
