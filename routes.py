from flask import session, jsonify, request
from app import app, db, api
from models import Admin, Category, Transacao, User, Item
import bcrypt, re
from datetime import datetime
from flask_restx import Resource, fields, reqparse


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

        if User.query.filter_by(email=criar_user.get('email')).first():
            return jsonify({'error': 'Email já cadastrado!'})

        if not re.match(r"[^@]+@[^@]+\.[^@]+", criar_user.get('email', '')):
            return jsonify({'error': 'Formato de email inválido!'})

        if len(criar_user.get('password', '')) < 4:
            return jsonify({'error': 'A senha deve ter pelo menos 4 caracteres!'})

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
        'email': fields.String(required=True, description='Email do usuário'),
        'password': fields.String(required=True, description='Senha do usuário')
    })

    @api.doc(
        description="Efetua o login de um usuário. O usuário deve fornecer seu email e senha.",
        responses={
            200: 'Login feito com sucesso',
            401: 'Dados Inválidos'
        },
        body=user_login_model
    )
    def post(self):
        login = request.get_json()

        email = login.get('email')
        senha = login.get('password')

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.checkpw(senha.encode('utf-8'), user.password.encode('utf-8')):
            session['email'] = email

        if user and bcrypt.checkpw(senha.encode('utf-8'), user.password.encode('utf-8')):
            session['email'] = email
            return jsonify({'id': user.id, 'email': user.email, 'message': 'Login feito com sucesso!'})

        return jsonify({'message': 'Dados Inválidos!'})

# -------------------------Logout de usuario---------------------------------------------#
@api.route('/users/logout', methods=['POST'])
class LogoutUser(Resource):
    @api.doc(
        description="Efetua o logout do usuario(Comprador-Vendedor).",
        responses={
            200: 'Logout bem-sucedido',
            401: 'Não autorizado, nenhum usuário logado'
        })
    def post(self):
        if 'email' in session:
            session.pop('email', None)
            return jsonify({'message': 'Usuário saiu da sessão!'})

        return jsonify({'message': 'Nenhum usuário logado!'})


# -------------------------Editar Usuario--------------------------------------#
@api.route('/users/<int:id>', methods=['PUT'])
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
        if 'email' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.filter_by(email=session['email']).first()

        editar_user = request.get_json()
        user = User.query.get(id)

        if user:

            if 'email' in editar_user and not re.match(r"[^@]+@[^@]+\.[^@]+", editar_user['email']):
                return jsonify({'error': 'Formato de email inválido!'})

            if 'password' in editar_user and len(editar_user['password']) < 4:
                return jsonify({'error': 'A senha deve ter pelo menos 4 caracteres!'})

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
        if 'email' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.filter_by(email=session['email']).first()

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
            'status': fields.String(required=True, description='Status do item', enum=['Disponível', 'Vendido']),
            'date': fields.DateTime(description='Data de criação do item')
        })
    )
    def post(self):
        if 'email' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.filter_by(email=session['email']).first()
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

    @api.doc(
        description="Lista todos os itens",
        responses={
            200: 'Lista de itens retornada com sucesso',
            401: 'Não autorizado - necessário estar logado'
        }
    )
    def get(self):
        if 'email' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.filter_by(email=session['email']).first()

        items = Item.query.all()
        items_json = [{'id': i.id, 'title': i.title, 'author': i.author, 'category_id': i.category_id, 'price': i.price,
                       'description': i.description, 'status': i.status, 'date': i.date, 'saller_id': i.saller_id} for i
                      in items]
        return jsonify(items_json)

    # ------------------------Listar Itens por filtro----------------------------------------#


@api.route('/items/buscar', methods=['GET'])
class BuscarItems(Resource):
    @api.doc(
        description="Busca itens com base em um filtro genérico, que pode ser título, autor ou categoria",
        responses={
            200: 'Busca realizada com sucesso',
            400: 'Parâmetro de busca inválido'
        },
        params={
            'filtro': {
                'description': 'Filtro de busca (pode ser título, autor ou ID da categoria)',
                'in': 'query',
                'type': 'string',
                'required': True
            }
        }
    )
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument('filtro', type=str, required=True,
                            help='Filtro de busca (pode ser título, autor ou ID da categoria)')
        args = parser.parse_args()

        filtro = args['filtro']
        query = Item.query

        if filtro.isdigit():
            query = query.filter_by(category_id=int(filtro))
        else:

            filtro_like = f"%{filtro}%"
            query = query.filter(db.or_(Item.title.ilike(filtro_like), Item.author.ilike(filtro_like)))

        items = query.all()
        items_json = [{'id': i.id, 'title': i.title, 'author': i.author, 'category_id': i.category_id, 'price': i.price,
                       'description': i.description, 'status': i.status, 'date': i.date, 'saller_id': i.saller_id}
                      for i in items]

        return jsonify(items_json)
#------------------------------------Editar item, deletar item e listar item por id
@api.route('/items/<int:id>', methods=['PUT', 'DELETE', 'GET'])
class SpecificItemOperations(Resource):
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
            'status': fields.String(description='Status do item', enum=['Disponível', 'Vendido'])
        })
    )
    def put(self, id):
        if 'email' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.filter_by(email=session['email']).first()
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
        if 'email' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.filter_by(email=session['email']).first()
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
        if 'email' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.filter_by(email=session['email']).first()

        item = Item.query.get(id)
        if item:
            return jsonify(
                {'id': item.id, 'title': item.title, 'author': item.author, 'category_id': item.category_id,
                 'price': item.price, 'description': item.description, 'status': item.status,
                 'date': item.date, 'saller_id': item.saller_id})

        return jsonify({'message': 'Item não encontrado!'})


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
        if 'email' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.filter_by(email=session['email']).first()
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
        if 'email' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.filter_by(email=session['email']).first()
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
        if 'email' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        user = User.query.filter_by(email=session['email']).first()
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
        if 'email' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        comprador = User.query.filter_by(email=session['email']).first()
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
        if 'email' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        comprador = User.query.filter_by(email=session['email']).first()
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
        if 'email' not in session:
            return jsonify({'message': 'É necessário estar logado para utilizar esta função!'})

        vendedor = User.query.filter_by(email=session['email']).first()
        transacoes = Transacao.query.filter_by(vendedor_id=vendedor.id).all()
        transacoes_json = [{'id': t.id, 'item_id': t.item_id, 'valor': t.valor} for t in transacoes]
        return jsonify(transacoes_json)
