# Importações
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify  # Framework web e utilitários
from pymongo import MongoClient  # Cliente MongoDB
from bson.objectid import ObjectId  # Para trabalhar com IDs do MongoDB
from werkzeug.security import generate_password_hash, check_password_hash  # Segurança de senhas
import os  # Sistema operacional (para secret_key)
from datetime import datetime  # Manipulação de datas
import requests  # Requisições HTTP (para API ViaCEP)

app = Flask(__name__)  # Cria instância do Flask
app.secret_key = os.urandom(24)  # Chave secreta para sessões

# Conexão com MongoDB
client = MongoClient('mongodb://localhost:27017/')  # Conecta ao MongoDB local
db = client['ecommerce']  # Banco de dados 'ecommerce'

# Coleções (tabelas)
produtos_collection = db['produtos']  # Armazena produtos
users_collection = db['users']  # Armazena usuários
pedidos_collection = db['pedidos']  # Armazena pedidos
categorias_collection = db['categorias']  # Armazena categorias

# Configurações do app
app.config['FRETE_GRATIS_VALOR'] = 200.00  # Valor mínimo para frete grátis
app.config['VALOR_FRETE'] = 15.00  # Valor do frete normal

# Produtos que serão inseridos
produtos_exemplo = [
    {
        "nome": "God of War 1",
        "preco": 59.90,
        "estoque": 100,
        "categoria": "Games",
        "imagem": "https://upload.wikimedia.org/wikipedia/pt/5/53/God_of_War_2005_capa.png"
    },
    {
        "nome": "God of War 2",
        "preco": 69.00,
        "estoque": 50,
        "categoria": "Games",
        "imagem": "https://upload.wikimedia.org/wikipedia/pt/7/7e/God_of_War_2_capa.png"
    },
    {
        "nome": "God of War 3",
        "preco": 129.99,
        "estoque": 30,
        "categoria": "Games",
        "imagem": "https://upload.wikimedia.org/wikipedia/pt/6/6c/God_of_War_3_capa.png"
    },
    {
        "nome": "God of War",
        "preco": 200.00,
        "estoque": 10,
        "categoria": "Games",
        "imagem": "https://upload.wikimedia.org/wikipedia/pt/8/82/God_of_War_2018_capa.png"
    },
    {
        "nome": "God of War Ragnarok",
        "preco": 349.99,
        "estoque": 75,
        "categoria": "Games",
        "imagem": "https://upload.wikimedia.org/wikipedia/pt/thumb/a/a5/God_of_War_Ragnarök_capa.jpg/330px-God_of_War_Ragnarök_capa.jpg"
    },
    {
        "nome": "QCY T13",
        "preco": 189.90,
        "estoque": 200,
        "categoria": "Fones",
        "imagem": "https://qcy.com.br/cdn/shop/products/t13-black_1024x1024.png?v=1660932190"
    },
    {
        "nome": "QCY T20",
        "preco": 219.90,
        "estoque": 150,
        "categoria": "Fones",
        "imagem": "https://qcy.com.br/cdn/shop/products/t20-png_750x750.png?v=1660928804"
    },
   {
        "nome": "HT08® Pro",
        "preco": 309.90,
        "estoque": 300,
        "categoria": "Fones",
        "imagem": "https://qcy.com.br/cdn/shop/files/HT08-black2_1024x1024.png?v=1728267638"
    }, 
    {
        "nome": "GTR2®",
        "preco": 279.90,
        "estoque": 500,
        "categoria": "Fones",
        "imagem": "https://qcy.com.br/cdn/shop/files/05_black_750x750.png?v=1726158290"
    },
        {
        "nome": "GTS8®",
        "preco": 299.90,
        "estoque": 200,
        "categoria": "Fones",
        "imagem": "https://qcy.com.br/cdn/shop/files/gts8-1_750x750.png?v=1712718132"
    }, 
]

def initialize_db():
    # Inicializa o banco de dados com dados padrão
    if categorias_collection.count_documents({}) == 0:  # Verifica se não há categorias
        categorias_collection.insert_many([  # Insere categorias iniciais
            {"nome": "Games", "data_criacao": datetime.now()},  # Categoria de jogos
            {"nome": "Fones", "data_criacao": datetime.now()},  # Categoria de fones
        ])
        print("Categorias padrão inseridas")  # Log de confirmação
    
    if produtos_collection.count_documents({}) == 0:  # Verifica se não há produtos
        produtos_collection.insert_many(produtos_exemplo)  # Insere produtos de exemplo
        print("Produtos inseridos")  # Log de confirmação
    
    if users_collection.count_documents({"username": "admin"}) == 0:  # Verifica se admin existe
        users_collection.insert_one({  # Cria usuário admin padrão
            "username": "admin",  # Nome de usuário
            "email": "admin@example.com",  # Email padrão
            "password": generate_password_hash("admin123"),  # Senha criptografada
            "role": "admin",  # Perfil de administrador
            "data_cadastro": datetime.now(),  # Timestamp de criação
            "enderecos": []  # Lista de endereços vazia
        })
        print("Usuario Admin Criado")  # Log de confirmação
    
    # Cria usuário de exemplo para testes
if users_collection.count_documents({"username": "user1"}) == 0:  # Verifica se usuário já existe
    users_collection.insert_one({  # Insere novo usuário
        "username": "user1",  # Nome de usuário padrão
        "email": "user1@example.com",  # Email de exemplo
        "password": generate_password_hash("password123"),  # Senha criptografada
        "role": "user",  # Tipo de usuário normal (não admin)
        "data_cadastro": datetime.now(),  # Data/hora do cadastro
        "enderecos": []  # Lista vazia de endereços
    })
    print("Exemplo de usuário criado")  # Confirmação no console

# Função para adicionar novas categorias
def adicionar_categoria(nome_categoria):
    if not nome_categoria:  # Valida se o nome não está vazio
        return False, "Nome da categoria não pode ser vazio"
    
    if categorias_collection.count_documents({"nome": nome_categoria}) > 0:  # Verifica se categoria já existe
        return False, "Categoria já existe"
    
    categorias_collection.insert_one({  # Insere nova categoria
        "nome": nome_categoria,  # Nome da categoria
        "data_criacao": datetime.now()  # Data/hora de criação
    })
    return True, "Categoria adicionada com sucesso"  # Retorno de sucesso

def listar_categorias():
    return list(categorias_collection.find().sort("nome", 1))

def remover_categoria(nome_categoria):
    if produtos_collection.count_documents({"categoria": nome_categoria}) > 0:
        return False, "Não é possível remover: existem produtos nesta categoria"
    
    resultado = categorias_collection.delete_one({"nome": nome_categoria})
    if resultado.deleted_count > 0:
        return True, "Categoria removida com sucesso"
    return False, "Categoria não encontrada"

# Funções de gerenciamento de produto
def adicionar_produto(dados_produto):
    produto_existente = produtos_collection.find_one({"nome": dados_produto['nome']})
    if produto_existente:
        return False, "Produto com este nome já existe"
    
    # Verifica se a categoria existe, se não existir, cria
    if not categorias_collection.find_one({"nome": dados_produto['categoria']}):
        adicionar_categoria(dados_produto['categoria'])
    
    dados_produto['data_cadastro'] = datetime.now()
    produtos_collection.insert_one(dados_produto)
    return True, "Produto adicionado com sucesso"

def atualizar_produto_por_nome(nome_produto, novos_dados):
    if 'categoria' in novos_dados and not categorias_collection.find_one({"nome": novos_dados['categoria']}):
        return False, "Categoria não existe"
    
    # Atualiza produto e adiciona timestamp de modificação
    novos_dados['data_atualizacao'] = datetime.now()  # Registra data/hora da atualização
    resultado = produtos_collection.update_one(
    {"nome": nome_produto},  # Filtra por nome do produto
    {"$set": novos_dados}    # Aplica as novas informações
)
    return resultado.modified_count > 0  # Retorna True se houve alteração

# Remove produto pelo nome
def remover_produto_por_nome(nome_produto):
    resultado = produtos_collection.delete_one({"nome": nome_produto})  # Deleta o produto
    return resultado.deleted_count > 0  # Retorna True se deletou algo

# Busca um produto específico pelo nome
def buscar_produto_por_nome(nome_produto):
    return produtos_collection.find_one({"nome": nome_produto})  # Retorna o produto ou None

# Lista todos os produtos ordenados por data de cadastro (mais novos primeiro)
def listar_produtos():
    return list(produtos_collection.find().sort("data_cadastro", -1))  # -1 = ordem decrescente

# Lista produtos filtrados por categoria
def listar_produtos_por_categoria(categoria):
    return list(produtos_collection.find({"categoria": categoria}))  # Filtra por categoria

# Funções de gerenciamento de usuários
def registrar_usuario(username, email, password, endereco=None):
    # Verifica se usuário ou email já existem
    if users_collection.find_one({"$or": [{"username": username}, {"email": email}]}):
        return False, "Usuário ou email já existente"
    
    # Prepara dados do novo usuário
    user_data = {
        "username": username,
        "email": email,
        "password": generate_password_hash(password),  # Armazena senha criptografada
        "role": "user",  # Permissão padrão
        "data_cadastro": datetime.now(),  # Data de registro
        "enderecos": []  # Lista de endereços vazia
    }
    
    # Adiciona endereço se fornecido
    if endereco:
        user_data['enderecos'].append(endereco)
    
    # Insere usuário no banco
    users_collection.insert_one(user_data)
    return True, "Usuário registrado com sucesso"

# Adiciona endereço a um usuário existente
def adicionar_endereco_usuario(username, endereco):
    users_collection.update_one(
        {"username": username},  # Encontra usuário
        {"$push": {"enderecos": endereco}}  # Adiciona endereço ao array
    )

# Funções de estatísticas administrativas
def get_admin_stats():
    stats = {
        "total_produtos": produtos_collection.count_documents({}),  # Conta todos produtos
        "total_usuarios": users_collection.count_documents({"role": "user"}),  # Conta usuários comuns
        "total_pedidos": pedidos_collection.count_documents({}),  # Conta todos pedidos
        "pedidos_recentes": list(pedidos_collection.find().sort("data_pedido", -1).limit(5)),  # 5 últimos pedidos
        "produtos_baixo_estoque": list(produtos_collection.find({"estoque": {"$lt": 10}}).limit(5)),  # Produtos com menos de 10 unidades
        "ultimos_usuarios": list(users_collection.find({"role": "user"}).sort("data_cadastro", -1).limit(5)),  # 5 últimos usuários
        "categorias": [cat['nome'] for cat in categorias_collection.find()],  # Lista de categorias
        "receita_total": sum(pedido['total'] for pedido in pedidos_collection.find())  # Soma do valor de todos pedidos
    }
    return stats  # Retorna dicionário com todas estatísticas

# Rotas principais
@app.route('/')
def index():
    produtos = listar_produtos()
    categorias = [cat['nome'] for cat in categorias_collection.find()]
    return render_template('index.html', produtos=produtos, categorias=categorias)

@app.route('/categoria/<categoria>')
def produtos_por_categoria(categoria):
    produtos = listar_produtos_por_categoria(categoria)
    categorias = [cat['nome'] for cat in categorias_collection.find()]
    return render_template('index.html', produtos=produtos, categorias=categorias)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Por favor, preencha todos os campos', 'danger')
            return redirect(url_for('login'))
        
        user = users_collection.find_one({"$or": [{"username": username}, {"email": username}]})
        if user and check_password_hash(user['password'], password):
            session['user'] = user['username']
            session['role'] = user['role']
            session['email'] = user.get('email', '')
            flash('Login realizado com sucesso!', 'success')
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('index'))
        
        flash('Usuário ou senha incorretos', 'danger')
    
    return render_template('login.html')

@app.route('/registrar', methods=['GET', 'POST'])
def registrar():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        cep = request.form.get('cep')
        
        if not all([username, email, password, confirm_password]):
            flash('Por favor, preencha todos os campos obrigatórios', 'danger')
            return redirect(url_for('registrar'))
        
        if password != confirm_password:
            flash('As senhas não coincidem', 'danger')
            return redirect(url_for('registrar'))
        
        endereco = None
        if cep:
            try:
                response = requests.get(f'https://viacep.com.br/ws/{cep}/json/')
                data = response.json()
                if 'erro' not in data:
                    endereco = {
                        'cep': cep,
                        'rua': data.get('logradouro', ''),
                        'bairro': data.get('bairro', ''),
                        'cidade': data.get('localidade', ''),
                        'uf': data.get('uf', ''),
                        'principal': True
                    }
            except:
                pass
        
        success, message = registrar_usuario(username, email, password, endereco)
        if success:
            flash(message, 'success')
            return redirect(url_for('login'))
        flash(message, 'danger')
    
    return render_template('registrar.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Você foi deslogado', 'info')
    return redirect(url_for('index'))

# Rotas administrativas
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user' not in session or session.get('role') != 'admin':
        flash('Acesso não autorizado', 'danger')
        return redirect(url_for('login'))
    
    stats = get_admin_stats()
    produtos = listar_produtos()
    return render_template('admin/dashboard.html', produtos=produtos, stats=stats)

@app.route('/admin/produtos/adicionar', methods=['GET', 'POST'])
def adicionar_produto():
    if 'user' not in session or session.get('role') != 'admin':
        flash('Acesso não autorizado', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Obter dados do formulário
        nome = request.form['nome']
        preco = request.form['preco']
        estoque = request.form['estoque']
        categoria = request.form['categoria']
        nova_categoria = request.form.get('nova_categoria', '').strip()
        imagem = request.form['imagem']
        descricao = request.form.get('descricao', '')

        # Validar categoria
        if categoria == 'nova_categoria':
            if not nova_categoria:
                flash('Por favor, informe o nome da nova categoria', 'danger')
                return redirect(url_for('adicionar_produto'))
            
            # Verificar se categoria já existe
            if categorias_collection.find_one({'nome': nova_categoria}):
                flash('Esta categoria já existe', 'danger')
                return redirect(url_for('adicionar_produto'))
            
            # Criar nova categoria
            categorias_collection.insert_one({
                'nome': nova_categoria,
                'data_criacao': datetime.now()
            })
            categoria = nova_categoria
        
        # Validar outros campos
        if not all([nome, preco, estoque, categoria]):
            flash('Por favor, preencha todos os campos obrigatórios', 'danger')
            return redirect(url_for('adicionar_produto'))

        # Verificar se produto já existe
        if produtos_collection.find_one({'nome': nome}):
            flash('Já existe um produto com este nome', 'danger')
            return redirect(url_for('adicionar_produto'))

        # Criar novo produto
        produto = {
            'nome': nome,
            'preco': float(preco),
            'estoque': int(estoque),
            'categoria': categoria,
            'imagem': imagem or 'https://via.placeholder.com/150',
            'descricao': descricao,
            'data_cadastro': datetime.now()
        }

        produtos_collection.insert_one(produto)
        flash('Produto cadastrado com sucesso!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    # GET request - mostrar formulário
    categorias = [cat['nome'] for cat in categorias_collection.find().sort('nome', 1)]
    return render_template('admin/adicionar_produto.html', categorias=categorias)

@app.route('/admin/produtos/editar/<nome>', methods=['GET', 'POST'])
def editar_produto(nome):
    if 'user' not in session or session.get('role') != 'admin':
        flash('Acesso não autorizado', 'danger')
        return redirect(url_for('login'))
    
    produto = buscar_produto_por_nome(nome)
    if not produto:
        flash('Produto não encontrado', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        novos_dados = {
            "preco": float(request.form['preco']),
            "estoque": int(request.form['estoque']),
            "categoria": request.form['categoria'],
            "imagem": request.form['imagem'],
            "descricao": request.form.get('descricao', '')
        }
        
        if atualizar_produto_por_nome(nome, novos_dados):
            flash('Produto atualizado com sucesso', 'success')
        else:
            flash('Falha ao atualizar produto', 'danger')
        
        return redirect(url_for('admin_dashboard'))
    
    categorias = [cat['nome'] for cat in categorias_collection.find()]
    return render_template('admin/editar_produto.html', produto=produto, categorias=categorias)

@app.route('/admin/produtos/remover/<nome>')
def remover_produto(nome):
    if 'user' not in session or session.get('role') != 'admin':
        flash('Acesso não autorizado', 'danger')
        return redirect(url_for('login'))
    
    if remover_produto_por_nome(nome):
        flash('Produto removido com sucesso', 'success')
    else:
        flash('Produto não encontrado', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/usuarios')
def listar_usuarios():
    if 'user' not in session or session.get('role') != 'admin':
        flash('Acesso não autorizado', 'danger')
        return redirect(url_for('login'))
    
    usuarios = list(users_collection.find({"role": "user"}).sort("data_cadastro", -1))
    return render_template('admin/usuarios.html', usuarios=usuarios)

@app.route('/admin/pedidos')
def listar_pedidos():
    if 'user' not in session or session.get('role') != 'admin':
        flash('Acesso não autorizado', 'danger')
        return redirect(url_for('login'))
    
    pedidos = list(pedidos_collection.find().sort("data_pedido", -1))
    return render_template('admin/pedidos.html', pedidos=pedidos)

# Rotas para gerenciamento de categorias
@app.route('/admin/categorias')
def listar_categorias_admin():
    if 'user' not in session or session.get('role') != 'admin':
        flash('Acesso não autorizado', 'danger')
        return redirect(url_for('login'))
    
    categorias = list(categorias_collection.find().sort("nome", 1))
    return render_template('admin/categorias.html', categorias=categorias)

@app.route('/admin/categorias/adicionar', methods=['GET', 'POST'])
def adicionar_categoria_admin():
    if 'user' not in session or session.get('role') != 'admin':
        flash('Acesso não autorizado', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        nome_categoria = request.form.get('nome')
        success, message = adicionar_categoria(nome_categoria)
        flash(message, 'success' if success else 'danger')
        return redirect(url_for('listar_categorias_admin'))
    
    return render_template('admin/adicionar_categoria.html')

@app.route('/admin/categorias/remover/<nome>')
def remover_categoria_admin(nome):
    if 'user' not in session or session.get('role') != 'admin':
        flash('Acesso não autorizado', 'danger')
        return redirect(url_for('login'))
    
    success, message = remover_categoria(nome)
    flash(message, 'success' if success else 'danger')
    return redirect(url_for('listar_categorias_admin'))

# Rotas para carrinho e compras
@app.route('/adicionar_carrinho/<nome>')
def adicionar_carrinho(nome):
    if 'user' not in session:
        flash('Por favor, faça login para adicionar itens ao carrinho', 'warning')
        return redirect(url_for('login'))
    
    if 'carrinho' not in session:
        session['carrinho'] = []
    
    produto = buscar_produto_por_nome(nome)
    if produto:
        for item in session['carrinho']:
            if item['nome'] == nome:
                if item['quantidade'] + 1 > produto['estoque']:
                    flash('Quantidade solicitada maior que o estoque disponível', 'danger')
                    return redirect(url_for('index'))
                item['quantidade'] += 1
                session.modified = True
                flash('Quantidade do produto atualizada no carrinho', 'success')
                return redirect(url_for('index'))
        
        session['carrinho'].append({
            'nome': produto['nome'],
            'preco': produto['preco'],
            'imagem': produto['imagem'],
            'quantidade': 1,
            'produto_id': str(produto['_id'])
        })
        session.modified = True
        flash('Produto adicionado ao carrinho', 'success')
    
    return redirect(url_for('index'))

@app.route('/remover_carrinho/<nome>')
def remover_carrinho(nome):
    if 'user' not in session:
        flash('Por favor, faça login para gerenciar seu carrinho', 'warning')
        return redirect(url_for('login'))
    
    if 'carrinho' in session:
        session['carrinho'] = [item for item in session['carrinho'] if item['nome'] != nome]
        session.modified = True
        flash('Produto removido do carrinho', 'success')
    
    return redirect(url_for('ver_carrinho'))

@app.route('/atualizar-carrinho', methods=['POST'])
def atualizar_carrinho():
    if 'user' not in session:
        return jsonify({'error': 'Não autorizado'}), 401
    
    data = request.get_json()
    nome = data.get('nome')
    quantidade = int(data.get('quantidade', 1))
    
    if 'carrinho' not in session:
        return jsonify({'error': 'Carrinho vazio'}), 400
    
    produto = buscar_produto_por_nome(nome)
    if not produto:
        return jsonify({'error': 'Produto não encontrado'}), 404
    
    if quantidade > produto['estoque']:
        return jsonify({'error': 'Quantidade maior que estoque disponível'}), 400
    
    for item in session['carrinho']:
        if item['nome'] == nome:
            item['quantidade'] = quantidade
            session.modified = True
            break
    
    subtotal = sum(item['preco'] * item['quantidade'] for item in session['carrinho'])
    frete = session.get('frete', 0)
    total = subtotal + frete
    
    return jsonify({
        'success': True,
        'subtotal': subtotal,
        'frete': frete,
        'total': total,
        'carrinho': session['carrinho']
    })

@app.route('/carrinho')
def ver_carrinho():
    if 'user' not in session:
        flash('Por favor, faça login para ver seu carrinho', 'warning')
        return redirect(url_for('login'))
    
    carrinho = session.get('carrinho', [])
    subtotal = sum(item['preco'] * item['quantidade'] for item in carrinho)
    frete = session.get('frete', 0)
    total = subtotal + frete
    
    for item in carrinho:
        produto = produtos_collection.find_one({"_id": ObjectId(item['produto_id'])})
        if produto and item['quantidade'] > produto['estoque']:
            flash(f"Estoque insuficiente para {item['nome']}. Máximo disponível: {produto['estoque']}", 'warning')
    
    return render_template('carrinho.html', carrinho=carrinho, subtotal=subtotal, frete=frete, total=total)

@app.route('/calcular-frete', methods=['POST'])
def calcular_frete():
    if 'user' not in session:
        return jsonify({'error': 'Por favor, faça login para calcular o frete'}), 401
    
    cep = request.form.get('cep')
    if not cep or len(cep.replace('-', '')) != 8:
        return jsonify({'error': 'CEP inválido'}), 400
    
    try:
        response = requests.get(f'https://viacep.com.br/ws/{cep}/json/')
        data = response.json()
        
        if 'erro' in data:
            return jsonify({'error': 'CEP não encontrado'}), 404
        
        carrinho = session.get('carrinho', [])
        subtotal = sum(item['preco'] * item['quantidade'] for item in carrinho)
        
        if subtotal >= app.config['FRETE_GRATIS_VALOR']:
            frete = 0.00
            mensagem = "Parabéns! Frete grátis para sua compra!"
        else:
            frete = app.config['VALOR_FRETE']
            mensagem = f"Frete calculado para {data.get('localidade', 'sua região')}"
        
        session['frete'] = frete
        session['endereco_entrega'] = {
            'cep': cep,
            'rua': data.get('logradouro', ''),
            'bairro': data.get('bairro', ''),
            'cidade': data.get('localidade', ''),
            'uf': data.get('uf', ''),
            'complemento': request.form.get('complemento', '')
        }
        
        return jsonify({
            'success': True,
            'frete': frete,
            'subtotal': subtotal,
            'total': subtotal + frete,
            'mensagem': mensagem,
            'endereco': session['endereco_entrega']
        })
    
    except Exception as e:
        return jsonify({'error': f'Erro ao calcular frete: {str(e)}'}), 500

@app.route('/finalizar-compra', methods=['POST'])
def finalizar_compra():
    if 'user' not in session:
        flash('Por favor, faça login para finalizar a compra', 'warning')
        return redirect(url_for('login'))
    
    if not session.get('carrinho'):
        flash('Seu carrinho está vazio', 'warning')
        return redirect(url_for('ver_carrinho'))
    
    for item in session['carrinho']:
        produto = produtos_collection.find_one({"_id": ObjectId(item['produto_id'])})
        if not produto or item['quantidade'] > produto['estoque']:
            flash(f"Produto {item['nome']} não disponível na quantidade solicitada", 'danger')
            return redirect(url_for('ver_carrinho'))
    
    pedido = {
        "usuario": session['user'],
        "itens": session['carrinho'],
        "subtotal": sum(item['preco'] * item['quantidade'] for item in session['carrinho']),
        "frete": session.get('frete', 0),
        "total": sum(item['preco'] * item['quantidade'] for item in session['carrinho']) + session.get('frete', 0),
        "status": "pendente",
        "data_pedido": datetime.now(),
        "endereco_entrega": session.get('endereco_entrega', {})
    }
    
    try:
        pedidos_collection.insert_one(pedido)
        
        for item in session['carrinho']:
            produtos_collection.update_one(
                {"_id": ObjectId(item['produto_id'])},
                {"$inc": {"estoque": -item['quantidade']}}
            )
        
        endereco = session.get('endereco_entrega')
        if endereco:
            user = users_collection.find_one({"username": session['user']})
            if user and 'enderecos' in user:
                endereco_existente = any(addr['cep'] == endereco['cep'] for addr in user['enderecos'])
                if not endereco_existente:
                    adicionar_endereco_usuario(session['user'], endereco)
        
        session.pop('carrinho', None)
        session.pop('frete', None)
        session.pop('endereco_entrega', None)
        
        flash('Compra finalizada com sucesso! Obrigado por sua compra.', 'success')
        return redirect(url_for('index'))
    
    except Exception as e:
        flash(f'Erro ao finalizar compra: {str(e)}', 'danger')
        return redirect(url_for('ver_carrinho'))

@app.route('/toggle_dark_mode', methods=['POST'])
def toggle_dark_mode():
    if 'dark_mode' not in session:
        session['dark_mode'] = True
    else:
        session['dark_mode'] = not session['dark_mode']
    return jsonify({'success': True, 'dark_mode': session['dark_mode']})

if __name__ == '__main__':
    initialize_db()
    app.run(debug=True)