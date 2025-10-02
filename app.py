# -*- coding: utf-8 -*-

# 1. Importações das bibliotecas necessárias
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt # Para criptografar senhas
from functools import wraps # Para proteger rotas

# 2. Inicialização do Flask App
app = Flask(__name__)

# 3. Configuração da Conexão com o Banco de Dados MySQL
#    !!!! IMPORTANTE: Substitua com suas credenciais do MySQL !!!!
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'lele_trab'      # Ex: 'root'
app.config['MYSQL_PASSWORD'] = 'lf28' # Ex: '12345'
app.config['MYSQL_DB'] = 'academia_db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor' # Retorna os resultados como dicionários

# 4. Chave Secreta para a Sessão
#    É necessária para o Flask gerenciar sessões e mensagens flash de forma segura.
app.secret_key = 'uma-chave-secreta'

# 5. Inicialização do MySQL
mysql = MySQL(app)

# --- DECORATOR PARA PROTEGER ROTAS ---
# Esta função verifica se um usuário está logado antes de permitir o acesso a uma página.
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Por favor, faça o login para acessar esta página.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROTAS DA APLICAÇÃO ---

# Rota Principal (Página Inicial)
@app.route('/')
def index():
    # Se o usuário já estiver logado, redireciona para o dashboard
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    # Caso contrário, mostra a página de login
    return redirect(url_for('login'))

# Rota de Cadastro de Usuário
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        # Pega os dados do formulário
        nome = request.form['nome']
        email = request.form['email']
        senha = request.form['senha']

        # Criptografa a senha antes de salvar no banco
        senha_hash = sha256_crypt.hash(senha)

        # Cria um cursor para interagir com o banco
        cur = mysql.connection.cursor()

        # Executa a query para inserir o novo usuário
        try:
            cur.execute("INSERT INTO usuarios(nome, email, senha) VALUES (%s, %s, %s)", (nome, email, senha_hash))
            # Salva a transação no banco
            mysql.connection.commit()
        except Exception as e:
            # Em caso de erro (ex: email já existe), desfaz a transação
            mysql.connection.rollback()
            flash('Erro ao cadastrar: O email informado já pode estar em uso.', 'danger')
            return render_template('cadastro.html')
        finally:
            # Fecha a conexão do cursor
            cur.close()

        flash('Cadastro realizado com sucesso! Faça o login para continuar.', 'success')
        return redirect(url_for('login'))

    return render_template('cadastro.html')

# Rota de Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha_candidata = request.form['senha']

        cur = mysql.connection.cursor()
        # Busca o usuário pelo email no banco
        result = cur.execute("SELECT * FROM usuarios WHERE email = %s", [email])

        if result > 0:
            # Pega os dados do usuário encontrado
            usuario = cur.fetchone()
            senha_hash = usuario['senha']

            # Compara a senha do formulário com a senha criptografada no banco
            if sha256_crypt.verify(senha_candidata, senha_hash):
                # Se a senha estiver correta, cria a sessão do usuário
                session['logged_in'] = True
                session['user_id'] = usuario['id']
                session['user_name'] = usuario['nome']

                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Senha incorreta
                flash('Senha inválida.', 'danger')
                return render_template('login.html')
        else:
            # Usuário não encontrado
            flash('Usuário não encontrado.', 'danger')
            return render_template('login.html')

    return render_template('login.html')

# Rota do Dashboard (Protegida)
@app.route('/dashboard')
@login_required
def dashboard():
    cur = mysql.connection.cursor()

    # Busca todos os treinos registrados PELO USUÁRIO LOGADO
    cur.execute("SELECT * FROM treinos WHERE usuario_id = %s ORDER BY data_treino DESC", [session['user_id']])
    treinos = cur.fetchall()
    cur.close()

    return render_template('dashboard.html', treinos=treinos, nome_usuario=session['user_name'])

# Rota para Adicionar um Novo Treino (Protegida)
@app.route('/adicionar_treino', methods=['GET', 'POST'])
@login_required
def adicionar_treino():
    if request.method == 'POST':
        # Pega os dados do formulário de treino
        nome_exercicio = request.form['nome_exercicio']
        peso = request.form['peso']
        series = request.form['series']
        repeticoes = request.form['repeticoes']
        usuario_id = session['user_id'] # Pega o ID do usuário logado

        cur = mysql.connection.cursor()
        # Insere o novo treino no banco, associado ao usuário correto
        cur.execute(
            "INSERT INTO treinos(usuario_id, nome_exercicio, peso_levantado_kg, series, repeticoes) VALUES (%s, %s, %s, %s, %s)",
            (usuario_id, nome_exercicio, peso, series, repeticoes)
        )
        mysql.connection.commit()
        cur.close()

        flash('Treino registrado com sucesso!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('adicionar_treino.html')


# Rota de Logout
@app.route('/logout')
@login_required
def logout():
    # Limpa os dados da sessão
    session.clear()
    flash('Você saiu da sua conta.', 'success')
    return redirect(url_for('login'))

# 6. Execução do Aplicativo
#    O bloco 'if' garante que o servidor só rode quando o script é executado diretamente.
if __name__ == '__main__':
    app.run(debug=True)

