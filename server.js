const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
dotenv.config();

const app = express();
app.use(express.json());

// Simulação de banco de dados para usuários e alunos
const users = [];
const alunos = [];

// Middleware de autenticação JWT
const authenticateJWT = (req, res, next) => {
    const authHeader = req.header('Authorization');
    let token;

    if (authHeader) {
        const parts = authHeader.split(' ');
        if (parts.length === 2) {
            token = parts[1];
        }
    }

    if (!token) {
        return res.status(401).json({ message: "Acesso negado. Token não fornecido." });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            const errorMessage =
                err.name === 'TokenExpiredError' ? "Token expirado." :
                err.name === 'JsonWebTokenError' ? "Token inválido." :
                "Erro na verificação do token.";
            return res.status(403).json({ message: errorMessage });
        }

        req.user = user;
        next();
    });
};

// Rota para registro de usuários
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "Campos 'username' e 'password' são obrigatórios." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });

    res.status(201).json({ message: "Usuário registrado com sucesso." });
});

// Rota para login e geração de token
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(user => user.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: "Credenciais inválidas." });
    }

    const token = jwt.sign(
        { username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: '1h', algorithm: 'HS256' }
    );

    res.json({ token });
});

// Rotas protegidas
app.use(authenticateJWT);

// Rota para listar todos os alunos
app.get('/alunos', (req, res) => {
    res.json(alunos);
});

// Rota para listar nome e média de todos os alunos
app.get('/alunos/medias', (req, res) => {
    if (alunos.length === 0) {
        return res.status(404).json({ message: "Nenhum aluno cadastrado." });
    }

    const medias = alunos.map(aluno => ({
        nome: aluno.nome,
        media: ((aluno.nota1 + aluno.nota2) / 2).toFixed(2)
    }));

    res.json(medias);
});

// Rota para listar alunos aprovados ou reprovados
app.get('/alunos/aprovados', (req, res) => {
    if (alunos.length === 0) {
        return res.status(404).json({ message: "Nenhum aluno cadastrado." });
    }

    const aprovados = alunos.map(aluno => {
        const media = (aluno.nota1 + aluno.nota2) / 2;
        return {
            nome: aluno.nome,
            status: media >= 6 ? "aprovado" : "reprovado"
        };
    });

    res.json(aprovados);
});

// Rota para obter dados de um aluno específico
app.get('/alunos/:id', (req, res) => {
    const aluno = alunos.find(a => a.id === parseInt(req.params.id));
    if (!aluno) {
        return res.status(404).json({ message: "Aluno não encontrado." });
    }
    res.json(aluno);
});

// Rota para criar um novo aluno
app.post('/alunos', (req, res) => {
    const { id, nome, ra, nota1, nota2 } = req.body;

    if (!id || !nome || !ra || nota1 === undefined || nota2 === undefined) {
        return res.status(400).json({ message: "Todos os campos são obrigatórios." });
    }

    if (alunos.find(a => a.id === id)) {
        return res.status(400).json({ message: "Aluno com este ID já existe." });
    }

    alunos.push({ id, nome, ra, nota1: parseFloat(nota1), nota2: parseFloat(nota2) });
    res.status(201).json({ message: "Aluno criado com sucesso." });
});

// Rota para alterar dados de um aluno
app.put('/alunos/:id', (req, res) => {
    const aluno = alunos.find(a => a.id === parseInt(req.params.id));
    if (!aluno) {
        return res.status(404).json({ message: "Aluno não encontrado." });
    }

    const { nome, ra, nota1, nota2 } = req.body;
    if (nome) aluno.nome = nome;
    if (ra) aluno.ra = ra;
    if (nota1 !== undefined) aluno.nota1 = parseFloat(nota1);
    if (nota2 !== undefined) aluno.nota2 = parseFloat(nota2);

    res.json({ 
        message: "Aluno atualizado com sucesso.", 
        aluno: aluno 
    });
});


// Rota para deletar um aluno
app.delete('/alunos/:id', (req, res) => {
    const index = alunos.findIndex(a => a.id === parseInt(req.params.id));
    if (index === -1) {
        return res.status(404).json({ message: "Aluno não encontrado.", });
    }

    alunos.splice(index, 1);
    res.json({ message: "Aluno deletado com sucesso." });
});

// Iniciar o servidor
app.listen(3000, () => {
    console.log("Servidor rodando em http://localhost:3000");
});
