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


// Iniciar o servidor
app.listen(3000, () => {
    console.log("Servidor rodando em http://localhost:3000");
});
