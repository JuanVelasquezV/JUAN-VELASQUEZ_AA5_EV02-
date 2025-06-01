const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

const usuarios = [];

const SECRET = "clave_secreta";

// REGISTRO
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  usuarios.push({ username, password: hash });
  res.json({ mensaje: "Usuario registrado correctamente" });
});

// LOGIN
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const usuario = usuarios.find(u => u.username === username);
  if (!usuario || !(await bcrypt.compare(password, usuario.password))) {
    return res.status(401).json({ mensaje: "Credenciales inválidas" });
  }
  const token = jwt.sign({ username }, SECRET, { expiresIn: "1h" });
  res.json({ mensaje: "Login exitoso", token });
});

// PERFIL (requiere token)
app.get("/perfil", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split(" ")[1];
  if (!token) return res.status(401).json({ mensaje: "Token requerido" });

  try {
    const usuario = jwt.verify(token, SECRET);
    res.json({ mensaje: `Bienvenido ${usuario.username}`, usuario });
  } catch (err) {
    res.status(401).json({ mensaje: "Token inválido o expirado" });
  }
});

app.listen(3000, () => {
  console.log("Servidor corriendo en http://localhost:3000");
});
