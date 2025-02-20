const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const serviceAccount = require("../serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore(); 

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "Todos los campos son obligatorios" });
    }

    const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "El formato del correo electrónico es inválido" });
    }

    const existingUser = await db.collection("users").where("email", "==", email).get();
    if (!existingUser.empty) {
      return res.status(400).json({ message: "El correo electrónico ya está registrado" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const userRecord = await admin.auth().createUser({
      email: email,
      password: password,
      displayName: username,
    });

    await db.collection("users").doc(userRecord.uid).set({
      email,
      username,
      last_login: admin.firestore.FieldValue.serverTimestamp(), 
      rol: "empleado", 
      password: hashedPassword, 
    });

    res.status(201).json({ message: "Usuario registrado exitosamente", uid: userRecord.uid });
  } catch (error) {
    console.error("Error al registrar usuario:", error);
    res.status(500).json({ message: error.message });
  }
});

require('dotenv').config();
const moment = require('moment');

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "El correo y la contraseña son obligatorios" });
    }

    const userSnapshot = await db.collection("users").where("email", "==", email).get();
    if (userSnapshot.empty) {
      return res.status(400).json({ message: "Correo electrónico no encontrado" });
    }

    const user = userSnapshot.docs[0].data();

    const passwordIsValid = await bcrypt.compare(password, user.password);
    if (!passwordIsValid) {
      return res.status(400).json({ message: "Contraseña incorrecta" });
    }

    const lastLogin = moment().format('D [de] MMMM [de] YYYY, h:mm:ss a'); 
    await db.collection("users").doc(userSnapshot.docs[0].id).update({ last_login: lastLogin });

    const expirationTime = 1 * 60; 
    const token = jwt.sign(
      { uid: userSnapshot.docs[0].id, email: user.email, username: user.username },
      process.env.JWT_SECRET, 
      { expiresIn: expirationTime }
    );

    res.status(200).json({ message: "Inicio de sesión exitoso", token });
  } catch (error) {
    console.error("Error al iniciar sesión:", error);
    res.status(500).json({ message: error.message });
  }
});

app.post("/api/record/tasks", async (req, res) => {
  try {
    const { name_task, description, dead_line, status, category, email } = req.body;

    if (!name_task || !status || !email) {
      return res.status(400).json({ message: "El nombre de la tarea, el estado y el correo electrónico son obligatorios" });
    }

    const newTask = {
      name_task,
      description,
      dead_line: dead_line ? new Date(dead_line) : null,
      status,
      category,
      email,
      created_at: admin.firestore.FieldValue.serverTimestamp(),
    };

    const taskRef = await db.collection("task").add(newTask);

    res.status(201).json({ message: "Tarea creada exitosamente", taskId: taskRef.id });
  } catch (error) {
    console.error("Error al crear la tarea:", error);
    res.status(500).json({ message: error.message });
  }
});

app.get("/api/tasks", async (req, res) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const email = decoded.email;

    const tasksSnapshot = await db.collection("task").where("email", "==", email).get();
    const tasks = tasksSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    res.status(200).json(tasks);
  } catch (error) {
    console.error("Error al obtener las tareas:", error);
    res.status(500).json({ message: error.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});