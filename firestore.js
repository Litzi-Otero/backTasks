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
      rol: "user", 
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
      { uid: userSnapshot.docs[0].id, email: user.email, username: user.username, rol: user.rol },
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

app.put("/api/edit/tasks/:id", async (req, res) => {
  try {
    const taskId = req.params.id;
    const { name_task, description, dead_line, status, category, email } = req.body;

    if (!name_task || !status || !email) {
      return res.status(400).json({ message: "El nombre de la tarea, el estado y el correo electrónico son obligatorios" });
    }

    const updatedTask = {
      name_task,
      description,
      dead_line: dead_line ? new Date(dead_line) : null,
      status,
      category,
      email,
      updated_at: admin.firestore.FieldValue.serverTimestamp(),
    };

    const taskRef = db.collection("task").doc(taskId);
    await taskRef.update(updatedTask);

    const updatedTaskSnapshot = await taskRef.get();
    const updatedTaskData = updatedTaskSnapshot.data();

    res.status(200).json({ id: taskId, ...updatedTaskData });
  } catch (error) {
    console.error("Error al actualizar la tarea:", error);
    res.status(500).json({ message: error.message });
  }
});

app.delete("/api/delete/tasks/:id", async (req, res) => {
  try {
    const taskId = req.params.id;
    const taskRef = db.collection("task").doc(taskId);
    await taskRef.delete();
    res.status(200).json({ message: "Tarea eliminada exitosamente" });
  } catch (error) {
    console.error("Error al eliminar la tarea:", error);
    res.status(500).json({ message: error.message });
  }
});

app.get("/api/users", async (req, res) => {
  try {
    // Obtener todos los usuarios
    const usersSnapshot = await db.collection("users").get();
    const users = usersSnapshot.docs.map(doc => doc.data());

    // Obtener todos los grupos
    const groupsSnapshot = await db.collection("group").get();
    const groups = groupsSnapshot.docs.map(doc => doc.data());

    // Obtener una lista de todos los correos electrónicos de los miembros de los grupos
    const usersInGroups = groups.flatMap(group => group.members);

    // Filtrar los usuarios que no están en ningún grupo
    const availableUsers = users.filter(user => !usersInGroups.includes(user.email));

    res.status(200).json(availableUsers);
  } catch (error) {
    console.error("Error al obtener los usuarios:", error);
    res.status(500).json({ message: error.message });
  }
});

app.post("/api/create/groups", async (req, res) => {
  try {
    const { name, description, created_by, members } = req.body;

    if (!name || !created_by || !members) {
      return res.status(400).json({ message: "El nombre del grupo, el creador y los miembros son obligatorios" });
    }

    const newGroup = {
      name,
      description,
      created_by,
      members,
      created_at: admin.firestore.FieldValue.serverTimestamp(),
    };

    const groupRef = await db.collection("group").add(newGroup);

    res.status(201).json({ id: groupRef.id, ...newGroup });
  } catch (error) {
    console.error("Error al crear el grupo:", error);
    res.status(500).json({ message: error.message });
  }
});

app.get("/api/groups", async (req, res) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const email = decoded.email;

    const groupsSnapshot = await db.collection("group").where("created_by", "==", email).get();
    const groups = groupsSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    res.status(200).json(groups);
  } catch (error) {
    console.error("Error al obtener los grupos:", error);
    res.status(500).json({ message: error.message });
  }
});

app.get("/api/user/group", async (req, res) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const email = decoded.email;

    const groupsSnapshot = await db.collection("group").where("members", "array-contains", email).get();
    if (!groupsSnapshot.empty) {
      const group = groupsSnapshot.docs[0].data();
      res.status(200).json({ group });
    } else {
      res.status(200).json({ group: null });
    }
  } catch (error) {
    console.error("Error al obtener el grupo del usuario:", error);
    res.status(500).json({ message: error.message });
  }
});

app.post("/api/record/user/task", async (req, res) => {
  try {
    console.log("Solicitud recibida para asignar tarea:", req.body);

    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      console.error("No se proporcionó token");
      return res.status(401).json({ message: "No autorizado" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Usuario autenticado:", decoded.email);

    const { name_task, description, dead_line, status, category, email, groupName } = req.body;
    if (!name_task || !email || !groupName) {
      console.error("Datos faltantes:", req.body);
      return res.status(400).json({ message: "Faltan campos obligatorios" });
    }

    const newTask = {
      name_task,
      description,
      dead_line: dead_line ? new Date(dead_line) : null,
      status,
      category,
      assigned_to: email,
      group: groupName, 
      created_by: decoded.email,
      created_at: new Date(),
    };

    console.log("Insertando tarea en la base de datos:", newTask);

    const taskRef = await db.collection("task").add(newTask);
    const task = await taskRef.get();

    console.log("Tarea creada con ID:", task.id);

    res.status(201).json({ id: task.id, ...task.data() });
  } catch (error) {
    console.error("Error al crear la tarea:", error.message);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

app.get("/api/user/group/tasks", async (req, res) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const email = decoded.email;

    const tasksSnapshot = await db.collection("task").where("assigned_to", "==", email).get();
    const tasks = tasksSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    res.status(200).json(tasks);
  } catch (error) {
    console.error("Error al obtener las tareas:", error);
    res.status(500).json({ message: error.message });
  }
});

app.put("/api/tasks/status/:id", async (req, res) => {
  try {
    const taskId = req.params.id;
    const { status } = req.body;

    if ( !status) {
      return res.status(400).json({ message: "El estado es obligatorios" });
    }

    const updatedTask = {
      status,
      updated_at: admin.firestore.FieldValue.serverTimestamp(),
    };

    const taskRef = db.collection("task").doc(taskId);
    await taskRef.update(updatedTask);

    const updatedTaskSnapshot = await taskRef.get();
    const updatedTaskData = updatedTaskSnapshot.data();

    res.status(200).json({ id: taskId, ...updatedTaskData });
  } catch (error) {
    console.error("Error al actualizar la tarea:", error);
    res.status(500).json({ message: error.message });
  }
});

app.put('/api/users/:email/role', async (req, res) => {
  try {
    const userEmail = req.params.email;
    const { rol } = req.body;

    if (!rol) {
      return res.status(400).json({ message: "El rol es obligatorio" });
    }

    const userRef = db.collection("users").where("email", "==", userEmail);
    const snapshot = await userRef.get();

    if (snapshot.empty) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    snapshot.forEach(async (doc) => {
      await doc.ref.update({
        rol,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });

    res.status(200).json({ message: "Rol actualizado correctamente" });
  } catch (error) {
    console.error("Error al actualizar el rol del usuario:", error);
    res.status(500).json({ message: error.message });
  }
});

app.get('/api/users/admin', async (req, res) => {
  try {
    // Obtener todos los usuarios
    const usersSnapshot = await db.collection('users').get();
    const users = usersSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    res.status(200).json(users);
  } catch (error) {
    console.error('Error al obtener los usuarios:', error);
    res.status(500).json({ message: error.message });
  }
});

app.delete('/api/delete/users/:email', async (req, res) => {
  try {
    const userEmail = req.params.email;

    // Buscar el usuario por email
    const userRef = db.collection('users').where('email', '==', userEmail);
    const snapshot = await userRef.get();

    if (snapshot.empty) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    // Eliminar el usuario
    snapshot.forEach(async (doc) => {
      await doc.ref.delete();
    });

    res.status(200).json({ message: 'Usuario eliminado correctamente' });
  } catch (error) {
    console.error('Error al eliminar el usuario:', error);
    res.status(500).json({ message: error.message });
  }
});

app.post('/api/add/users', async (req, res) => {
  try {
    const { username, email, rol, password } = req.body;

    if (!username || !email || !rol || !password) {
      return res.status(400).json({ message: 'Todos los campos son obligatorios' });
    }

    const newUser = {
      username,
      email,
      rol,
      password,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    const userRef = await db.collection('users').add(newUser);

    const userSnapshot = await userRef.get();
    const userData = userSnapshot.data();

    res.status(201).json({ id: userRef.id, ...userData });
  } catch (error) {
    console.error('Error al agregar el usuario:', error);
    res.status(500).json({ message: error.message });
  }
});

app.put('/api/groups/add-users', async (req, res) => {
  try {
    const { groupName, members } = req.body;

    if (!groupName || !members || !Array.isArray(members)) {
      return res.status(400).json({ message: 'El nombre del grupo y los miembros son obligatorios y los miembros deben ser un array' });
    }

    const groupRef = db.collection('group').where('name', '==', groupName);
    const groupSnapshot = await groupRef.get();

    if (groupSnapshot.empty) {
      return res.status(404).json({ message: 'Grupo no encontrado' });
    }

    let updatedGroupData;
    groupSnapshot.forEach(async (doc) => {
      const groupData = doc.data();
      const updatedMembers = [...new Set([...groupData.members, ...members])];

      await doc.ref.update({
        members: updatedMembers,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      updatedGroupData = { id: doc.id, ...groupData, members: updatedMembers };
    });

    res.status(200).json(updatedGroupData);
  } catch (error) {
    console.error('Error al agregar usuarios al grupo:', error);
    res.status(500).json({ message: error.message });
  }
});

app.get("/api/admin/groups", async (req, res) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const email = decoded.email;

    const groupsSnapshot = await db.collection("group").where("members", "array-contains", email).get();
    const groups = groupsSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    res.status(200).json(groups);
  } catch (error) {
    console.error("Error al obtener los grupos:", error);
    res.status(500).json({ message: error.message });
  }
});

app.get("/api/groups/:groupName/tasks", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      console.error("No se proporcionó token");
      return res.status(401).json({ message: "No autorizado" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Usuario autenticado:", decoded.email);

    const { groupName } = req.params;

    const tasksSnapshot = await db.collection("task").where("group", "==", groupName).get();
    const tasks = tasksSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    res.status(200).json(tasks);
  } catch (error) {
    console.error("Error al obtener las tareas del grupo:", error.message);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});