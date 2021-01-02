const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const unless = require('express-unless');

const app = express();

// Permite recibir un JSON (middleware)
app.use(express.json());
// Declaracion del puerto
const port = process.env.PORT ? process.env.PORT : 3000;

// Declaracion del middleware
const auth = (req, res, next) => {
    try {
        let token = req.headers['authorization'];
        if(!token){
            throw new Error("No estas logeado");
        }
        token = token.replace('Bearer ', '');

        jwt.verify(token, 'Secret', (err, user) => {
            if(err) {
                res.status(401).send({
                    error: 'Token invalido'
                })
            } else {
                res.send(user);
            }
        });
        next();
    } catch (e) {
        res.status(403).send({message: e.message});
    }
}

auth.unless = unless;

app.use(auth.unless({
    path: [
        {url: '/login', methods: ['POST']},
        {url: '/registro', methods: ['POST']}
    ]
}));

// Autenticacion
// Paso 1: Registracion
app.post('/registro', async (req, res) => {
    try {
        if(!req.body.usuario || !req.body.clave || !req.body.email || !req.body.celu) {
            throw new Error("No enviaste todos los datos necesarios");
        }

        // Verifico que no exista el nombre de usuario
        // Consulto con la base de datos que estoy trabajando
        /*
        SQL --> SELECT * FROM usuarios WHERE usuario = req.body.usuario
        MONGODB --> usuario.find({usuario: req.body.usuario})
        */

        // Si existe, mando error, sino encripto la clave
        const claveEncriptada = await bcrypt.hash(req.body.clave, 10);

        // Guardar el usuario con la clave encriptada
        const usuario = {
            usuario: req.body.usuario,
            clave: claveEncriptada,
            email: req.body.email,
            celu: req.body.celu
        }

        res.send({message: "Se registro correctamente"});

    } catch (e) {
        res.status(413).send({message: e.message});
    }
});

// Paso 2: Login
app.post('/login', (req, res) => {
    try {
        if(!req.body.usuario || !req.body.clave) {
            throw new Error("No enviaste los datos necesarios");
        }

        // Paso 1: Encuentro el usuario en la DB
        /*
        SQL --> SELECT * FROM usuarios WHERE usuario = req.body.usuario
        MONGODB --> usuario.find({usuario: req.body.usuario})
        */
        // Si no lo encuentro -> Error

        // Paso 2: Verificar la clave
        /*
        const claveEncriptada = "nfias9f2bo4190na0";
        if(!bcrypt.compareSync(req.body.clave, claveEncriptada)){
            throw new Error("Fallo el login");
        }
        */

        // Paso 3: Sesion
        const tokenData = {
            nombre: "Santiago",
            apellido: "Delmonte",
            user_id: 1
        }

        const token = jwt.sign(tokenData, 'Secret', {
            expiresIn: 60 * 60 * 24 // Expires in 24 hs
        })
        res.send({token});

    } catch (e) {
        res.status(413).send({message: e.message});
    }
});

// Sesion

app.get('/libros', (req, res) => {
    try {
        res.send({message: "Lista de libros"});
    } catch (e) {
        res.status(413).send({message: e.message});
    }
});



app.listen(port, () => {
    console.log("Servidor escuchando en el puerto ", port); 
});


/*
app.post('/', (req, res) => {
    try {
        
    } catch (e) {
        res.status(413).send({message: e.message});
    }
});
*/