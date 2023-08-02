/*
Práctica SC 21/22

# Funcionalidad a implementar

Estudiante: (PABLO ARAGÓN LLABATA)
*/
package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"

	//"crypto/rand"

	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"time"

	"golang.org/x/crypto/scrypt"
	//"github.com/zserge/lorca" //go get github.com/zserge/lorca
)

/************************
CONFIGURACION PRÁCTICA
*************************/

// Indica el tipo de interfaz que usará la aplicación:
// 0: solo test
// 1: Linea de comandos
// 2: Interfaz gráfica
func tipoUI() int {
	return 1
}

/**********************
FUNCIONES A IMPLEMENTAR
***********************/

//FUNCIONES PARA COMPRIMIR Y DESCOMPRIMIR, ENCRIPTAR Y DESENCRIPTAR

func encrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)
	rand.Read(out[:16])
	blk, err := aes.NewCipher(key)
	chk(err)
	ctr := cipher.NewCTR(blk, out[:16])
	ctr.XORKeyStream(out[16:], data)
	return
}

func decrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)
	blk, err := aes.NewCipher(key)
	chk(err)
	ctr := cipher.NewCTR(blk, data[:16])
	ctr.XORKeyStream(out, data[16:])
	return
}

func compress(data []byte) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(data)
	w.Close()
	return b.Bytes()
}

func decompress(data []byte) []byte {
	var b bytes.Buffer
	r, err := zlib.NewReader(bytes.NewReader(data))
	chk(err)
	io.Copy(&b, r)
	r.Close()
	return b.Bytes()
}

func accionMenuInicial() int {
	fmt.Println("")
	fmt.Println("---------------****---------------")
	fmt.Println("Acciones:")
	fmt.Println("1) Login")
	fmt.Println("0) Salir")
	fmt.Println("----------------------------------")
	fmt.Println("¿Qué deseas hacer? (0,1)")

	var opcion int
	fmt.Scanln(&opcion)

	return opcion
}

func accionMenuSecundario() int {
	fmt.Println("")
	fmt.Println("---------------****---------------")
	fmt.Println("Acciones:")
	fmt.Println("1)Inicializar base de datos")
	fmt.Println("2)Registrar doctor")
	fmt.Println("3)Registrar paciente")
	fmt.Println("4)Registrar historial")
	fmt.Println("5)Cargar base de datos")
	fmt.Println("6)Grabar base de datos")
	fmt.Println("7)Imprimir base de datos")
	fmt.Println("0)Volver")
	fmt.Println("----------------------------------")
	fmt.Println("¿Qué deseas hacer? (0,1,2,3,4,5,6)")

	var opcion int
	fmt.Scanln(&opcion)

	return opcion
}

/**********************
-------SERVIDOR--------
***********************/

func (dSrv *db) guardar(nomFich string, clave []byte) {
	b, err := json.Marshal(dSrv)
	chk(err)
	b = compress(b)
	b = encrypt(b, clave)
	err = ioutil.WriteFile(nomFich, b, 0777)
	chk(err)
}
func (dSrv *db) cargar(nomFich string, clave []byte) {
	b, err := ioutil.ReadFile(nomFich)
	chk(err)
	b = decrypt(b, clave)
	b = decompress(b)
	err = json.Unmarshal(b, dSrv)
	chk(err)
}

func (dSrv *db) registrarUsuario(login, contr string) bool {
	_, ok := dSrv.Creds[login]
	if ok {
		return false
	} else {
		var hash []byte
		sal := make([]byte, 16)
		rand.Read(sal)
		hash, _ = scrypt.Key([]byte(contr), sal, 16384, 8, 1, 32)
		dSrv.Creds[login] = auth{login, hash, sal}
	}
	return true
}

func (dSrv *db) puedeAcceder(login, contr string, token string, comando string) bool {
	accesoOk := false
	autenticacionOk := false
	usuarioAdmin := false
	if login == dSrv.UserAdmin() {
		usuarioAdmin = true
	}
	u, ok := dSrv.Creds[login]
	hash, _ := scrypt.Key([]byte(contr), u.Salt, 16384, 8, 1, 32)
	if ok {
		if bytes.Equal(u.Hash, hash) {
			autenticacionOk = true
		}
	}
	switch comando {
	case "BD_INI":
		_, existeAdmin := dSrv.Creds[dSrv.UserAdmin()]
		if usuarioAdmin && !existeAdmin {
			if contr == dSrv.ClaveAdminInicial() {
				accesoOk = true
			} else {
				accesoOk = false
			}
		}
	case "SALIR":
		accesoOk = autenticacionOk && usuarioAdmin
	case "DOC_REG":
		accesoOk = autenticacionOk && usuarioAdmin
	case "LOGIN":
		accesoOk = true
	default:
		accesoOk = autenticacionOk
	}

	return accesoOk
}

const letrasArray = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func crearClaveAdminAleatoria(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letrasArray[rand.Intn(len(letrasArray))]
	}
	return string(b)
}

var global_pass string
var global_pass_maestra = make([]byte, 32)

func (dSrv *db) AccionPreStart() {
	global_pass = crearClaveAdminAleatoria(32)

	fmt.Println("La contraseña del Admin es:  " + global_pass)

	var contra_maestra string
	fmt.Scanf("%s", contra_maestra)

	var hash []byte

	salt := make([]byte, 16)
	rand.Read(salt)

	hash, _ = scrypt.Key([]byte(contra_maestra), salt, 16384, 8, 1, 32)
	global_pass_maestra = hash

}

// Acciones a ejecutar antes de realizar un comando
func (dSrv *db) AccionPreCommando(w http.ResponseWriter, req *http.Request) {
	//...
}

// Manejador de commandos extras
func (dSrv *db) CommandosExtras(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "Comando sin implementar: %s \n", req.Form.Get("cmd"))
}

// Acciones a ejecutar despues de realizar un comando
func (dSrv *db) AccionPostCommando(w http.ResponseWriter, req *http.Request) {
	//...
}

// Acciones a ejecutar antes de apagar el servidor
func (dSrv *db) AccionPreStop() {
	//...
}

func (dSrv *db) ClaveMaestra() []byte {
	return global_pass_maestra
}

func (dSrv *db) ClaveAdminInicial() string {
	return global_pass
}

// Obtener nombre usuario admin para login
func (dSrv *db) UserAdmin() string {
	return "Admin"
}

// Obtiene el token actual de un cliente. Cadena vacia si no tiene o está caducado
func (dSrv *db) GetUserToken(usr string) string {
	return ""
}

/**********************
-------CLIENTE--------
***********************/

// Obtener clave admin para login en servidor
func (dCli *dataCliente) ClaveAdminInicial() string {
	return global_pass
}

// Devuelve el usuario actual para login en servidor
func (dCli *dataCliente) UserActual() string {
	return dCli.usrActual
}

// Devuelve la clave del usuario actual
func (dCli *dataCliente) ClaveActual() string {
	return dCli.passActual
}

// Devuelve el token de acceso del usuario actual
func (dCli *dataCliente) TokenActual() string {
	return dCli.tokenActual
}

/**********
INTERFACES
***********/

// Función que desarrolla la interfaz por linea de comandos en caso de ser este el modo de implemantación
func cmdIniIUI(cli *http.Client) {
	fmt.Println("¡Bienvenido a mi programa!")

	var accion, accion2 int

	fmt.Println("Elige:")
	fmt.Scanln(accion)

	//Bucle del menú inicial
	for {
		accion = accionMenuInicial()
		fmt.Println("Has elegido:" + fmt.Sprint(accion))
		fmt.Println("")
		if accion == 0 {
			break
		}
		switch accion {
		case 1:
			var usr, pass string

			fmt.Println("Usuario:")
			fmt.Scanln(&usr)
			fmt.Println("Contraseña:")
			fmt.Scanln(&pass)

			clienteData = dataCliente{
				usrActual:   usr,
				tokenActual: "",
				passActual:  pass,
			}

			fmt.Println("Iniciando sesión con '" + usr + "' y  contraseña '" + pass + "'")

			//Bucle del menú principal
			for {
				accion2 = accionMenuSecundario()
				fmt.Println("Has elegido:" + fmt.Sprint(accion2))
				fmt.Println("")
				if accion2 == 0 {
					break
				}
				switch accion2 {
				case 1:
					//Iniciar base de datos.
					cmdBDIni(cli)
					fmt.Println("La base de datos ha sido Iniciada")

				case 2:
					//Registrar Doctor

					var id, nombre, apellidos, especialidad, login, contraseña string
					fmt.Println("Id del medico:")
					fmt.Scanln(&id)
					fmt.Println("Nombre:")
					fmt.Scanln(&nombre)
					fmt.Println("Apellidos:")
					fmt.Scanln(&apellidos)
					fmt.Println("Especialidad hospitalaria:")
					fmt.Scanln(&especialidad)
					fmt.Println("Login")
					fmt.Scanln(&login)
					fmt.Println("Contraseña")
					fmt.Scanln(&contraseña)

					cmdDocReg(cli, id, nombre, apellidos, especialidad, login, contraseña)

				case 3:
					//Registrar Paciente
					var id, nombre, apellidos, nacimiento, género string
					fmt.Println("Id del paciente:")
					fmt.Scanln(&id)
					fmt.Println("Nombre:")
					fmt.Scanln(&nombre)
					fmt.Println("Apellidos:")
					fmt.Scanln(&apellidos)
					fmt.Println("Fecha de nacimiento:")
					fmt.Scanln(&nacimiento)
					fmt.Println("Género")
					fmt.Scanln(&género)

					cmdPacReg(cli, id, nombre, apellidos, nacimiento, género)

				case 4:
					//Registrar un historial
					var doctor, paciente, datos string

					fmt.Println("Id del doctor:")
					fmt.Scanln(&doctor)
					fmt.Println("Id del Paciente:")
					fmt.Scanln(&paciente)
					fmt.Println("Datos para añadir:")
					fmt.Scanln(&datos)

					cmdHistReg(cli, doctor, paciente, datos)

				case 5:
					//Cargar en la base de datos
					cmdBDCargar(cli, "datos.db")

				case 6:
					//Graba en la base de datos
					cmdBDGrabar(cli, "datos.db")

				case 7:
					//Imprime la base de datos
					cmdBDImp(cli)

				case 8:
					//Salir
					cmdSalir(cli)

				}
			}
		}
	}
}

// Función que desarrolla la interfaz gráfica en caso de ser este el modo de implemantación
// Recuerda descargar el módulo de go con:
// go get github.com/zserge/lorca
func cmdIniGUI(cli *http.Client) {
	/*
		args := []string{}
		if runtime.GOOS == "linux" {
			args = append(args, "--class=Lorca")
		}
		ui, err := lorca.New("", "", 480, 320, args...)
		if err != nil {
			log.Fatal(err)
		}
		defer ui.Close()

		// A simple way to know when UI is ready (uses body.onload event in JS)
		ui.Bind("start", func() {
			log.Println("UI is ready")
		})

		// Load HTML.
		b, err := ioutil.ReadFile("./www/index.html") // just pass the file name
		if err != nil {
			fmt.Print(err)
		}
		html := string(b) // convert content to a 'string'
		ui.Load("data:text/html," + url.PathEscape(html))

		// You may use console.log to debug your JS code, it will be printed via
		// log.Println(). Also exceptions are printed in a similar manner.
		ui.Eval(`
			console.log("Hello, world!");
		`)

		// Wait until the interrupt signal arrives or browser window is closed
		sigc := make(chan os.Signal)
		signal.Notify(sigc, os.Interrupt)
		select {
		case <-sigc:
		case <-ui.Done():
		}

		log.Println("exiting...")
	*/
}

/******
DATOS
*******/

// contenedor de la base de datos
type db struct {
	Pacs  map[uint]paciente  // lista de pacientes indexados por ID
	Docs  map[uint]doctor    // lista de doctores indexados por ID
	Hists map[uint]historial // lista de historiales indexados por ID
	Creds map[string]auth    // lista de credenciales indexadas por Login
}

// datos relativos a pacientes
type paciente struct {
	ID         uint // identificador primario de paciente
	Nombre     string
	Apellidos  string
	Nacimiento time.Time
	Sexo       string //H-> Mombre, M-> Mujer
}

// datos relativos al personal médico
type doctor struct {
	ID           uint // identificador primario del doctor
	Nombre       string
	Apellidos    string
	Especialidad string
	Login        string // referencia a auth
}

// datos relativos a historiales
type historial struct {
	ID       uint      // identificador primario de la entrada de historial
	Fecha    time.Time // fecha de creación/modificación
	Doctor   uint      // referencia a un doctor
	Paciente uint      // referencia a un paciente
	Datos    string    // contenido de la entrada del historial (texto libre)
}

// datos relativos a la autentificación (credenciales)
type auth struct {
	Login string // nombre de entrada e identificador primario de credenciales
	Hash  []byte
	Salt  []byte
}

// Estos son los datos que almacena el cliente en memoría para trabajar
type dataCliente struct {
	usrActual   string // nombre de usuario introducido por el usuario
	passActual  string // contraseña introducida por el usuario
	tokenActual string // token proporcionado por el servidor para autenticación de las peticiones
}

/***********
UTILIDADES
************/

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}
