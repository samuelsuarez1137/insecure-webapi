<?php 
include 'conection/BDconection.php';

function getToken(){
    //creamos el objeto fecha y obtuvimos la cantidad de segundos desde el 1ª enero 1970
    $fecha = date_create();
    $tiempo = date_timestamp_get($fecha);
    //vamos a generar un numero aleatorio
    $numero = mt_rand();
    //vamos a generar ua cadena compuesta
    $cadena = ''.$numero.$tiempo;
    // generar una segunda variable aleatoria
    $numero2 = mt_rand();
    // generar una segunda cadena compuesta
    $cadena2 = ''.$numero.$tiempo.$numero2;
    // generar primer hash en este caso de tipo sha1
    $hash_sha1 = sha1($cadena);
    // generar segundo hash de tipo MD5 
    $hash_md5 = md5($cadena2);
    return substr($hash_sha1,0,20).$hash_md5.substr($hash_sha1,20);
}

require 'vendor/autoload.php';
$f3 = \Base::instance();

$f3->route('GET /',
    function() {
        echo 'Hello, world!';
    }
);


// Registro
$f3->route('POST /Registro',
    function($f3) {
        $db = BD();
        $db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        /////// obtener el cuerpo de la peticion
        $Cuerpo = $f3->get('BODY');
        $jsB = json_decode($Cuerpo,true);
        /////////////
        $R = array_key_exists('uname',$jsB) && array_key_exists('email',$jsB) && array_key_exists('password',$jsB);
        if (!$R){
            echo '{"R":-1}';
            return;
        }
        $options = [
            'cost' => 12 // (número de iteraciones)
        ];

        $authenticator = new PHPGangsta_GoogleAuthenticator();
        $secret = $authenticator->createSecret();


        try {
            $stmt = $db->prepare('INSERT INTO Usuario (uname, email, password, clave) VALUES (:uname, :email, :password, :clave)');
            $stmt->bindParam(':uname', $jsB['uname'], \PDO::PARAM_STR);
            $stmt->bindParam(':email', $jsB['email'], \PDO::PARAM_STR);
            $hashedPassword = password_hash($jsB['password'], PASSWORD_DEFAULT, $options);
            $stmt->bindParam(':password', $hashedPassword, \PDO::PARAM_STR);
            $stmt->bindParam(':clave', $secret, \PDO::PARAM_STR);
            $stmt->execute();
        } catch (Exception $e) {
            echo '{"R":-2}';
            return;
        }
        echo '{"R":0, "T": '.$secret.'}';
    }
);

// Login
$f3->route('POST /Login',
    function($f3) {
        $db = BD();
        $db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        /////// obtener el cuerpo de la petición
        $Cuerpo = $f3->get('BODY');
        $jsB = json_decode($Cuerpo,true);
        /////////////
        $R = array_key_exists('uname',$jsB) && array_key_exists('password',$jsB);
        if (!$R){
            echo '{"R":-1}';
            return;
        }
        try {
            $stmt = $db->prepare('SELECT id, password FROM Usuario WHERE uname = :uname');
            $stmt->bindParam(':uname', $jsB['uname'], \PDO::PARAM_STR);
            $stmt->execute();
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
        } catch (Exception $e) {
            echo '{"R":-2}';
            return;
        }

        if (!$result || !password_verify($jsB['password'], $result['password'])) {
            echo '{"R":-3}';
            return;
        }

        $id_usuario = $result['id'];
        $T = getToken();

        try {
            $stmt = $db->prepare('INSERT INTO Logins (id_usuario, log_login, fecha) VALUES (:id_usuario, :log_login, NOW())');
            $log_login = 'ID: '.$id_usuario.', Token: ' . $T.' inició sesión con Usr y Pass';
            $stmt->bindParam(':id_usuario', $id_usuario, \PDO::PARAM_INT);
            $stmt->bindParam(':log_login', $log_login, \PDO::PARAM_STR);
            $stmt->execute();
        } catch (Exception $e) {
            echo '{"R":-2}';
            return;
        }

        // Eliminar token antiguo y guardar nuevo
        try {
            $stmt = $db->prepare('DELETE FROM AccesoToken WHERE id_Usuario = :id_usuario');
            $stmt->bindParam(':id_usuario', $id_usuario, \PDO::PARAM_INT);
            $stmt->execute();
            $stmt = $db->prepare('INSERT INTO AccesoToken (id_Usuario, token, fecha) VALUES (:id_usuario, :token, NOW())');
            $stmt->bindParam(':id_usuario', $id_usuario, \PDO::PARAM_INT);
            $stmt->bindParam(':token', $T, \PDO::PARAM_STR);
            $stmt->execute();
        } catch (Exception $e) {
            echo '{"R":-2}';
            return;
        }

        echo '{"R":0,"D":"'.$T.'"}';
    }
);


// Login con Codigo
$f3->route('POST /LoginCodigo',
    function($f3) {
        $db = BD();
        $db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        /////// obtener el cuerpo de la petición
        $Cuerpo = $f3->get('BODY');
        $jsB = json_decode($Cuerpo,true);
        /////////////
        $R = array_key_exists('uname',$jsB) && array_key_exists('codigo',$jsB);
        if (!$R){
            echo '{"R":-1}';
            return;
        }
        try {
            $stmt = $db->prepare('SELECT id, clave FROM Usuario WHERE uname = :uname');
            $stmt->bindParam(':uname', $jsB['uname'], \PDO::PARAM_STR);
            $stmt->execute();
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
        } catch (Exception $e) {
            echo '{"R":-2}';
            return;
        }

        if (!$result) {
            echo '{"R":-3}';
            return;
        }

        $authenticator = new PHPGangsta_GoogleAuthenticator();
        $clave= $result['clave'];
        $otp = $jsB['codigo']; 
        $tolerance = 0; // Cada OTP es válido durante 30 segundos.

        $checkResult = $authenticator->verifyCode($clave, $otp, $tolerance);
        if (!$checkResult) {
            echo '{"R":-3}';
            return;
        } 

        $id_usuario = $result['id'];
        $T = getToken();

        try {
            $stmt = $db->prepare('INSERT INTO Logins (id_usuario, log_login, fecha) VALUES (:id_usuario, :log_login, NOW())');
            $log_login = 'ID: '.$id_usuario.', Token: ' . $T.' inició sesión con Codigo';
            $stmt->bindParam(':id_usuario', $id_usuario, \PDO::PARAM_INT);
            $stmt->bindParam(':log_login', $log_login, \PDO::PARAM_STR);
            $stmt->execute();
        } catch (Exception $e) {
            echo '{"R":-2}';
            return;
        }

        // Eliminar token antiguo y guardar nuevo
        try {
            $stmt = $db->prepare('DELETE FROM AccesoToken WHERE id_Usuario = :id_usuario');
            $stmt->bindParam(':id_usuario', $id_usuario, \PDO::PARAM_INT);
            $stmt->execute();
            $stmt = $db->prepare('INSERT INTO AccesoToken (id_Usuario, token, fecha) VALUES (:id_usuario, :token, NOW())');
            $stmt->bindParam(':id_usuario', $id_usuario, \PDO::PARAM_INT);
            $stmt->bindParam(':token', $T, \PDO::PARAM_STR);
            $stmt->execute();
        } catch (Exception $e) {
            echo '{"R":-2}';
            return;
        }

        echo '{"R":0,"D":"'.$T.'"}';
    }
);


// Subir Imagen
$f3->route('POST /Imagen',
    function($f3) {
        // Directorio
        if (!file_exists('tmp')) {
            mkdir('tmp');
        }
        if (!file_exists('img')) {
            mkdir('img');
        }
        /////// obtener el cuerpo de la petición
        $Cuerpo = $f3->get('BODY');
        $jsB = json_decode($Cuerpo,true);
        /////////////
        $R = array_key_exists('name',$jsB) && array_key_exists('data',$jsB) && array_key_exists('ext',$jsB) && array_key_exists('token',$jsB);
        // TODO checar si están vacíos los elementos del JSON
        if (!$R){
            echo '{"R":-1}';
            return;
        }
        
        $db = BD();
        $db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        // Validar si el usuario está en la base de datos
        $TKN = $jsB['token'];
        
        try {
            $stmt = $db->prepare('SELECT id_Usuario FROM AccesoToken WHERE token = :token');
            $stmt->bindParam(':token', $TKN, \PDO::PARAM_STR);
            $stmt->execute();
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
        } catch (Exception $e) {
            echo '{"R":-2}';
            return;
        }

        if (!$result){
            echo '{"R":-3}';
            return;
        }

        $id_Usuario = $result['id_Usuario'];
        file_put_contents('tmp/'.$id_Usuario,base64_decode($jsB['data']));
        $jsB['data'] = '';

        // Guardar info del archivo en la base de datos
        try {
            $stmt = $db->prepare('INSERT INTO Imagen (name, ruta, id_Usuario) VALUES (:name, :ruta, :id_Usuario)');
            $ruta = 'img/';
            $stmt->bindParam(':name', $jsB['name'], \PDO::PARAM_STR);
            $stmt->bindParam(':ruta', $ruta, \PDO::PARAM_STR);
            $stmt->bindParam(':id_Usuario', $id_Usuario, \PDO::PARAM_INT);
            $stmt->execute();
            
            // Obtener el ID del último registro insertado
            $stmt = $db->prepare('SELECT MAX(id) AS idImagen FROM Imagen WHERE id_Usuario = :id_Usuario');
            $stmt->bindParam(':id_Usuario', $id_Usuario, \PDO::PARAM_INT);
            $stmt->execute();
            $idImagenResult = $stmt->fetch(\PDO::FETCH_ASSOC);
            $idImagen = $idImagenResult['idImagen'];
            
            $ruta .= $idImagen.'.'.$jsB['ext'];
            
            // Actualizar la ruta en la base de datos
            $stmt = $db->prepare('UPDATE Imagen SET ruta = :ruta WHERE id = :idImagen');
            $stmt->bindParam(':ruta', $ruta, \PDO::PARAM_STR);
            $stmt->bindParam(':idImagen', $idImagen, \PDO::PARAM_INT);
            $stmt->execute();
        } catch (Exception $e) {
            echo '{"R":-4}';
            return;
        }

        // Mover archivo a su nueva locación
        rename('tmp/'.$id_Usuario,'img/'.$idImagen.'.'.$jsB['ext']);
        echo '{"R":0,"D":'.$idImagen.'}';
    }
);


// Descargar Imagen
$f3->route('POST /Descargar',
    function($f3) {
        $db = BD();
        $db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        /////// obtener el cuerpo de la petición
        $Cuerpo = $f3->get('BODY');
        $jsB = json_decode($Cuerpo,true);
        /////////////
        $R = array_key_exists('token',$jsB) && array_key_exists('id',$jsB);
        if (!$R){
            echo '{"R":-1}';
            return;
        }
        
        // Validar el token
        $TKN = $jsB['token'];
        try {
            $stmt = $db->prepare('SELECT id_Usuario FROM AccesoToken WHERE token = :token');
            $stmt->bindParam(':token', $TKN, \PDO::PARAM_STR);
            $stmt->execute();
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
        } catch (Exception $e) {
            echo '{"R":-2}';
            return;
        }

        if (!$result){
            echo '{"R":-3}';
            return;
        }

        // Verificar si el ID de la imagen corresponde al ID del token
        try {
            $stmt = $db->prepare('SELECT id_Usuario FROM Imagen WHERE id = :id');
            $stmt->bindParam(':id', $jsB['id'], \PDO::PARAM_INT);
            $stmt->execute();
            $imagenResult = $stmt->fetch(\PDO::FETCH_ASSOC);
        } catch (Exception $e) {
            echo '{"R":-4}';
            return;
        }

        if (!$imagenResult || $imagenResult['id_Usuario'] !== $result['id_Usuario']) {
            echo '{"R":-5}';
            return;
        }

        // Si el ID de la imagen coincide con el ID del token, enviar la imagen
        try {
            $stmt = $db->prepare('SELECT name, ruta FROM Imagen WHERE id = :id');
            $stmt->bindParam(':id', $jsB['id'], \PDO::PARAM_INT);
            $stmt->execute();
            $result = $stmt->fetch(\PDO::FETCH_ASSOC);
        } catch (Exception $e) {
            echo '{"R":-6}';
            return;
        }

        if (!$result) {
            echo '{"R":-7}';
            return;
        }

        $ruta = $result['ruta'];
        $nombre = $result['name'];

        $web = \Web::instance();
        ob_start();
        $info = pathinfo($ruta);
        $web->send($ruta,NULL,0,TRUE,$nombre.'.'.$info['extension']);
        ob_get_clean();
    }
);

$f3->run();
?>

