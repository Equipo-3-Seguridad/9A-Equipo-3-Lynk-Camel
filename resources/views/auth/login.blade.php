<!--Se llama a la plantilla principal ya creada-->
@extends('plantillas.portada')

@section('titulo')
<title>Login</title>
<style>
    .formulario {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 20px;
    }

    .formulario__label {
        display: block;
        font-weight: 700;
        padding: 10px;
        cursor: pointer;
    }

    .formulario__grupo-input {
        position: relative;
    }

    .formulario__input {
        width: 100%;
        background: #fff;
        border: 3px solid transparent;
        border-radius: 3px;
        height: 45px;
        line-height: 45px;
        padding: 0 40px 0 10px;
        transition: .3s ease all;
    }

    .formulario__input:focus {
        border: 3px solid #0075FF;
        outline: none;
        box-shadow: 3px 0px 30px rgba(163, 163, 163, 0.4);
    }

    .formulario__input-error {
        font-size: 12px;
        margin-bottom: 0;
        display: none;
    }

    .formulario__input-error-activo {
        display: block;
    }

    .formulario__validacion-estado {
        position: absolute;
        right: 10px;
        bottom: 15px;
        z-index: 100;
        font-size: 16px;
        opacity: 0;
    }

    .formulario__checkbox {
        margin-right: 10px;
    }

    .formulario__grupo-terminos,
    .formulario__mensaje,
    .formulario__grupo-btn-enviar {
        grid-column: span 2;
    }

    .formulario__mensaje {
        height: 45px;
        line-height: 45px;
        background: #F66060;
        padding: 0 15px;
        border-radius: 3px;
        display: none;
    }

    .formulario__mensaje-activo {
        display: block;
    }

    .formulario__mensaje p {
        margin: 0;
    }

    .formulario__grupo-btn-enviar {
        display: flex;
        flex-direction: column;
        align-items: center;
    }

    .formulario__btn {
        height: 45px;
        line-height: 45px;
        width: 30%;
        background: #000;
        color: #fff;
        font-weight: bold;
        border: none;
        border-radius: 3px;
        cursor: pointer;
        transition: .1s ease all;
    }

    .formulario__btn:hover {
        box-shadow: 3px 0px 30px rgba(163, 163, 163, 1);
    }

    .formulario__mensaje-exito {
        font-size: 14px;
        color: #119200;
        display: none;
    }

    .formulario__mensaje-exito-activo {
        display: block;
    }

    /* ----- -----  Estilos para Validacion ----- ----- */
    .formulario__grupo-correcto .formulario__validacion-estado {
        color: #1ed12d;
        opacity: 1;
    }

    .formulario__grupo-incorrecto .formulario__label {
        color: #bb2929;
    }

    .formulario__grupo-incorrecto .formulario__validacion-estado {
        color: #bb2929;
        opacity: 1;
    }

    .formulario__grupo-incorrecto .formulario__input {
        border: 3px solid #bb2929;
    }


    /* ----- -----  Mediaqueries ----- ----- */
    @media screen and (max-width: 800px) {
        .formulario {
            grid-template-columns: 1fr;
        }

        .formulario__grupo-terminos,
        .formulario__mensaje,
        .formulario__grupo-btn-enviar {
            grid-column: 1;
        }

        .formulario__btn {
            width: 100%;
        }
    }
</style>
@stop

@section('contenidoPrincipal')
<h3 class="fw-bold text-dark" style="text-align: center;">Login</h3>
<div class="container-fluid bg-secondary rounded-3 align-center p-3" style="width: 500px; margin-bottom: 15%;">
    @if(\Session::has('message'))
    <p class="alert alert-info">
        {{ \Session::get('message') }}
    </p>
    @endif
    <form id="formulario" action="{{ route('login') }}" method="post">
        @csrf
        <div id="grupo__role" class="formulario__grupo mb-3">
            <label class="formulario-label form-label fw-bold" for="">Rol</label><br>
            <div class="formulario__grupo-input">
                <select class="formulario__input form-control" id="role" name="role" value="{{ old('role') }}">
                    <option value="">Elige tu rol</option>
                    <option value="Empleado">Empleado</option>
                    <option value="Empleador">Empleador</option>
                    <option value="Admin">Administrador</option>
                </select>
                <i class="formulario__validacion-estado fas fa-times-circle"></i>
            </div>
            @error('role')
            <br>
            <small style="color: white; font-weight: bold;">{{$message}}</small>
            @enderror
            <p class="formulario__input-error text-light fw-bold">Por favor, selecciona el rol de tu sesión.</p>
        </div>
        <div id="grupo__email" class="formulario__grupo mb-3">
            <label class="formulario-label form-label fw-bold" for="emailInput">Correo</label>
            <div class="formulario__grupo-input">
                <input id="email" name="email" class="formulario__input form-control" type="email" value="{{ old('email') }}">
                <i class="formulario__validacion-estado fas fa-times-circle"></i>
            </div>
            @error('email')
            <br>
            <small style="color: white; font-weight: bold;">{{$message}}</small>
            @enderror
            <p class="formulario__input-error text-light fw-bold">Por favor introduce un correo válido.</p>
        </div>
        <div id="grupo__password" class="formulario__grupo mb-3">
            <label class="formulario-label form-label fw-bold" for="passwordInput">Contraseña</label>
            <div class="formulario__grupo-input">
                <input id="password" name="password" class="formulario__input form-control" type="password" value="{{ old('password') }}">
                <i class="formulario__validacion-estado fas fa-times-circle"></i>
            </div>
            @error('password')
            <br>
            <small style="color: white; font-weight: bold;">{{$message}}</small>
            @enderror
            <!------Te haz quedado aquí-------->
            <p class="formulario__input-error fw-bold text-light">Por favor comprueba que tu contraseña cumple con 1 mayúscula, 1 minúscula, 1 número y 1 caracter especial, con una extensión de entre 8-20 caracteres.</p>
        </div>
        <div class="mb-3 form-check">
            <input id="rememberCheck" class="form-check-input" name="remember" type="checkbox">
            <label class="form-check-label" for="rememberCheck">Recuerdame...</label>
        </div>
        <div>
            <p>¿No tienes cuenta? <a class="text-light" href="/register"> Regístrate</a></p>
        </div>
        <div class="formulario__mensaje" id="formulario__mensaje">
            <p><i class="fas fa-exclamation-triangle" style="font-size: 15px;"></i> <b>Error:</b> Por favor, rellena el inicio de sesión correctamente. </p>
        </div>
        <div class="formulario__mensaje-exito bg-success round-3" id="formulario__mensaje-exito" style="height: 45px; line-height: 45px; background: #36e34d; padding: 0 15px; border-radius: 3px;">
            <p class="text-light fw-bold" style="font-size: 15px;">Iniciando Sesión...</p>
        </div>
        <br>
        <button class="btn btn-success" type="submit">Acceder</button>
        <a class="btn btn-dark" href="/">Volver</a>
        @if (Route::has('password.request'))
        <a class="btn btn-link text-light" href="{{ route('password.request') }}">
            Olvidaste tu contraseña?
        </a>
        @endif
    </form>
</div>
<script>
    //Comunicación Sincrona
    //Accediendo a los elementos del formulario
    let formulario = document.getElementById('formulario');
    //Obtiene los inputs del formulario
    let inputs = document.querySelectorAll('#formulario input');
    //Obtiene el select de roles
    let selects = document.querySelectorAll('#formulario select');

    //Arreglo de las cadenas que evaluán el contenido de los inputs
    let regex = {
        role: /^[A-Za-z0-9áéíóúüñÑÁÉÍÓÚÜ\s]{2,12}$/,
        email: /^([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$/,
        password: /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,20}$/,
    };

    //Por defecto están desactivados
    let campos = {
        role: false,
        email: false,
        password: false,
    };

    //Validación del formulario en caso de haber activado algún event listener
    let validarFormulario = (e) => {
        switch (e.target.name) {
            case "role":
                validarCampo(regex.role, e.target, 'role');
                break;
            case "email":
                validarCampo(regex.email, e.target, 'email');
                break;
            case "password":
                validarCampo(regex.password, e.target, 'password');
                break;
        }
    }

    let validarCampo = (expresion, input, campo) => {
        if (expresion.test(input.value)) {
            document.getElementById(`grupo__${campo}`).classList.remove('formulario__grupo-incorrecto');
            document.getElementById(`grupo__${campo}`).classList.add('formulario__grupo-correcto');
            document.querySelector(`#grupo__${campo} i`).classList.remove('fa-times-circle');
            document.querySelector(`#grupo__${campo} i`).classList.add('fa-check-circle');
            document.querySelector(`#grupo__${campo} .formulario__input-error`).classList.remove('formulario__input-error-activo');
            //Guardando los valores del campo
            localStorage.setItem(`campo_${campo}`, input.value);
            campos[campo] = true;
        } else {
            document.getElementById(`grupo__${campo}`).classList.add('formulario__grupo-incorrecto');
            document.getElementById(`grupo__${campo}`).classList.add('formulario__grupo-correcto');
            document.querySelector(`#grupo__${campo} i`).classList.add('fa-times-circle');
            document.querySelector(`#grupo__${campo} i`).classList.remove('fa-check-circle');
            document.querySelector(`#grupo__${campo} .formulario__input-error`).classList.add('formulario__input-error-activo');
            //Guardando los valores del campo
            localStorage.setItem(`campo_${campo}`, input.value);
            campos[campo] = false;
        }
    };

    //Event listener de los campos del formulario
    inputs.forEach((input) => {
        input.addEventListener('keyup', validarFormulario);
        input.addEventListener('blur', validarFormulario);
    });

    //Event listener del rol
    selects.forEach((selectElement) => {
        selectElement.addEventListener('change', validarFormulario);
    });

    //Event listener al momento de realizar un submit
    formulario.addEventListener('submit', (e) => {
        e.preventDefault();
        if (campos.role && campos.email && campos.password) {
            document.getElementById('formulario__mensaje-exito').classList.add('formulario__mensaje-exito-activo');
            document.getElementById('formulario__mensaje').classList.remove('formulario__mensaje-activo');
            setTimeout(() => {
                document.getElementById('formulario__mensaje-exito').classList.remove('formulario__mensaje-exito-activo');
            }, 2000);
            document.querySelectorAll('.formulario__grupo-correcto').forEach((icono) => {
                icono.classList.remove('formulario__grupo-correcto');
            });
            formulario.submit();
        } else {
            document.getElementById('formulario__mensaje').classList.add('formulario__mensaje-activo');
        }
    });
</script>
@stop
