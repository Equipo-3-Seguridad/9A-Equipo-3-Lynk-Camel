<!--Se llama a la plantilla principal ya creada-->
@extends('plantillas.portada')

@section('titulo')
<title>Login</title>
@stop

@section('contenidoPrincipal')
<h3 class="fw-bold text-dark" style="text-align: center;">Login</h3>
<div class="container bg-secondary rounded-3 align-center p-3" style="width: 400px; margin-bottom: 15%;">
    @if(\Session::has('message'))
    <p class="alert alert-info">
        {{ \Session::get('message') }}
    </p>
    @endif
    <form action="{{ route('login') }}" method="post">
        @csrf
        <div class="mb-3">
            <label class="form-label fw-bold mx-1" for="">Rol</label><br>
            <div class="form-group">
                <select class="form-control bg-secondary border-light text-light" id="role" name="role">
                    <option value="">Elige tu rol</option>
                    <option value="Empleado">Empleado</option>
                    <option value="Empleador">Empleador</option>
                    <option value="Admin">Administrador</option>
                </select>
                @error('role')
                <br>
                <small style="color: white; font-weight: bold;">{{$message}}</small>
                @enderror
            </div>
        </div>
        <div class="mb-3">
            <label class="form-label fw-bold" for="emailInput">Correo</label>
            <input id="emailInput" name="email" class="form-control" type="email">
            @error('email')
            <br>
            <small style="color: white; font-weight: bold;">{{$message}}</small>
            @enderror
        </div>
        <div class="mb-3">
            <label class="form-label fw-bold" for="passwordInput">Contraseña</label>
            <input id="passwordInput" name="password" class="form-control" type="password">
            @error('password')
            <br>
            <small style="color: white; font-weight: bold;">{{$message}}</small>
            @enderror
        </div>
        <div class="mb-3 form-check">
            <input id="rememberCheck" class="form-check-input" name="remember" type="checkbox">
            <label class="form-check-label" for="rememberCheck">Recuerdame...</label>
        </div>
        <div>
            <p>¿No tienes cuenta? <a class="text-light" href="/register"> Regístrate</a></p>
        </div>
        <button class="btn btn-success" type="submit">Acceder</button>
        <a class="btn btn-dark" href="/">Volver</a>
        @if (Route::has('password.request'))
        <a class="btn btn-link text-light" href="{{ route('password.request') }}">
            Olvidaste tu contraseña?
        </a>
        @endif
    </form>
</div>
@stop
