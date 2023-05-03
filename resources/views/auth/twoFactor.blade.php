@extends('plantillas.portada')

@section('titulo')
<title>Autentificación de 2 factores</title>
@stop

@section('contenidoPrincipal')
<h3 class="fw-bold text-dark" style="text-align: center;">Autenticación de dos factores</h3>
<div class="container bg-secondary rounded-3 align-center p-3" style="width: 400px; margin-bottom: 15%;">
    @if(session()->has('message'))
    <p class="alert alert-info">
        {{ session()->get('message') }}
    </p>
    @endif
    <form action="{{ route('verify.store') }}" method="post">
        @csrf
        <p class="text-dark">
            Se ha enviado un correo electrónico que contiene el código de doble factor.
            Si no lo haz recibido, da clic <a class="fw-bold" href="{{ route('verify.resend') }}">aquí.</a>
        </p>
        <div class="mb-3">
            <input name="two_factor_code" type="text" class="form-control{{ $errors->has('two_factor_code') ? ' is-invalid' : '' }}" autofocus placeholder="Código de A2F">
            @if($errors->has('two_factor_code'))
            <div class="text-light fw-bold invalid-feedback">
                {{ $errors->first('two_factor_code') }}
            </div>
            @endif
        </div>
        <div class="mb-3">
            <div class="mb-3 ">
                <button type="submit" class="btn btn-primary px-4">
                    Validar
                </button>
                <a class="btn btn-danger px-4" href="#" onclick="event.preventDefault(); document.getElementById('logoutform').submit();">
                    Salir
                </a>
            </div>
        </div>
    </form>
</div>

<form id="logoutform" action="{{ route('logout') }}" method="POST" style="display: none;">
    {{ csrf_field() }}
</form>
@endsection
