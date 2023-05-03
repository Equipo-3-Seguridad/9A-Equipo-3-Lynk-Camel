@extends('plantillas.portada')

@section('titulo')
<title>Reiniciar Contraseña</title>
@stop

@section('contenidoPrincipal')
<h3 class="fw-bold text-dark" style="text-align: center;">Reiniciar Contraseña</h3>
<div class="container bg-secondary rounded-3 align-center p-3" style="width: 500px; margin-bottom: 15%;">
    @if (session('status'))
    <div class="alert alert-success" role="alert">
        {{ session('status') }}
    </div>
    @endif
    <form action="{{ route('password.email') }}" method="post">
        @csrf
        <div class="mb-3">
            <label class="form-label fw-bold" for="emailInput">Correo</label>
            <input id="emailInput" name="email" class="form-control" type="email">
            @error('email')
            <small style="color: white; font-weight: bold;">{{$message}}</small>
            @enderror
        </div>
        <button class="btn btn-success" type="submit">Enviar link de restauración de la contraseña</button>
        <a class="btn btn-dark" href="/">Volver</a>
    </form>
</div>
@endsection
