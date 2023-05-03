@extends('plantillas.portada')

@section('contenidoPrincipal')
<h3 class="fw-bold text-dark" style="text-align: center;">Reiniciar Contraseña</h3>
<div class="container bg-secondary rounded-3 align-center p-3" style="width: 500px; margin-bottom: 15%;">
    <form action="{{ route('password.update') }}" method="post">
        @csrf
        <input type="hidden" name="token" value="{{ $token }}">
        <div class="mb-3">
            <label for="email" class="form-label fw-bold">Correo Electrónico</label>

            <div class="mb-3">
                <input id="email" type="email" class="form-control @error('email') is-invalid @enderror" name="email" value="{{ $email ?? old('email') }}" required autocomplete="email" autofocus>
                @error('email')
                <span class="invalid-feedback" role="alert">
                    <strong class="text-light">{{ $message }}</strong>
                </span>
                @enderror
            </div>
        </div>
        <div class="mb-3">
            <label for="password" class="form-label fw-bold">Contraseña</label>
            <div class="mb-3">
                <input id="password" type="password" class="form-control @error('password') is-invalid @enderror" name="password" required autocomplete="new-password">
                @error('password')
                <span class="invalid-feedback" role="alert">
                    <strong class="text-light">{{ $message }}</strong>
                </span>
                @enderror
            </div>
        </div>
        <div class="mb-3">
            <label for="password-confirm" class="form-label fw-bold">Confirmar contraseña</label>
            <div class="mb-3">
                <input id="password-confirm" type="password" class="form-control" name="password_confirmation" required autocomplete="new-password">
            </div>
        </div>
        <button class="btn btn-success" type="submit">Reiniciar Contraseña</button>
    </form>
</div>
@endsection
