<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    @yield('titulo')
    <!--Ejemplo de inclusion de hoja de estilos + css-->
    <!--@vite(['resources/css/app.css', 'resources/js/app.js'])-->
    <!--Incluyendo los estilos en css-->
    @vite(['resources/css/app.css', 'resources/js/app.js'])
    <link rel="icon" href="{{ asset('img/icon.png')}}" />
    <!--Bootstrap-->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-KK94CHFLLe+nY2dmCWGMq91rCGa5gtU4mk92HdvYe+M/SXH301p5ILy+dN9+nJOZ" crossorigin="anonymous">
    <!-- Font Awesome -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet" />
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css?family=Roboto:300,400,500,700&display=swap" rel="stylesheet" />
    <!--Contenido css y demás...-->
    @yield('contenidoStyles')
</head>

<body class="bg-light">
    <!--Barra de Navegación-->
    <nav class="navbar navbar-expand-lg navbar-dark bg-light">
        <div class="container-fluid">
            <a id="1" class="navbar-brand fw-bold text-danger" style="font-size: 25px;" href="/administrador/inicio">Lynk Camel</a>
            <!--Toggler Button Responsive-->
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarSupportedContent">
                <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                    <li class="nav-item">
                        <a class="nav-link active text-dark fw-bold" style="font-size: 20px;" href="/administrador/conocenos">Conócenos</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active text-dark fw-bold" style="font-size: 20px;" href="/administrador/empleos">Empleos</a>
                    </li>
                </ul>
                <ul class="navbar-nav ml-auto mb-2 mb-lg-0">
                    <li class="nav-item">
                        <a class="nav-link active text-dark fw-bold " style="font-size: 20px;" href="">Usuario: @auth {{ Auth::user()->name }} @endauth</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active text-dark fw-bold" style="font-size: 20px;" href="">Tipo: @auth {{ Auth::user()->role }} @endauth</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active text-dark fw-bold" style="font-size: 20px;" href="{{ route('logout-back') }}">Cerrar Sesión</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    <!--Contenido Principal-->
    @yield('contenidoPrincipal')

    <!--Pie de Página-->
    <footer class="row row-cols-1 row-cols-sm-2 row-cols-md-5 py-5 my-5 border-top">
        <div class="col mb-3">
            <a href="https://getbootstrap.com/" class="d-flex align-items-center mb-3 link-dark text-decoration-none">
                <svg class="bi me-2" width="40" height="32">
                    <use xlink:href="#bootstrap"></use>
                </svg>
            </a>
            <p class="text-muted">© 2023 Lynk Camel</p>
        </div>

        <div class="col mb-3">
            <h5 class="fw-bold">Navegación</h5>
            <ul class="nav flex-column">
                <li class="nav-item mb-2"><a href="/administrador/inicio" class="nav-link p-0 text-muted"><i class="fas fa-home"></i> Inicio</a></li>
                <li class="nav-item mb-2"><a href="/administrador/conocenos" class="nav-link p-0 text-muted"><i class="fa-regular fa-handshake"></i> Conócenos</a></li>
                <li class="nav-item mb-2"><a href="/administrador/empleos" class="nav-link p-0 text-muted"><i class="fa-solid fa-briefcase" style="color: #616161;"></i> Empleos</a></li>
                <li class="nav-item mb-2"><a href="/login" class="nav-link p-0 text-muted"><i class="fa-solid fa-right-to-bracket"></i> Login</a></li>
                <li class="nav-item mb-2"><a href="/registro" class="nav-link p-0 text-muted"><i class="fas fa-pencil"></i> Registro</a></li>
            </ul>
        </div>

        <div class="col mb-3">
            <h5 class="fw-bold">Redes Sociales</h5>
            <ul class="nav flex-column">
                <li class="nav-item mb-2"><a href="https://www.facebook.com" class="nav-link p-0 text-muted"><i class="fa-brands fa-facebook"></i> Facebook</a></li>
                <li class="nav-item mb-2"><a href="https://www.twitter.com" class="nav-link p-0 text-muted"><i class="fa-brands fa-twitter"></i> Twitter</a></li>
                <li class="nav-item mb-2"><a href="https://www.instagram.com" class="nav-link p-0 text-muted"><i class="fa-brands fa-instagram"></i> Instagram</a></li>
            </ul>
        </div>

        <div class="col mb-3">
            <h5 class="fw-bold">Marco Legal</h5>
            <ul class="nav flex-column">
                <li class="nav-item mb-2"><a href="/administrador/politica-privacidad" class="nav-link p-0 text-muted"><i class="fas fa-shield"></i> Políticas de Privacidad</a></li>
                <li class="nav-item mb-2"><a href="/administrador/politica-uso" class="nav-link p-0 text-muted"><i class="fas fa-pencil"></i> Políticas de Uso</a></li>
                <li class="nav-item mb-2"><a href="/administrador/aviso-privacidad" class="nav-link p-0 text-muted"><i class="fas fa-pencil"></i> Aviso de Privacidad</a></li>
            </ul>
        </div>

        <div class="col mb-3">
            <h5 class="fw-bold">Contáctanos</h5>
            <ul class="nav flex-column">
                <li class="nav-item mb-2"><i class="fa-solid fa-envelope" style="color: #5b5b5b;"></i> 20191134@uthh.edu.mx</li>
                <li class="nav-item mb-2"><i class="fa-solid fa-envelope" style="color: #5b5b5b;"></i> 20191202@uthh.edu.mx</li>
            </ul>
        </div>
    </footer>

    <!--Js Bootstrap-->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ENjdO4Dr2bkBIFxQpeoTz1HIcje39Wm4jDKdf19U8gI4ddQ3GYNS7NTKfAdVQSZe" crossorigin="anonymous"></script>
    <!--Contenido JS-->
    @yield('contenidoJs')
</body>

</html>
