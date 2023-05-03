<!--Se llama a la plantilla principal ya creada-->
@extends('plantillas.portada')

@section('titulo')
<title>Error 500</title>
@stop

@section('contenidoPrincipal')
<!--Breadcrumb-->
<nav aria-label="breadcrumb">
    <ol class="breadcrumb">
        <li id="bread1" class="breadcrumb-item text-dark"><a href="/"><i class="fas fa-home"></i> Inicio</a></li>
        <li id="bread2" class="breadcrumb-item active text-dark" aria-current="page">Error 500</li>
    </ol>
</nav>
<h3 class="text-dark fw-bold m"><center>Error 500</center></h3>
<!--Llamando a la imagen-->
<img class="error-img" src="{{ asset('img/error500.PNG') }}" style="margin-bottom: 15%; border: 5px solid black" alt="">
@endsection
