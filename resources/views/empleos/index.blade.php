@extends('plantillas.portada')

@section('titulo')
<title>Buscar empleos</title>
@stop

@section('contenidoPrincipal')
<!--Breadcrumb-->
<nav aria-label="breadcrumb">
    <ol class="breadcrumb">
        <li id="bread1" class="breadcrumb-item text-dark"><a href="/"><i class="fas fa-home"></i> Inicio</a></li>
        <li id="bread2" class="breadcrumb-item active text-dark" aria-current="page">Empleos</li>
    </ol>
</nav>
<h3 class="fw-bold text-dark">Empleos</h3>
<div class="container-fluid bg-light rounded-3" style="width: 98%">
    <!----Botón de Búsqueda----->
    <form action="" method="get">
        <br>
        <div class="input-group">
            <div class="form-outline">
                @csrf
                <label class="form-label fw-bold">Realizar Búsqueda</label>
                <!--Aquí va la variable busqueda value=""-->
                <input type="text" id="form1" class="form-control bg-white" placeholder="Buscar..." name="busqueda" value="" pattern="^[A-Za-z0-9áéíóúüñÑÁÉÍÓÚÜ\s]{0,60}$" title="No se aceptan caracteres especiales" />
                <br>
                <select class="form-select text-white bg-danger border-danger" aria-label="Default select example" placeholder="Marca" name="marca" value="">
                    <option value="Tipo">Tipo</option>
                    <option value="Profesion">Profesión</option>
                    <option value="Oficio">Oficio</option>
                </select>
            </div>
            <div>

            </div>
            <br>
        </div>
    </form>

</div>
@stop
