<!--Se llama a la plantilla principal ya creada-->
@extends('plantillas.portada')

@section('titulo')
<title>Conócenos</title>
@stop

@section('contenidoPrincipal')
<!--Breadcrumb-->
<nav aria-label="breadcrumb">
    <ol class="breadcrumb">
        <li id="bread1" class="breadcrumb-item text-dark"><a href="/"><i class="fas fa-home"></i> Inicio</a></li>
        <li id="bread2" class="breadcrumb-item active text-dark" aria-current="page">Conócenos</li>
    </ol>
</nav>
<div class="">
    <h3 class="text-dark fw-bold m">Misión</h3>
    <p>Somos una empresa que permite a los usuarios encontrar empleo de manera segura y confiable, y a los empleadores y empresas contar con futuros empleados con capacidad para desempeñar un buen trabajo. </p>
    <h3 class="text-dark fw-bold m">Visión</h3>
    <p>Ser una empresa que facilite el contacto de los usuarios con empleadores o empresas que estén en busca de personal que cumpla con sus habilidades sin importar el nivel profesional de los empleados, pero con experiencia comprobable. </p>
    <h3 class="text-dark fw-bold m">Valores</h3>
    <p>Lynk Camel busca ser una empresa seria con el objetivo de brindar un buen servicio a todos los usuarios que accedan al sitio en busca de empleos ya sea profesiones u oficios, tomando en cuenta usuarios que publiquen que solicitan empleados estar comprometidos con su bienestar inspirando tranquilidad, seguridad y confianza.</p>
    <ol class="valores" start="1">
        <li>Respeto: Tratar bien a los usuarios y al equipo de trabajo que hacen posible el funcionamiento de la empresa. </li>
        <li>Responsabilidad: Actuar de la mejor manera posible para la solución de problemas y para brindar un servicio de calidad. </li>
        <li>Compromiso: Cumplir con nuestras obligaciones para brindar una buena experiencia a nuestros usuarios. </li>
        <li>Disponibilidad: Tener un servicio confiable al cual se pueda acceder en cualquier momento. </li>
        <li>Calidad: Brindar un servicio en el que los usuarios puedan confiar. </li>
        <li>Compasión: Dar un buen trato mediante el sitio, comprender mejor y dar respuesta a las necesidades de los usuarios. </li>
        <li>Honestidad: Actuar con honestidad a los usuarios para dar un mejor servicio. </li>
        <li>Generosidad: Ser generosos con las personas que utilicen el sitio para fortalecer su sentido como empresa u organización, para brindar seguridad, lealtad y confianza que los inspire a realizar un esfuerzo adicional para servir a los demás. </li>
        <li>Solidaridad: Buscar apoyar a los usuarios para que encuentren un empleo o empleados. </li>
        <li>Empatía: Ponernos en el lugar de los usuarios que necesitan un servicio mediante una necesidad.</li>
        <li>Tolerancia: Respetando a todos los usuarios y colaboradores. </li>
    </ol>
</div>

@stop
