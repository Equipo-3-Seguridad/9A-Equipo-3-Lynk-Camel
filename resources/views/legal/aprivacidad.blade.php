<!--Se llama a la plantilla principal ya creada-->
@extends('plantillas.portada')

@section('titulo')
<title>Aviso de Privacidad</title>
@stop

@section('contenidoPrincipal')
<!--Breadcrumb-->
<nav aria-label="breadcrumb">
    <ol class="breadcrumb">
        <li id="bread1" class="breadcrumb-item text-dark"><a href="/"><i class="fas fa-home"></i> Inicio</a></li>
        <li id="bread2" class="breadcrumb-item active text-dark" aria-current="page">Aviso de Privacidad</li>
    </ol>
</nav>
<h3 class="text-dark fw-bold">Aviso de Privacidad</h3>
<div class="text-justify" style="margin-bottom: 15%;">
    <p>
        Este aviso de privacidad explica cómo recopilamos, usamos y protegemos la información personal que recopilamos a través de nuestro sitio web de búsqueda de empleos.
    </p>
    <p><strong>Información personal que recopilamos</strong></p>
    <p>Podemos recopilar información personal que nos proporciona al registrarse para usar nuestro servicio, como su nombre, dirección de correo electrónico, número de teléfono y CV. También podemos recopilar información sobre su experiencia laboral y educación.</p>

    <p><strong>Uso de la información personal</strong></p>
    <p>Utilizamos la información personal que recopilamos para ayudar a conectar a los buscadores de empleo con los empleadores. Podemos compartir su información con los empleadores que están buscando candidatos para los trabajos que se publican en nuestro sitio web. También podemos usar su información para enviarle correos electrónicos relacionados con nuestros servicios.</p>

    <p><strong>Protección de la información personal</strong></p>
    <p>Nos tomamos muy en serio la seguridad de su información personal y tomamos medidas razonables para protegerla contra el acceso no autorizado, la alteración o la divulgación. Sin embargo, no podemos garantizar la seguridad de la información que nos envía a través de nuestro sitio web.</p>

    <p><strong>Divulgación de información personal</strong></p>
    <p>No vendemos ni alquilamos su información personal a terceros. Sin embargo, podemos compartir su información personal con los empleadores que están buscando candidatos para los trabajos que se publican en nuestro sitio web. También podemos divulgar su información si se nos exige por ley.</p>

    <p><strong>Sus derechos de privacidad</strong></p>
    <p>Si desea revisar o actualizar la información personal que hemos recopilado sobre usted, o si desea que eliminemos su información personal de nuestro sistema, comuníquese con nosotros a través de la información de contacto que se proporciona en nuestro sitio web.</p>

    <p><strong>Cambios a este aviso de privacidad</strong></p>
    <p>Podemos actualizar este aviso de privacidad de vez en cuando. Si hacemos cambios significativos, publicaremos una notificación en nuestro sitio web y/o le enviaremos un correo electrónico para informarle del cambio.
        Si tiene alguna pregunta o inquietud sobre este aviso de privacidad o sobre cómo manejamos su información personal, no dude en ponerse en contacto con nosotros a través de la información de contacto proporcionada en nuestro sitio web.</p>
</div>
@stop
