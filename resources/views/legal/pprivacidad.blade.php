<!--Se llama a la plantilla principal ya creada-->
@extends('plantillas.portada')

@section('titulo')
<title>Políticas de Privacidad</title>
@stop

@section('contenidoPrincipal')
<!--Breadcrumb-->
<nav aria-label="breadcrumb">
    <ol class="breadcrumb">
        <li id="bread1" class="breadcrumb-item text-dark"><a href="/"><i class="fas fa-home"></i> Inicio</a></li>
        <li id="bread2" class="breadcrumb-item active text-dark" aria-current="page">Políticas de Privacidad</li>
    </ol>
</nav>
<h3 class="text-dark fw-bold">Políticas de Privacidad</h3>
<div style="margin-bottom: 15%;">
    <p>En este sitio web, nos tomamos muy en serio la privacidad de nuestros usuarios y visitantes. En esta política de privacidad, explicamos cómo recopilamos, utilizamos, almacenamos y protegemos su información personal.</p>
    <p><strong>Información que recopilamos</strong></p>
    <p>Podemos recopilar la siguiente información personal de los usuarios y visitantes de nuestro sitio web:</p>
    <ul>
        <li>Nombre y apellidos</li>
        <li>Dirección de correo electrónico</li>
        <li>Número de teléfono</li>
        <li>Dirección postal</li>
        <li>Currículum vitae (CV) y carta de presentación</li>
        <li>Historial laboral</li>
        <li>Información sobre sus habilidades y experiencia</li>
    </ul>
    <p>Además, podemos recopilar información no personal, como la dirección IP, el tipo de navegador y el sistema operativo que está utilizando.</p>
    <p><strong>Cómo utilizamos su información personal</strong></p>
    <p>La información personal que recopilamos se utiliza para los siguientes fines:</p>
    <ul>
        <li>Procesar y gestionar su solicitud de empleo</li>
        <li>Comunicarnos con usted sobre las oportunidades de trabajo</li>
        <li>Mantener registros internos</li>
        <li>Mejorar nuestro sitio web y servicios</li>
        <li>Enviar correos electrónicos promocionales y boletines informativos (si ha optado por recibirlos)</li>
    </ul>
    <p>No compartimos su información personal con terceros, excepto cuando sea necesario para procesar su solicitud de empleo, cumplir con la ley o proteger nuestros derechos y propiedad.</p>
    <p><strong>Cómo protegemos su información personal</strong></p>
    <p>Hemos implementado medidas de seguridad adecuadas para proteger su información personal de accesos no autorizados, divulgación o destrucción. Solo nuestro personal autorizado tiene acceso a su información personal.</p>
    <p>Sin embargo, debe tener en cuenta que ninguna transmisión de datos a través de Internet o de cualquier red inalámbrica puede garantizarse como 100% segura. Por lo tanto, no podemos garantizar la seguridad de su información personal transmitida a través de nuestro sitio web.</p>
    <p><strong>Cookies y tecnologías similares</strong></p>
    <p>Utilizamos cookies y otras tecnologías similares para recopilar información no personal sobre los usuarios de nuestro sitio web. Las cookies nos permiten proporcionar una mejor experiencia de usuario y personalizar los anuncios que se muestran en nuestro sitio web.</p>
    <p>Puede optar por no aceptar las cookies en su navegador web, pero esto puede afectar la funcionalidad de nuestro sitio web.</p>
    <p><strong>Enlaces a sitios web de terceros</strong></p>
    <p>Nuestro sitio web puede contener enlaces a sitios web de terceros. No somos responsables de las políticas de privacidad o prácticas de los sitios web de terceros. Le recomendamos que revise las políticas de privacidad de estos sitios web de terceros antes de proporcionar cualquier información personal.</p>
    <p><strong>Cambios a nuestra política de privacidad</strong></p>
    <p>Nos reservamos el derecho de actualizar o cambiar nuestra política de privacidad en cualquier momento. Si realizamos cambios importantes en nuestra política de privacidad, publicaremos un aviso en nuestro sitio web.</p>
    <p><strong>Contáctenos</strong></p>
    <p>Si tiene alguna pregunta o inquietud acerca de nuestra política de privacidad, puede comunicarse con nosotros a través de nuestro correo electrónico.</p>
</div>
@stop
