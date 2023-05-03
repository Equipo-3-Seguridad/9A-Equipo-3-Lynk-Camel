<!--Se llama a la plantilla principal ya creada-->
@extends('plantillas.portada')

@section('titulo')
<title>Políticas de Uso</title>
@stop

@section('contenidoPrincipal')
<!--Breadcrumb-->
<nav aria-label="breadcrumb">
    <ol class="breadcrumb">
        <li id="bread1" class="breadcrumb-item text-dark"><a href="/"><i class="fas fa-home"></i> Inicio</a></li>
        <li id="bread2" class="breadcrumb-item active text-dark" aria-current="page">Políticas de Uso</li>
    </ol>
</nav>
<h3 class="text-dark fw-bold">Políticas de Uso</h3>
<div style="margin-bottom: 15%;">
    <p>Gracias por utilizar nuestro sitio web de búsqueda de empleo. Por favor, lee atentamente nuestra política de uso antes de utilizar nuestros servicios. Al utilizar nuestro sitio web, aceptas los términos y condiciones descritos en esta política.</p>
    <p><strong>Propósito del Sitio Web</strong></p>
    <p>El propósito de nuestro sitio web de búsqueda de empleo es ayudar a los usuarios a encontrar oportunidades laborales que se ajusten a sus habilidades y experiencia. No garantizamos que los usuarios encuentren empleo a través de nuestro sitio web, pero haremos todo lo posible para ofrecer las mejores oportunidades laborales disponibles en nuestra base de datos.</p>
    <p><strong>Responsabilidades del Usuario</strong></p>
    <p>El usuario se compromete a utilizar nuestro sitio web de manera responsable y no utilizarlo para cualquier actividad ilegal o fraudulenta. El usuario debe proporcionar información precisa y actualizada al utilizar nuestro sitio web y acepta que cualquier información proporcionada será verificada por nosotros.</p>
    <p><strong>Responsabilidades de la Empresa</strong></p>
    <p>Nuestra empresa se compromete a proporcionar información precisa y actualizada sobre las oportunidades laborales disponibles en nuestra base de datos. No nos hacemos responsables de la veracidad de la información proporcionada por los empleadores y no garantizamos que los usuarios encuentren empleo a través de nuestro sitio web.</p>
    <p><strong>Privacidad de los Usuarios</strong></p>
    <p>Nos comprometemos a proteger la privacidad de nuestros usuarios y no compartiremos su información personal con terceros sin su consentimiento. Sin embargo, nos reservamos el derecho de proporcionar información personal de los usuarios si se nos solicita por motivos legales.</p>
    <p><strong>Propiedad Intelectual</strong></p>
    <p>Todos los contenidos en nuestro sitio web son propiedad de nuestra empresa y están protegidos por las leyes de propiedad intelectual. El usuario se compromete a no utilizar el contenido del sitio web para ningún propósito que no sea el uso personal del sitio web.</p>
    <p><strong>Modificaciones de la Política</strong></p>
    <p>Nos reservamos el derecho de modificar esta política en cualquier momento. Es responsabilidad del usuario leer y revisar esta política de forma regular para mantenerse informado sobre los términos y condiciones actuales.
        Al utilizar nuestro sitio web de búsqueda de empleo, aceptas los términos y condiciones descritos en esta política de uso. Si tienes alguna pregunta o preocupación sobre esta política, por favor contáctanos.</p>
</div>
@stop
