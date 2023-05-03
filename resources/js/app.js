import './bootstrap';

//Contenido del slider
//Obteniendo los elementos html
const slider = document.querySelector("#slider");
let sliderSection = document.querySelectorAll(".slider__section");
let sliderSectionLast = sliderSection[sliderSection.length -1];
//Obteniendo los botones
const btnLeft = document.querySelector("#btn-left");
const btnRight = document.querySelector("#btn-right");
//Seleccionando la ultima imagen del carrusel y posicionandola antes de la primera
slider.insertAdjacentElement('afterbegin', sliderSectionLast);

//Botón derecho
function Next(){
    let sliderSectionFirst = document.querySelectorAll(".slider__section")[0];
    slider.style.marginLeft = "-200%";
    slider.style.transition = "all 0.5s";
    setTimeout(function(){
        slider.style.transition = "none";
        slider.insertAdjacentElement('beforeend', sliderSectionFirst);
        slider.style.marginLeft = "-100%"
    }, 500);
}

//Botón Izquierdo
function Prev(){
    let sliderSection = document.querySelectorAll(".slider__section");
    let sliderSectionLast = sliderSection[sliderSection.length -1];
    slider.style.marginLeft = "0%";
    slider.style.transition = "all 0.5s";
    setTimeout(function(){
        slider.style.transition = "none";
        slider.insertAdjacentElement('afterbegin', sliderSectionLast);
        slider.style.marginLeft = "-100%"
    }, 500);
}
//Evento del botón derecho al dar clic sobre el
btnRight.addEventListener('click', function(){
    Next();
});
//Evento del botón izquierdo al dar clic sobre el
btnLeft.addEventListener('click', function(){
    Prev();
});
//Evento para que el slider sea automatico
setInterval(function(){
    Next();
}, 5000);
