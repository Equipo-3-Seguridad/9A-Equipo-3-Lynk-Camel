<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Providers\RouteServiceProvider;
use App\Models\User;
use Illuminate\Foundation\Auth\RegistersUsers;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class RegisterController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Register Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles the registration of new users as well as their
    | validation and creation. By default this controller uses a trait to
    | provide this functionality without requiring any additional code.
    |
    */

    use RegistersUsers;

    /**
     * Where to redirect users after registration.
     *
     * @var string
     */
    protected $redirectTo = RouteServiceProvider::HOME;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest');
    }

    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function validator(array $data)
    {
        return Validator::make($data, [
            'name' => 'required|string|min:2|max:20|regex:/^[A-Za-z0-9áéíóúüñÑÁÉÍÓÚÜ\s]{2,30}$/',
            'lastname' => 'required|string|min:3|max:30|regex:/^[A-Za-z0-9áéíóúüñÑÁÉÍÓÚÜ\s]{2,30}$/',
            'birth' => 'required|string|min:8|max:10|regex:/^\d{4}-\d{2}-\d{2}$/',
            'gender' => 'required|string|min:1|max:1|regex:/^[MF]$/',
            'role' => 'required|string|min:2|max:12|regex:/^[A-Za-z0-9áéíóúüñÑÁÉÍÓÚÜ\s]{2,12}$/',
            'email' => 'required|string|min:5|max:100|regex:/^([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$/',
            'password' => 'required|string|min:8|max:20|regex:/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,20}$/|confirmed',
        ],
        [
            'name.required' => 'El nombre es obligatorio',
            'name.string' => 'Solo se aceptan cadenas de texto',
            'name.min' => 'No se aceptan nombres de menos de 2 caracteres',
            'name.max' => 'No se aceptan nombres de más de 2 caracteres',
            'name.regex' => 'No se aceptan caracteres especiales',
            'lastname.required' => 'El apellido es obligatorio',
            'lastname.string' => 'Solo se aceptan cadenas de texto',
            'lastname.min' => 'No se aceptan apellidos de menos de 3 caracteres',
            'lastname.max' => 'No se aceptan apellidos de más de 30 caracteres',
            'lastname.regex' => 'No se aceptan caracteres especiales',
            'birth.required' => 'La fecha de nacimiento es obligatoria',
            'birth.string' => 'Solo se aceptan valores con estructura de fecha',
            'birth.min' => 'No se aceptan fechas de menos de 8 caracteres',
            'birth.max' => 'No se aceptan fechas de más de 10 caracteres',
            'birth.regex' => 'Solo se aceptan fechas con la siguiente estructura dd/mm/aaaa',
            'gender.required' => 'El genero es necesario',
            'gender.string' => 'Solo se acepta 1 caracter',
            'gender.min' => 'No se acepta menos de 1 caracter',
            'gender.max' => 'No se acepta más de 1 caracter',
            'gender.regex' => 'Solo se aceptan valores M o F',
            'role.required' => 'El rol es obligatorio',
            'role.string' => 'Solo se aceptan cadenas de texto',
            'role.min' => 'No se aceptan cadenas de menos de 2 caracteres',
            'role.max' => 'No se aceptan cadenas de más de 2 caracteres',
            'role.regex' => 'No se aceptan caracteres especiales',
            'email.required' => 'El correo electrónico es obligatorio',
            'email.string' => 'Solo se aceptan correos electrónicos',
            'email.min' => 'No se aceptan correos electrónicos de menos de 5 caracteres',
            'email.max' => 'No se aceptan correos electronicos de más de 100 caracteres',
            'email.regex' => 'Solo se aceptan correos electrónicos que cumplan con la estructura adecuada',
            'password.required' => 'La contraseña es obligatoria',
            'password.string' => 'Solo se aceptan contraseñas',
            'password.min' => 'No se aceptan contraseñas de menos de 8 caracteres',
            'password.max' => 'No se aceptan contraseñas de más de 20 caracteres',
            'password.regex' => 'La contraseña debe contener al menos 1 letra mayuscula, 1 minuscula, 1 número y 1 caracter especial',
            'password.confirmed' => 'Las contraseñas no coinciden',
        ]);
    }

    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array  $data
     * @return \App\Models\User
     */
    protected function create(array $data)
    {
        return User::create([
            'name' => $data['name'],
            'lastname' => $data['lastname'],
            'birth' => $data['birth'],
            'gender' => $data['gender'],
            'role' => $data['role'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
        ]);
    }
}
