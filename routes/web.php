<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Auth\TwoFactorController;


/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/
//Rutas Exteriores
Route::get('/', function () {
    return view('inicio.index');
});
Route::get('/conocenos', function () {
    return view('legal.misionvision');
});
Route::get('/empleos', function () {
    return view('empleos.index');
});
Route::get('/politica-privacidad', function () {
    return view('legal.pprivacidad');
});
Route::get('/politica-uso', function () {
    return view('legal.puso');
});
Route::get('/aviso-privacidad', function () {
    return view('legal.aprivacidad');
});
//Rutas de Error
Route::get('/error-400', function () {
    abort(400, 'Bad request');
});
Route::get('/error-404', function () {
    abort(404, 'Not found');
});
Route::get('/error-500', function () {
    abort(500, 'Internal server error');
});
//Activando las rutas de verificación de la autenticación
Auth::routes(['verify'=>true]);

Route::get('/home', [App\Http\Controllers\HomeController::class, 'index'])->name('home');

//Posiblemente haya algún fallo en restear la contraseña...

//Rutas para la autenticación de 2 factores
Route::get('verify/resend', [TwoFactorController::class, 'resend'])->name('verify.resend');
Route::resource('verify', TwoFactorController::class)->only(['index', 'store']);

/*
Ejemplo de rutas
Route::group(['prefix' => 'admin', 'as' => 'admin.', 'namespace' => 'Admin', 'middleware' => ['auth', 'twofactor']], function () {
    Route::get('/', 'HomeController@index')->name('home');
    // Permissions
    Route::delete('permissions/destroy', 'PermissionsController@massDestroy')->name('permissions.massDestroy');
    Route::resource('permissions', 'PermissionsController');

    // Roles
    Route::delete('roles/destroy', 'RolesController@massDestroy')->name('roles.massDestroy');
    Route::resource('roles', 'RolesController');

    // Users
    Route::delete('users/destroy', 'UsersController@massDestroy')->name('users.massDestroy');
    Route::resource('users', 'UsersController');
});
*/
