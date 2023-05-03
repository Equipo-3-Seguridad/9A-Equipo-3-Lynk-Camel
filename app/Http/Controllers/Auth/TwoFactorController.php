<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Notifications\TwoFactorCode;
use Illuminate\Http\Request;

class TwoFactorController extends Controller
{
    public function __construct()
    {
        $this->middleware(['auth', 'twofactor']);
    }

    public function index()
    {
        return view('auth.twoFactor');
    }

    public function store(Request $request)
    {
        $request->validate([
            'two_factor_code' => 'required|integer|min:6',
        ],
        [
            'two_factor_code.required' => 'Es necesario ingresar el código de dos factores',
            'two_factor_code.integer' => 'El código solo debe contener números enteros',
            'two_factor_code.min' => 'El código debe consistir de 6 caracteres',
        ]);

        $user = auth()->user();

        if($request->input('two_factor_code') == $user->two_factor_code)
        {
            $user->resetTwoFactorCode();
            if($user->role == 'Empleado'){
                return redirect()->route('home');
            }elseif($user->role == 'Empleador'){
                return redirect()->route('home');
            }elseif($user->role == 'Admin'){
                return redirect()->route('home');
            }
        }

        return redirect()->back()->withErrors(['two_factor_code' => 'El código de doble factor que has ingresado no coincide.']);
    }

    public function resend()
    {
        $user = auth()->user();
        $user->generateTwoFactorCode();
        $user->notify(new TwoFactorCode());

        return redirect()->back()->withMessage('El código de doble factor ha sido reenviado');
    }
}
