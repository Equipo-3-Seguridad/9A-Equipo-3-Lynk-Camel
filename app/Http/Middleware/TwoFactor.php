<?php

namespace App\Http\Middleware;

use Closure;

class TwoFactor
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $user = auth()->user();

        if(auth()->check() && $user->two_factor_code)
        {
            if($user->two_factor_expires_at<now()) //expired
            {
                $user->resetTwoFactorCode();
                auth()->logout();

                return redirect()->route('login')
                ->withMessage('El código de dos factores ha expirado. Por favor inicia sesión otra vez.');
            }

            if(!$request->is('verify*')) //prevent endless loop, otherwise send to verify
            {
                return redirect()->route('verify.index');
            }
        }

        return $next($request);
    }
}
