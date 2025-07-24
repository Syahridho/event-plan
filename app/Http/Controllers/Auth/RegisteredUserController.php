<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Mail\OtpMail;
use App\Models\Otp;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Validation\Rules;
use Inertia\Inertia;
use Inertia\Response;

class RegisteredUserController extends Controller
{
    /**
     * Display the registration view.
     */
    public function create(): Response
    {
        return Inertia::render('Auth/Register');
    }

    /**
     * Handle an incoming registration request.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function store(Request $request): RedirectResponse
    {
        $otpCode = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT); 
        $expiresAt = now()->addMinutes(10);    

        $request->validate([
            'name' => 'required|string|max:255',
            'username' => 'required|string|max:255|alpha_num|unique:'.User::class,
            'email' => 'required|string|lowercase|email|max:255|unique:'.User::class,
            'password' => ['required', 'confirmed', Rules\Password::defaults()],
        ]);

        $user = User::create([
            'uuid' => str()->uuid(),
            'name' => $request->name,
            'username' => $request->username,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'last_seen_at' => now(),
        ]);

        
        $otp = Otp::create([
            'email' => $request->email,
            'otp' => $otpCode,
            'expires_at' => $expiresAt,
        ]);

        Mail::to($user->email)->send(new OtpMail($otp));

        return redirect('/verify-otp')->with([
            'success' => 'Registration successful! Please check your email for the OTP.',
            'user_email' => $user->email,
        ]);
    }
}
