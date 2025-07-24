<?php

namespace App\Http\Controllers\Auth;

use Inertia\Inertia;
use App\Mail\OtpMail;
use Inertia\Response;
use App\Models\OtpToken;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Models\Otp;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use App\Providers\RouteServiceProvider;

class OtpController extends Controller
{
    public function create(): Response
    {
        return Inertia::render('Auth/Otp');
    }

    public function verifyOtp(Request $request)
    {
        $request->validate([
            'otp' => 'required|string',
        ]);

        $otpToken = Otp::where('otp', $request->otp)
                    ->where('expires_at', '>', now())
                    ->first();

        if (!$otpToken) {
            return back()->withErrors(['otp' => 'Invalid or expired OTP']);
        }

        $user = $otpToken->user;

        if (!$user) {
            return back()->withErrors(['otp' => 'User not found.']);
        }

        $otpToken->delete();

        $user->email_verified_at = now();
        $user->save();

        Auth::login($user);

        return redirect()->intended(RouteServiceProvider::HOME)->with('success', 'Login berhasil!');
    }

    public function resendOtp(Request $request)
    {
        $request->validate([
            'email' => 'required|email|exists:users,email',
        ]);

        $otp = Otp::where('email', $request->email)->first();

        $otpCode = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $expiresAt = now()->addMinutes(10);

        $otp->otp = $otpCode;
        $otp->expires_at = $expiresAt;
        $otp->save();

        Mail::to($otp->email)->send(new OtpMail($otp));

        return back()->with('success', 'OTP resent successfully! Please check your email.');
     
    }
}
