<?php

namespace App\Http\Controllers;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;
class SocialAuthController extends Controller
{
    //

    // public function redirectToProvider($provider)
    // {
    //     $url = Socialite::driver($provider)->stateless()->redirect()->getTargetUrl();

    //     return re
    // }


    public function redirectToProvider($provider)
    {
       return   Socialite::driver($provider)->stateless()->redirect();
    }
    
    public function handleProviderCallback($provider)
{
    // الحصول على بيانات المستخدم
    $user = Socialite::driver($provider)->stateless()->user();
    
    // إنشاء أو الحصول على المستخدم في قاعدة البيانات
    $user = User::firstOrCreate(
        ['email' => $user->getEmail()],
        [
            'name' => $user->getName(),
            'password' => Hash::make(uniqid()), // كلمة مرور عشوائية
            'provider' => $provider,
            'provider_id' => $user->getId(),
        ]
    );

    // إنشاء توكن JWT
    $token = JWTAuth::fromUser($user);

    // إعادة توجيه المستخدم إلى واجهة React مع التوكن
    // return redirect('http://localhost:5173/auth/success?token=' . $token);)
    // return response()->json([
    //     'token' => $token,
    //     'user' =>  $user,
    // ]);

    return redirect()->to(env('FRONTEND_URL') . "/auth/success?token=" .$token);
        
    
}
}
