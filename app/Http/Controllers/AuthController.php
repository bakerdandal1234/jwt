<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;
use App\Models\User;
use Illuminate\Support\Str;
use Carbon\Carbon;
use App\Models\RefreshToken;
use Illuminate\Support\Facades\Cookie;

class AuthController extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register', 'refreshToken']]);
    }

    /**
     * Register a new user.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|min:3',
            'email' => 'required|string|email|unique:users,email',
            'password' => 'required|min:8|confirmed',
            'password_confirmation' => 'required'
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);
        $user->sendEmailVerificationNotification();

        // Create JWT for the new user
        $token = Auth::guard('api')->login($user);

        // Create refresh token and get the cookie
        $refreshTokenCookie = $this->createRefreshTokenAndGetCookie($user);

        return $this->respondWithToken($token, 'User registered successfully', $user)
            ->withCookie($refreshTokenCookie);
    }

    /**
     * Login and create JWT tokens.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        // Check if the user exists and email is verified
        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return response()->json(['error' => 'Email or password is incorrect'], 401);
        }

        // if (is_null($user->email_verified_at)) {
        //     return response()->json(['error' => 'Please verify your email before logging in.'], 403);
        // }

        // Attempt to authenticate the user
        if (!Auth::guard('api')->attempt($credentials)) {
            return response()->json(['error' => 'Email or password is incorrect'], 401);
        }

        // Successful login
        $user = Auth::guard('api')->user();

        // Create a new refresh token and get the cookie
        $refreshTokenCookie = $this->createRefreshTokenAndGetCookie($user);
        $token = Auth::guard('api')->login($user);

        return $this->respondWithToken($token, 'Login successful', $user)
            ->withCookie($refreshTokenCookie);
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    // public function me()
    // {
    //     return response()->json(Auth::guard('api')->user());
    // }

    public function me()
{
    return response()->json(
        Auth::user()->load('tasks') // أو: load('roles', 'permissions', 'tasks')
    );
}

    /**
     * Logout (invalidate current tokens).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
{
    $user = Auth::guard('api')->user();

    if ($user) {
        // الحصول على الرمز من الكوكي
        $refreshTokenValue = request()->cookie('refresh_token');
        
        if ($refreshTokenValue) {
            // حذف الرمز من قاعدة البيانات
            $hashedToken = hash('sha256', $refreshTokenValue);
            RefreshToken::where('user_id', $user->id)
                ->where('token', $hashedToken)
                ->delete();
                
            Log::info('تم حذف رمز التحديث عند تسجيل الخروج للمستخدم: ' . $user->id);
        }
    }

    // حذف الكوكي
    $cookie = Cookie::forget('refresh_token');

    // تسجيل الخروج من النظام
    Auth::guard('api')->logout();

    return response()->json(['message' => 'تم تسجيل الخروج بنجاح'])
        ->withCookie($cookie);
}

    /**
     * Refresh JWT token using a refresh token from cookie.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refreshToken(Request $request)
    {
        Log::info('🍪 [Refresh Attempt] محاولة تحديث الرمز.');
    
        // الحصول على رمز التحديث من الكوكي
        $refreshTokenValue = $request->cookie('refresh_token');
        Log::info('🍪 [Refresh Token] الكوكي: ' . ($refreshTokenValue ? 'موجود' : 'غير موجود'));
    
        if (!$refreshTokenValue) {
            Log::error('🍪 [Refresh Token Error] لم يتم العثور على رمز التحديث في الكوكيز.');
            return response()->json(['error' => 'لم يتم العثور على رمز التحديث في الكوكيز'], 401);
        }
    
        try {
            // تشفير الرمز للبحث عنه في قاعدة البيانات
            $hashedToken = hash('sha256', $refreshTokenValue);
            
            // البحث عن رمز التحديث في قاعدة البيانات
            $refreshToken = RefreshToken::where('token', $hashedToken)
                ->where('expires_at', '>', Carbon::now())
                ->first();
            
            if (!$refreshToken) {
                Log::error('🍪 [Refresh Token Error] رمز التحديث غير صالح أو منتهي الصلاحية.');
                return response()->json(['error' => 'رمز التحديث غير صالح أو منتهي الصلاحية'], 401);
            }
            
            // البحث عن المستخدم المرتبط بالرمز
            $user = User::find($refreshToken->user_id);
            
            if (!$user) {
                Log::error('🍪 [Refresh Token Error] لم يتم العثور على المستخدم (معرف: ' . $refreshToken->user_id . ')');
                return response()->json(['error' => 'المستخدم غير موجود'], 401);
            }
            
            // إنشاء رمز JWT جديد
            $token = Auth::guard('api')->login($user);
            
            Log::info('🍪 [Refresh Token] تم تحديث رمز الوصول بنجاح للمستخدم: ' . $user->id);
            
            // إرجاع الرمز الجديد مع الاحتفاظ برمز التحديث الحالي
            return $this->respondWithToken($token, 'تم تحديث رمز الوصول بنجاح');
            
        } catch (\Exception $e) {
            Log::error('🍪 [Refresh Token Error] ' . $e->getMessage());
            return response()->json(['error' => 'فشل في تحديث الرمز: ' . $e->getMessage()], 401);
        }
    }

    /**
     * Create a refresh token for the user and return an HTTP cookie.
     *
     * @param  \App\Models\User $user
     * @return \Symfony\Component\HttpFoundation\Cookie
     */
    protected function createRefreshTokenAndGetCookie(User $user)
    {
        // إنشاء رمز تحديث عشوائي
        $token = Str::random(64);
        
        // تخزين نسخة مشفرة من الرمز في قاعدة البيانات
        $hashedToken = hash('sha256', $token);
        
        // تعيين تاريخ انتهاء الصلاحية (30 يوم)
        $expiresAt = Carbon::now()->addDays(30);
        
        // إنشاء أو تحديث رمز التحديث في قاعدة البيانات
        RefreshToken::create([
            'user_id' => $user->id,
            'token' => $hashedToken,
            'expires_at' => $expiresAt
        ]);
        
        // تسجيل العملية
        Log::info('تم إنشاء رمز تحديث جديد للمستخدم: ' . $user->id);
        $secure = app()->environment('production');
        // إنشاء كوكي يحتوي على الرمز
        return cookie(
            'refresh_token',    // الاسم
            $token,             // القيمة (النسخة غير المشفرة)
            43200,              // المدة بالدقائق (30 يوم)
            '/',                // المسار
            null,               // المجال (null = المجال الحالي)
            $secure,              // آمن (في الإنتاج يجب تغييره إلى true)
            true,               // httpOnly (غير قابل للوصول عبر جافا سكريبت)
            false,              // خام
            'lax'               // sameSite
        );
    }

    /**
     * Respond with JWT token and details.
     *
     * @param  string $token
     * @param  string $message
     * @param  mixed  $user
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token, $message = null, $user = null)
    {
        $response = [
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => Auth::guard('api')->factory()->getTTL() * 60, // Token validity in seconds
        ];

        if ($message) {
            $response['message'] = $message;
        }

        if ($user) {
            $response['user'] = $user;
        }

        return response()->json($response);
    }
}
