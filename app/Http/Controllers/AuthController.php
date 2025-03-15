<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use App\Models\User;
use App\Models\RefreshToken;
use Illuminate\Support\Str;
use Carbon\Carbon;

class AuthController extends Controller
{
    /**
     * إنشاء مثيل جديد من وحدة التحكم.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register', 'refreshToken']]);
    }

    /**
     * تسجيل مستخدم جديد.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        // إنشاء JWT للمستخدم الجديد
        $token = Auth::guard('api')->login($user);
        $refreshToken = $this->createRefreshToken($user);

        return $this->respondWithTokens($token, $refreshToken, 'تم تسجيل المستخدم بنجاح', $user);
    }

    /**
     * تسجيل الدخول وإنشاء رموز JWT.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $credentials = $request->only('email', 'password');

        if (!$token = Auth::guard('api')->attempt($credentials)) {
            return response()->json(['message' => 'بيانات الاعتماد غير صحيحة'], 401);
        }

        $user = Auth::guard('api')->user();
        
        // إلغاء جميع رموز التحديث السابقة للمستخدم
        RefreshToken::where('user_id', $user->id)->update(['revoked' => true]);
        
        // إنشاء رمز تحديث جديد
        $refreshToken = $this->createRefreshToken($user);

        return $this->respondWithTokens($token, $refreshToken, 'تم تسجيل الدخول بنجاح', $user);
    }

    /**
     * الحصول على المستخدم المصادق عليه حاليًا.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return $this->response()->json(Auth::guard('api')->user());
    }

    /**
     * تسجيل الخروج (إبطال الرموز الحالية).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        $user = Auth::guard('api')->user();
        
        // إلغاء جميع رموز التحديث للمستخدم
        if ($user) {
            RefreshToken::where('user_id', $user->id)->update(['revoked' => true]);
        }
        
        Auth::guard('api')->logout();

        return response()->json(['message' => 'تم تسجيل الخروج بنجاح']);
    }

    /**
     * تحديث رمز JWT باستخدام رمز التحديث.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refreshToken(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'refresh_token' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        // البحث عن رمز التحديث في قاعدة البيانات
        $refreshTokenModel = RefreshToken::where('token', $request->refresh_token)
            ->where('revoked', false)
            ->where('expires_at', '>', now())
            ->first();

        if (!$refreshTokenModel) {
            return response()->json(['error' => 'رمز التحديث غير صالح أو منتهي الصلاحية'], 401);
        }

        $user = User::find($refreshTokenModel->user_id);
        
        if (!$user) {
            return response()->json(['error' => 'المستخدم غير موجود'], 404);
        }

        // إلغاء رمز التحديث الحالي
        $refreshTokenModel->update(['revoked' => true]);
        
        // إنشاء رمز JWT جديد للمستخدم
        Auth::guard('api')->setUser($user);
        $token = Auth::guard('api')->refresh();
        
        // إنشاء رمز تحديث جديد
        $newRefreshToken = $this->createRefreshToken($user);

        return $this->respondWithTokens($token, $newRefreshToken, 'تم تحديث الرمز بنجاح');
    }

    /**
     * إنشاء رمز تحديث للمستخدم.
     *
     * @param  \App\Models\User $user
     * @return string
     */
    protected function createRefreshToken(User $user)
    {
        // إنشاء رمز فريد
        $token = Str::random(64);
        
        // تحديد تاريخ انتهاء الصلاحية (30 يوم)
        $expiresAt = Carbon::now()->addDays(30);
        
        // تخزين رمز التحديث في قاعدة البيانات
        RefreshToken::create([
            'user_id' => $user->id,
            'token' => $token,
            'expires_at' => $expiresAt,
            'revoked' => false
        ]);
        
        return $token;
    }

    /**
     * الرد برموز JWT والتحديث وتفاصيلها.
     *
     * @param  string $token
     * @param  string $refreshToken
     * @param  string $message
     * @param  mixed  $user
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithTokens($token, $refreshToken, $message = null, $user = null)
    {
        $response = [
            'access_token' => $token,
            'refresh_token' => $refreshToken,
            'token_type' => 'bearer',
            'expires_in' => Auth::guard('api')->factory()->getTTL() * 60 // مدة صلاحية الرمز بالثواني
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