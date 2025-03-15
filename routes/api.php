<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\ResetPasswordController;
use App\Http\Controllers\VerifyEmailController;
use App\Http\Controllers\SocialAuthController;
// Ensure the SocialAuthController class exists in the specified namespace
// If it does not exist, create the class in the specified namespace

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});

   
Route::get('{provider}/url', [SocialAuthController::class, 'getAuthUrl']);
Route::post('{provider}/callback', [SocialAuthController::class, 'handleCallback']);
Route::get('user', [SocialAuthController::class, 'getUserInfo'])->middleware('auth:api');

Route::get('/email/verify/{id}/{hash}', [VerifyEmailController::class, 'verify'])->name('verification.verify')->middleware(['signed','throttle:6,1']);
Route::post('/resend', [VerifyEmailController::class, 'resend'])->name('verification.resend')->middleware('throttle:5,1');


    Route::post('register', [AuthController::class, 'register']);
    Route::post('login', [AuthController::class, 'login']);


Route::post('/forget-password', [ResetPasswordController::class, 'sendResetLink']);
Route::post('/reset-password', [ResetPasswordController::class, 'resetPassword']);


Route::group([
    'middleware' => 'auth:api'
], function () {
    Route::get('me', [AuthController::class, 'me']);
    Route::post('logout', [AuthController::class, 'logout']);
});

Route::post('refresh', [AuthController::class, 'refreshToken']);
