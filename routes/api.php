<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\ResetPasswordController;
use App\Http\Controllers\VerifyEmailController;
use App\Http\Controllers\SocialAuthController;
Route::middleware('auth:api')->group(function(){
    Route::get('/user', function (Request $request) {
        return $request->user();
    });
});


    Route::get('auth/{provider}', [SocialAuthController::class, 'redirectToProvider']);
    Route::get('auth/{provider}/callback', [SocialAuthController::class, 'handleProviderCallback']);


Route::get('/email/verify/{id}/{hash}', [VerifyEmailController::class, 'verify'])->name('verification.verify')->middleware(['signed','throttle:6,1']);
Route::post('/resend', [VerifyEmailController::class, 'resend']);

Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);
Route::post('/forget-password', [ResetPasswordController::class, 'sendResetLink']);
Route::post('/reset-password', [ResetPasswordController::class, 'resetPassword']);



Route::middleware('auth:api')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('/refresh', [AuthController::class, 'refresh']);
    Route::get('/user-profile', [AuthController::class, 'userProfile']);
});

