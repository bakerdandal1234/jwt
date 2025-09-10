<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController; // Ensure this class exists in the specified namespace
use App\Http\Controllers\ResetPasswordController;
use App\Http\Controllers\VerifyEmailController;
use App\Http\Controllers\SocialAuthController;
use App\Http\Controllers\TaskController;
// Ensure the SocialAuthController class exists in the specified namespace
// If it does not exist, create the class in the specified namespace

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});

   
Route::get('{provider}/url', [SocialAuthController::class, 'getAuthUrl']);
Route::post('{provider}/callback', [SocialAuthController::class, 'handleCallback']);

Route::get('/email/verify/{id}/{hash}', [VerifyEmailController::class, 'verify'])->name('verification.verify')->middleware(['signed','throttle:6,1']);
Route::post('/resend', [VerifyEmailController::class, 'resend'])->name('verification.resend')->middleware('throttle:5,1');


    Route::post('register', [AuthController::class, 'register'])->middleware('throttle:5,1');
    Route::post('login', [AuthController::class, 'login'])->middleware('throttle:5,1');


Route::post('/forget-password', [ResetPasswordController::class, 'sendResetLink'])->middleware('throttle:5,1');
Route::post('/reset-password', [ResetPasswordController::class, 'resetPassword'])->middleware('throttle:5,1');


Route::group([
    'middleware' => ['api','auth:api']
], function () {
    Route::get('me', [AuthController::class, 'me']);
    Route::post('logout', [AuthController::class, 'logout']);
});

Route::post('refresh', [AuthController::class, 'refreshToken'])->middleware('throttle:5,1');

// Route::middleware(['auth:api','permission:create task'])->group(function () {
//     Route::apiResource('tasks', TaskController::class);
// });

Route::middleware(['auth:api'])->group(function () {
    Route::get('tasks', [TaskController::class, 'index'])->middleware('permission:view task');
    Route::post('tasks', [TaskController::class, 'store'])->middleware('permission:create task');
    Route::put('tasks/{task}', [TaskController::class, 'update'])->middleware('permission:edit task');
    Route::delete('tasks/{task}', [TaskController::class, 'destroy'])->middleware('permission:delete task');
});
