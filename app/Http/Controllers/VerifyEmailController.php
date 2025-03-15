<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Auth\Events\Verified;
use Illuminate\Support\Facades\Validator;
class VerifyEmailController extends Controller
{
   
    public function verify( $id, $hash)
    {
        $user = User::findOrFail($id);

        if (! hash_equals((string) $hash, sha1($user->getEmailForVerification()))) {
            return response()->json(['message' => 'Invalid verification link'], 400);
        }

        if ($user->hasVerifiedEmail()) {
            return response()->json(['message' => 'Email already verified'], 400);
        }

        $user->markEmailAsVerified();
        event(new Verified($user));
        // return response()->json(['message' => 'Email verified successfully', 'user' => $user], 200);
       return response()->json(['message' => 'Email verified successfully','status' => 'success'], 200);
    }

    public function resend(Request $request)
{
    $validator = Validator::make($request->all(), [
        'email' => 'required|email',
    ]);

    if ($validator->fails()) {
        return response()->json([
            'message' => 'فشل التحقق',
            'errors' => $validator->errors(),
            'status' => 'error'
        ], 400);
    }

    $user = User::where('email', $request->email)->first();

    if (!$user) {
        return response()->json([
            'message' => 'المستخدم غير موجود',
            'status' => 'error'
        ], 404);
    }

    if ($user->hasVerifiedEmail()) {
        return response()->json([
            'message' => 'البريد الإلكتروني متحقق منه مسبقاً',
            'status' => 'warning'
        ], 400);
    }

    $user->sendEmailVerificationNotification();

    return response()->json([
        'message' => 'تم إرسال رابط التحقق إلى بريدك الإلكتروني',
        'status' => 'success'
    ], 200);
}
}
