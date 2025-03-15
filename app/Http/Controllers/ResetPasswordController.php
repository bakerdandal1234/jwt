<?php

namespace App\Http\Controllers;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;
use Illuminate\Auth\Passwords\CanResetPassword as ResetsPasswords;
use Illuminate\Support\Facades\Password;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class ResetPasswordController extends Controller
{
    use ResetsPasswords;
     

    public function sendResetLink(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        $status = Password::sendResetLink($request->only('email'));

        switch ($status) {
            case Password::RESET_LINK_SENT:
                return response()->json(['message' => 'Password reset link has been sent to your email', 'status' => 'success']);
            case Password::RESET_THROTTLED:
                return response()->json(['message' => 'Please wait before requesting another reset link', 'status' => 'error'], 429);
            case Password::INVALID_USER:
                return response()->json(['message' => 'No user found with this email address', 'status' => 'error'], 404);
            default:
                return response()->json(['message' => 'Unable to send password reset link', 'status' => 'error'], 500);
        }
    }



    public function resetpassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'token' => 'required',
            'email' => 'required|email',
            'password' => 'required|confirmed|min:8',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        $status = Password::reset($request->only('email', 'password', 'password_confirmation', 'token'), function ($user, $password) {
            $user->forceFill([
                'password' => Hash::make($password)
            ])->save();
        });

        switch ($status) {
            case Password::PASSWORD_RESET:
                return response()->json(['message' => 'Password has been reset successfully', 'status' => 'success']);
            case Password::INVALID_TOKEN:
                return response()->json(['message' => 'Invalid reset token', 'status' => 'error'], 400);
            case Password::INVALID_USER:
                return response()->json(['message' => 'No user found with this email address', 'status' => 'error'], 404);
            case Password::RESET_THROTTLED:
                return response()->json(['message' => 'Please wait before retrying', 'status' => 'error'], 429);
            default:
                return response()->json(['message' => 'Unable to reset password', 'status' => 'error'], 500);
        }
    }

   

}
