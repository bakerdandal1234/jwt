<?php

namespace App\Http\Controllers;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Models\User;
class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255|min:3',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
            'confirm_password' => 'required|same:password',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

         $user->sendEmailVerificationNotification();

       

        return response()->json(['message' => 'User registered successfully and email verification sent', 'user' => $user,'success'=>true], 201);
    }



    public function login(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }


        $credentials = $request->only('email', 'password');

        // Attempt to authenticate the user
        if (!$token = auth('api')->attempt($credentials)) {
            return response()->json(['error' => 'incorrect email or password'], 401);
        }

        // Get the authenticated user
        $user = auth('api')->user();

        // Check if the user's email is verified
    if (!$user->email_verified_at) {
        return response()->json(['error' => 'Please verify your email before logging in.'], 403);
    }

        // Return the token and user information
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60, // Token expiration time in seconds
            'user' => $user, // Include the authenticated user's details
        ]);
    }

    public function logout()
    {
        auth('api')->logout();
        return response()->json(['message' => 'User logged out successfully']);
    }





    public function userProfile()
{
    $user = auth('api')->user();

    if (!$user) {
        return response()->json(['error' => 'Unauthorized'], 401);
    }

    return response()->json(['user' => $user,'success'=>true]);
}

public function refresh()
{
    $user = auth('api')->user();

    if (!$user) {
        return response()->json(['error' => 'Unauthorized'], 401);
    }

    return response()->json([
        'access_token' => auth('api')->refresh(),
        'token_type' => 'bearer',
        'expires_in' => auth('api')->factory()->getTTL() * 60,
    ]);
}


   

   

   
    

   
    
    
}
