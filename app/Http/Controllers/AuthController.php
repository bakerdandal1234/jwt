<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
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

        return response()->json(['message' => 'User registered successfully', 'user' => $user], 201);
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
        if (! $token = auth('api')->attempt($credentials)) {
            return response()->json(['error' => 'incorrect credentials'], 401);
        }
    
        // Get the authenticated user
        $user = auth('api')->user();
    
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
        return response()->json(auth('api')->user());
    }

}
