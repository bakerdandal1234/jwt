<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;
use App\Models\User;
use App\Models\RefreshToken;
use Illuminate\Support\Str;
use Carbon\Carbon;

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
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255|min:3',
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

        // Create JWT for the new user
        $token = Auth::guard('api')->login($user);
        $refreshToken = $this->createRefreshToken($user);

        return $this->respondWithTokens($token, $refreshToken, 'User registered successfully', $user);
    }

    /**
     * Login and create JWT tokens.
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

        // Attempt to authenticate the user
        if (!Auth::guard('api')->attempt($credentials)) {
            return response()->json(['error' => 'Incorrect email or password'], 401);
        }

        // Get the authenticated user
        $user = Auth::guard('api')->user();
        
        // Revoke all previous refresh tokens for the user
        RefreshToken::where('user_id', $user->id)->update(['revoked' => true]);
        
        // Create a new refresh token
        $refreshToken = $this->createRefreshToken($user);

        // Generate a new JWT token
        $token = Auth::guard('api')->refresh();

        return $this->respondWithTokens($token, $refreshToken, 'Login successful', $user);
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(Auth::guard('api')->user());
    }

    /**
     * Logout (invalidate current tokens).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        $user = Auth::guard('api')->user();
        
        // Revoke all refresh tokens for the user
        if ($user) {
            RefreshToken::where('user_id', $user->id)->update(['revoked' => true]);
        }
        Auth::guard('api')->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh JWT token using a refresh token.
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

        // Find all valid non-revoked tokens for comparison
        $validTokens = RefreshToken::where('revoked', false)
            ->where('expires_at', '>', now())
            ->get();
        
        $refreshToken = null;
        $userId = null;
        
        // Check each token to find a match
        foreach ($validTokens as $token) {
            // Compare the plain text token with the hashed one in the database
            if (Hash::check($request->refresh_token, $token->token)) {
                $refreshToken = $token;
                $userId = $token->user_id;
                break;
            }
        }

        Log::info('Refresh Token Request:', [
            'token_provided' => substr($request->refresh_token, 0, 10) . '...',
            'token_found' => $refreshToken ? 'yes' : 'no',
            'expires_at' => $refreshToken ? $refreshToken->expires_at : 'N/A',
            'now' => now(),
            'is_revoked' => $refreshToken ? $refreshToken->revoked : 'N/A'
        ]);

        if (!$refreshToken) {
            return response()->json(['error' => 'Invalid or expired refresh token'], 401);
        }

        $user = User::find($userId);
        
        if (!$user) {
            return response()->json(['error' => 'User not found'], 404);
        }

        // Revoke the current refresh token
        $refreshToken->update(['revoked' => true]);
        
        // Create a new JWT token for the user
        Auth::guard('api')->setUser($user);
        $token = Auth::guard('api')->login($user);
        
        // Create a new refresh token
        $newRefreshToken = $this->createRefreshToken($user);

        return $this->respondWithTokens($token, $newRefreshToken, 'Token refreshed successfully');
    }

    /**
     * Create a refresh token for the user.
     *
     * @param  \App\Models\User $user
     * @return string
     */
    protected function createRefreshToken(User $user)
    {
        // Create a unique token
        $token = Str::random(64);
        
        // Hash the token before storing it in the database
        $hashedToken = Hash::make($token);
        
        // Set expiration date (30 days)
        $expiresAt = Carbon::now()->addDays(30);
        
        // Store the hashed refresh token in the database
        RefreshToken::create([
            'user_id' => $user->id,
            'token' => $hashedToken,  // Store the hashed token
            'expires_at' => $expiresAt,
            'revoked' => false
        ]);
        
        return $token;  // Return the plain token to send to the client
    }

    /**
     * Respond with JWT and refresh tokens and their details.
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
            'expires_in' => Auth::guard('api')->factory()->getTTL() * 60 // Token validity in seconds
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