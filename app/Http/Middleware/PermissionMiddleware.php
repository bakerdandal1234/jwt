<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Auth;
class PermissionMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next, $permission)
{
    $user = Auth::guard('api')->user();

    if (!$user || !$user->hasPermissionTo($permission)) {
        return response()->json(['error' => 'Forbidden: insufficient permission'], 403);
    }

    return $next($request);
}
}
