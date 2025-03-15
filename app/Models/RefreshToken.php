<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class RefreshToken extends Model
{
    //

    protected $fillable = [
        'user_id',
        'token',
        'expires_at',
        'last_used_at',
        'revoked', 
    ];

    protected $dates=[
        'expires_at',
        'created_at',
        'updated_at',
    ];

    protected $casts = [
        'revoked' => 'boolean',
    ];


    public function user()
    {
        return $this->belongsTo(User::class);
    }

    public function isValid()
    {
        return !$this->revoked && $this->expires_at->gt(now());
    }
}
