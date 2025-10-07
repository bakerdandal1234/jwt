<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;
class category extends Model
{
    use HasFactory;
    protected $fillable = [
        'name',
        'description',
    ];

    public function posts()
    {
        return $this->hasMany(Post::class);
    }
}
