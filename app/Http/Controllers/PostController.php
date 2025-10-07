<?php

namespace App\Http\Controllers;
use App\Models\Post;
use Illuminate\Http\Request;

class PostController extends Controller
{
    public function index()
    {
     $user=auth()->user();
     return response()->json($user->posts);
    }

    public function store(Request $request)
    {
        $user=auth()->user();
        $request->validate([
            'title' => 'required|string|max:255',
            'content' => 'required|string',
            'category_id' => 'required|exists:categories,id',
        ]);
        $post = $user->posts()->create($request->all());
        return response()->json([
            'message' => 'Post created successfully',
            'post' => $post->load('user', 'category') // اختياري: إرجاع بيانات المستخدم والتصنيف مع المنشور
        ], 201);
    }

    public function show($id)
    {
        $post = Post::with('user', 'category', 'comments.user')->find($id);

        if (!$post) {
            return response()->json(['error' => 'Post not found'], 404);
        }

        return response()->json($post);
    }

    public function update(Request $request, $id)
    {
        $user = auth()->user();
        $post = $user->posts()->find($id);

        if (!$post) {
            return response()->json(['error' => 'Post not found'], 404);
        }

        $request->validate([
            'title' => 'required|string|max:255',
            'content' => 'required|string',
            'category_id' => 'required|exists:categories,id',
        ]);

        $post->update($request->all());

        return response()->json([
            'message' => 'Post updated successfully',
            'post' => $post->load('user', 'category') // اختياري: إرجاع بيانات المستخدم والتصنيف مع المنشور
        ]);
    }


    public function destroy($id)
    {
        $user = auth()->user();
        $post = $user->posts()->find($id);

        if (!$post) {
            return response()->json(['error' => 'Post not found'], 404);
        }

        $post->delete();

        return response()->json(['message' => 'Post deleted successfully']);
    }
}
