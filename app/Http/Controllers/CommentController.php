<?php

namespace App\Http\Controllers;
use App\Models\Comment;
use Illuminate\Http\Request;

class CommentController extends Controller
{
    public function index()
    {
        $user = auth()->user();
        return response()->json($user->comments);
    }

    public function store(Request $request)
    {
        $user = auth()->user();

        $request->validate([
            'content' => 'required|string',
            'post_id' => 'required|exists:posts,id',
        ]);

        $comment = $user->comments()->create($request->all());
        
        return response()->json([
            'message' => 'Comment created successfully',
            'comment' => $comment->load('user', 'post') // اختياري: إرجاع بيانات المستخدم والمنشور مع التعليق
        ], 201);
    }


    public function show($id)
    {
        $comment = Comment::with('user', 'post')->find($id);

        if (!$comment) {
            return response()->json(['error' => 'Comment not found'], 404);
        }

        return response()->json($comment);
    }

    public function update(Request $request, $id)
    {
        $user = auth()->user();
        $comment = $user->comments()->find($id);

        if (!$comment) {
            return response()->json(['error' => 'Comment not found'], 404);
        }

        $request->validate([
            'content' => 'required|string',
            'post_id' => 'required|exists:posts,id',
        ]);

        $comment->update($request->all());

        return response()->json([
            'message' => 'Comment updated successfully',
            'comment' => $comment->load('user', 'post') // اختياري: إرجاع بيانات المستخدم والمنشور مع التعليق
        ]);
    }

    public function destroy($id)
    {
        $user = auth()->user();
        $comment = $user->comments()->find($id);

        if (!$comment) {
            return response()->json(['error' => 'Comment not found'], 404);
        }

        $comment->delete();

        return response()->json(['message' => 'Comment deleted successfully']);
    }
}
