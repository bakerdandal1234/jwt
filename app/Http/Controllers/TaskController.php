<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Models\Task;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class TaskController extends Controller
{
    // عرض كل مهام المستخدم الحالي
    public function index()
    {
        $tasks = Auth::user()->tasks;
        return response()->json($tasks);
    }

    // إنشاء مهمة جديدة
    public function store(Request $request)
    {
        $request->validate([
            'title' => 'required|string|max:255',
            'description' => 'nullable|string',
            'completed' => 'boolean'
        ]);

        $task = Auth::user()->tasks()->create($request->all());

        return response()->json([
            'message' => 'Task created successfully',
            'task' => $task->load('user') // اختياري: إرجاع بيانات المستخدم مع المهمة
        ], 201);
    }

    // عرض مهمة محددة
    public function show(Task $task)
    {
        // تحقق أن المهمة تخص المستخدم الحالي
        if ($task->user_id !== Auth::id()) {
            return response()->json(['error' => 'Unauthorized'], 403);
        }

        return response()->json($task->load('user'));
    }

    // تحديث مهمة
    public function update(Request $request, Task $task)
    {
        if ($task->user_id !== Auth::id()) {
            return response()->json(['error' => 'Unauthorized'], 403);
        }

        $request->validate([
            'title' => 'sometimes|required|string|max:255',
            'description' => 'nullable|string',
            'completed' => 'boolean'
        ]);

        $task->update($request->all());

        return response()->json([
            'message' => 'Task updated successfully',
            'task' => $task->load('user')
        ]);
    }

    // حذف مهمة
    public function destroy(Task $task)
    {
        if ($task->user_id !== Auth::id()) {
            return response()->json(['error' => 'Unauthorized'], 403);
        }

        $task->delete();

        return response()->json(['message' => 'Task deleted successfully']);
    }
}