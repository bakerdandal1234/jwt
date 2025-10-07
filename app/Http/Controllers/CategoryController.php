<?php

namespace App\Http\Controllers;

use App\Models\Category;
use Illuminate\Http\Request;

class CategoryController extends Controller
{
    public function index()
    {
        $user = auth()->user();
        $categories = $user->categories()->with('posts')->get();
        return response()->json($categories);
    }


    // public function store(Request $request)
    // {
    //     $user = auth()->user();


    //     $request->validate([
    //         'name' => 'required|string|max:255',
    //         'description' => 'nullable|string',
    //     ]);

    //     $category = $user->categories()->create($request->all());

    //     return response()->json([
    //         'message' => 'Category created successfully',
    //         'category' => $category // اختياري: إرجاع بيانات التصنيف
    //     ], 201);
    // }

    public function store(Request $request)
{
    $request->validate([
        'name' => 'required|string|max:255',
        'description' => 'nullable|string',
    ]);

    // ✅ إنشاء الفئة مباشرة — بدون ربط بمستخدم
    $category = Category::create([
        'name' => $request->name,
        'description' => $request->description,
    ]);

    return response()->json([
        'message' => 'Category created successfully',
        'category' => $category
    ], 201);
}

    public function show($id)
    {
        $category = Category::with('posts')->find($id);

        if (!$category) {
            return response()->json(['error' => 'Category not found'], 404);
        }

        return response()->json($category);
    }


    public function update(Request $request, $id)
    {
        $user = auth()->user();
        $category = $user->categories()->find($id);

        if (!$category) {
            return response()->json(['error' => 'Category not found'], 404);
        }

        $request->validate([
            'name' => 'required|string|max:255',
            'description' => 'nullable|string',
        ]);

        $category->update($request->all());

        return response()->json([
            'message' => 'Category updated successfully',
            'category' => $category // اختياري: إرجاع بيانات التصنيف المحدثة
        ]);
    }


    public function destroy($id)
    {
        $user = auth()->user();
        $category = $user->categories()->find($id);

        if (!$category) {
            return response()->json(['error' => 'Category not found'], 404);
        }

        $category->delete();

        return response()->json(['message' => 'Category deleted successfully']);
    }
}
