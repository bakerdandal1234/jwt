<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;
class RoleAndPermissionSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // مسح الكاش قبل إضافة أدوار جديدة
        app()[\Spatie\Permission\PermissionRegistrar::class]->forgetCachedPermissions();

        // إنشاء صلاحيات
        Permission::firstOrCreate(['name' => 'create task']);
        Permission::firstOrCreate(['name' => 'edit task']);
        Permission::firstOrCreate(['name' => 'delete task']);
        permission::firstOrCreate(['name' => 'view task']);
        // إنشاء أدوار وربط الصلاحيات
        $roleUser = Role::updateOrCreate(['name' => 'user']);
        $roleUser->syncPermissions('view task');

        $roleAdmin = Role::updateOrCreate(['name' => 'admin']);
        $roleAdmin->syncPermissions(Permission::all());
    }
}
