<?php

return [
    'paths' => ['*'],
    'allowed_methods' => ['*'], // السماح بجميع طرق HTTP
    'allowed_origins' => ['http://localhost:5173'], // تحديد المصادر المسموح بها
    'allowed_headers' => ['*'], // السماح بجميع الرؤوس
    'exposed_headers' => [],
    'max_age' => 0,
    'supports_credentials' => true, // تمكين دعم الاعتمادات
];
