<?php
return [
    'db' => [
        'type' => '',   // pdo or mysqli
        'host' => '',   // ホスト名
        'dbname' => '',   // データベース名
        'user' => '',   // データベースユーザー名
        'pass' => '',   // データベースパスワード
        'charset' => '',   // データベースキャラセット
        'encryption_key' => '', // キーワードを設定すると暗号化が有効になる
        'encrypt_columns' => [
            'users' => ['user_id', 'email', 'password'],   // テーブル名 => [カラム名配列]で指定したカラムは自動で暗号化される
        ]
    ],
];
