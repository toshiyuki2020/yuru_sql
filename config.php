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
        'pepper_key'     => '', // 検索用のHMAC_SHA256ハッシュのキーワード
        'encrypt_columns' => [
            'users' => ['user_id', 'email'],   // テーブル名 => [カラム名配列]で指定したカラムは自動で暗号化される
        ],
        'hash_columns' => [
          'users' => [
            'user_id_hash' => ['type' => 'hmac_sha256', 'normalize' => 'user_id'],
            'password'   => ['type' => 'argon2id'],
            //typeがhmac_sha256はpepper_keyが設定されるとハッシュが実行されるようになる
            //typoがArgon2idの場合はカラムが設定された段階でハッシュが実行されるようなる
          ],
        ],
    ]
];
