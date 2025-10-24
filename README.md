# Database Utility Library

このライブラリは、**PDO** または **MySQLi** を用いたシンプルかつ安全なデータベース操作を提供します。  
バインドパラメータ方式による SQL 実行、暗号化カラムの自動処理、トランザクション管理などを簡単に利用できます。
ちょっとしたPHPスクリプトに、緩い感じで、SQLが使いたい時用に作りました。
かなり緩い感じで使えます。

---

## 🚀 特徴

- ✅ PDO / MySQLi どちらにも対応  
- 🔐 暗号化キーを指定すると自動で暗号化／復号  
- 🧱 バインドパラメータ方式による安全なSQL実行  
- 🔄 トランザクション制御に対応  
- 🧩 結果を統一フォーマットで返却  

---

## ⚙️ 設定方法（config.php）

`config.php` に以下の設定を記述してください。

```php
return [
    'type' => '',          // "pdo" または "mysqli" を指定
    'host' => '',          // ホスト名
    'dbname' => '',        // データベース名
    'user' => '',          // データベースユーザー名
    'pass' => '',          // データベースパスワード
    'charset' => '',       // 例: utf8mb4

    // 🔐 暗号化設定
    'encryption_key' => '',  // 設定すると暗号化が有効になる

    // 自動暗号化設定（テーブル名 => カラム名配列）
    'encrypt_columns' => [
        'users' => ['user_id', 'email', 'password'],
    ],
];
```

> 💡 `encryption_key` に値を設定すると、  
> `encrypt_columns` に指定したカラムは自動的に暗号化・復号されます。

---

## 📘 使用方法

### 1️⃣ スクリプトでの読み込み

利用するスクリプトの冒頭で以下を記述します。

```php
require_once 'config.php';
require_once 'database.php';
```

---

### 2️⃣ データベースの初期化

```php
$db = new Database($config['db']);
```

---

### 3️⃣ クエリ実行（バインドパラメータ方式）

```php
$result = $db->query(string $sql, array $params);
```

#### 引数
| 引数 | 説明 |
|------|------|
| `$sql` | 実行するSQL文 |
| `$params` | バインドする値の配列 |

#### 戻り値
以下の連想配列を返します：

```php
[
    "success" => true,                // 成功時は true
    "error"   => "エラーメッセージ", // エラー発生時の内容
    "data"    => [ ... ]              // SELECT時のみ結果配列
]
```

> `SELECT`, `INSERT`, `UPDATE`, `DELETE` を自動判別。  
> `SELECT` の場合のみ `data` に結果配列を返します。  
> ※ `UNION` など複合クエリには非対応です。

---

### 4️⃣ データベース切断

```php
$db->close();
```

---

### 5️⃣ トランザクション操作

```php
// トランザクション開始
$db->beginTransaction();

// コミット
$db->commit();

// ロールバック
$db->rollback();
```

---

## 🧠 実行例

```php
require_once 'config.php';
require_once 'database.php';

$db = new Database($config['db']);

$sql = "SELECT * FROM users WHERE email = ?";
$params = ['user@example.com'];

$result = $db->query($sql, $params);

if ($result['success']) {
    foreach ($result['data'] as $row) {
        echo $row['email'] . PHP_EOL;
    }
} else {
    echo "Error: " . $result['error'];
}

$db->close();
```

---

## 🔐 暗号化の仕組み

- `config.php` の `encryption_key` に値を設定すると有効になります。  
- `encrypt_columns` に登録されたテーブルとカラムが自動で暗号化／復号されます。  
- `openssl_encrypt()` と `openssl_decrypt()` を利用しています。  
- キーの長さは AES-256-CBC に対応しています（16文字以上推奨）。

---

## ⚠️ 注意事項

- `UNION` や複雑な JOIN を含む SQL には非対応です。  
- SQLエラー時は `"success" => false` と `"error"` に詳細が返されます。  
- 暗号化を使用する場合、キーを安全に管理してください。  
- 文字コードは基本的に `utf8mb4` を推奨します。  

---

## 🧾 ライセンス

このライブラリは自由に改変・再利用可能です。  
商用利用も制限ありませんが、利用時は自己責任でお願いします。

---

## 🧑‍💻 作者

**AI Mandala Laboratory**  
開発・監修：まおち  

---

[![PHP Version](https://img.shields.io/badge/PHP-%3E%3D8.0-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()
