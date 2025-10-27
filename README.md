# 🧩 Database Utility Library --- 最新版

このライブラリは **PDO** または **MySQLi** を用いて、\
安全かつシンプルに SQL を実行できる軽量ユーティリティです。

暗号化カラムの自動処理、JOINを含むSELECTの自動復号、\
さらに `INSERT ... SELECT`
構文をアプリ側で再現（復号→再暗号化）できるようになっています。

------------------------------------------------------------------------

## 🚀 主な特徴

-   ✅ **PDO / MySQLi** 両対応\
-   🔐 暗号化キーを指定すると自動で **暗号化／復号**\
-   🔄
    **JOINを含むSELECTでも自動復号対応**（列メタ情報＋ASエイリアス規約）\
-   📦 **INSERT ... SELECT** も復号付きで自動処理（擬似実行）\
-   🧱 バインドパラメータ方式による安全なSQL実行\
-   🔁 トランザクション制御対応\
-   🧩 統一フォーマットでの結果返却

------------------------------------------------------------------------

## ⚙️ 設定方法（config.php）

``` php
return [
    'type' => 'pdo',        // "pdo" または "mysqli"
    'host' => 'localhost',  // ホスト名
    'dbname' => 'mydb',     // データベース名
    'user' => 'root',       // DBユーザー名
    'pass' => '',           // パスワード
    'charset' => 'utf8mb4', // 推奨

    // 🔐 暗号化設定
    'encryption_key' => 'your-secret-key',

    // 自動暗号化設定（テーブル => カラム配列）
    'encrypt_columns' => [
        'users' => ['user_id', 'email', 'password'],
        'orders' => ['name', 'address', 'tel']
    ],
];
```

> 💡 `encryption_key` を設定すると、\
> `encrypt_columns` に登録されたカラムは自動で暗号化／復号されます。

------------------------------------------------------------------------

## 📘 使用方法

### 1️⃣ ファイルの読み込み

``` php
require_once 'config.php';
require_once 'database.php';

$db = new Database($config['db']);
```

------------------------------------------------------------------------

### 2️⃣ クエリの実行

``` php
$result = $db->query($sql, $params);
```

#### 戻り値

``` php
[
  "success" => true,        // 成功時は true
  "error"   => "",          // エラー内容（失敗時）
  "data"    => [...],       // SELECT時の結果配列
  "last_insert_id" => 123   // INSERT時のみ（PDO/MySQLi共通）
]
```

------------------------------------------------------------------------

### 3️⃣ SELECT（JOIN含む）例

JOINを含むクエリでも、自動的に暗号カラムを復号します。\
PDO環境でも安全に扱うため、暗号カラムには `AS \`table\_\_column\`\`
の形式で別名を付けると確実です。

``` php
$sql = "
SELECT
  r.id,
  r.name          AS `restorations__name`,
  r.tel           AS `restorations__tel`,
  o.name          AS `orders__order_name`,
  o.ordered_at
FROM restorations AS r
LEFT JOIN orders AS o ON o.id = r.now_id
WHERE r.status = ?
";

$result = $db->query($sql, ['active']);
```

------------------------------------------------------------------------

### 4️⃣ INSERT ... SELECT（復号→再暗号化）

SELECTで取得した暗号カラムを復号してから、\
INSERT先の暗号カラムへ再暗号化して挿入します。

``` php
$sql = "
INSERT INTO orders_backup (
  backup_id, name, address, tel, branch, okuyami, backup_at
)
SELECT
  id AS backup_id,
  name,
  address,
  tel,
  branch,
  okuyami,
  ? AS backup_at
FROM orders
WHERE id = ?
";

$result = $db->query($sql, [$now, $order_id]);
```

> ⚠️ SELECT 側の列名は INSERT 側と一致させてください。\
> 一致しない場合は `AS` で別名を指定（例：`id AS backup_id`）。

------------------------------------------------------------------------

### 5️⃣ 通常のINSERT / UPDATE

``` php
$db->query(
  "INSERT INTO users (user_id, email, password) VALUES (?, ?, ?)",
  ['test', 'mail@example.com', 'secret']
);
```

暗号化対象カラムは自動的に暗号化されます。

------------------------------------------------------------------------

### 6️⃣ トランザクション操作

``` php
$db->beginTransaction();
$db->query("UPDATE users SET name=? WHERE id=?", ['Alice', 1]);
$db->commit();
// $db->rollback(); // 失敗時
```

------------------------------------------------------------------------

## 🔐 暗号化の仕様

-   暗号化は **AES-256-CBC** を使用\
-   `openssl_encrypt()` / `openssl_decrypt()` による安全な処理\
-   IV（初期化ベクトル）は16バイトランダム生成し、暗号文の先頭に結合\
-   データベース上には Base64 文字列で保存されます\
-   暗号化キーは 16～32文字を推奨（AES-256対応）

------------------------------------------------------------------------

## 🧩 JOINと復号の仕組み

-   復号は `getColumnMeta()`（PDO）または
    `fetch_fields()`（MySQLi）で列メタ情報を取得\
-   列メタに基づき「テーブル名 × カラム名」で自動復号\
-   PDOドライバがテーブル名を返さない場合も、`table__column`
    形式のエイリアスを解析して復号可能

------------------------------------------------------------------------

## ⚙️ INSERT ... SELECT の内部動作

1.  `INSERT ... SELECT` を検出\
2.  SELECTを実行 → 暗号カラムを復号\
3.  結果を再暗号化して挿入\
4.  大量データは自動で1000行ごとにチャンク処理\
5.  既存トランザクション中ならそのまま参加（PDOは自動管理）

------------------------------------------------------------------------

## ⚠️ 注意事項

-   `UNION`、`サブクエリを多段にネスト` したSQLはサポート外\
-   SELECT側とINSERT側の列名・順序は必ず一致させてください\
-   暗号化対象でないカラムは平文のまま扱われます\
-   暗号化キーは**アプリ内に平文で保持しない**よう注意\
-   文字コードは `utf8mb4` を推奨

------------------------------------------------------------------------

## 🧠 実行例まとめ

``` php
$db = new Database($config['db']);

// JOIN付きSELECT
$users = $db->query("SELECT u.id, u.email, p.name AS `profiles__name` FROM users u LEFT JOIN profiles p ON p.user_id = u.id");

// INSERT ... SELECT
$db->query("
  INSERT INTO users_backup (backup_id, email, name, backup_at)
  SELECT id AS backup_id, email, name, ? AS backup_at FROM users WHERE id = ?
", [$now, $uid]);
```

------------------------------------------------------------------------

## 🧾 ライセンス

MIT License\
自由に改変・再配布可能です。商用利用可。

------------------------------------------------------------------------

## 🧑‍💻 作者

**AI Mandala Laboratory**\
開発・監修：まおち

------------------------------------------------------------------------

[![PHP Version](https://img.shields.io/badge/PHP-%3E%3D8.0-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

------------------------------------------------------------------------

### 🔍 推奨運用ルール

  項目                推奨設定
  ------------------- --------------------------------------------------
  PDO利用             `ATTR_EMULATE_PREPARES = false`
  文字コード          `utf8mb4`
  暗号化キー          16～32文字
  暗号対象列名        できる限り明示的に `AS table__column` 形式を付与
  INSERT ... SELECT   挿入先と同名カラムに合わせてAS指定
