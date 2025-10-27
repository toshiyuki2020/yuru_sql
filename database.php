<?php
/**
 * Class Database
 * データベース接続・クエリ実行・暗号化/復号・トランザクション操作を提供するクラス。
 * - JOIN含むSELECTの復号: 列メタ情報（table/orgname）に基づく
 * - INSERT ... SELECT の擬似実行: SELECT→復号→INSERT VALUES(暗号化) の2段階
 */
class Database {
    /** @var string データベース種別（pdo or mysqli） */
    private $type;

    /** @var string ホスト名 */
    private $host;

    /** @var string データベース名 */
    private $dbname;

    /** @var string ユーザー名 */
    private $user;

    /** @var string パスワード */
    private $pass;

    /** @var string 文字セット */
    private $charset;

    /** @var string 暗号化キー（空の場合は暗号化スキップ） */
    private $encryptionKey;

    /** @var array テーブルごとの暗号化対象カラム（'users' => ['email', ...], ...） */
    private $encryptColumns;

    /** @var string HMAC用ペッパー */
    private $pepper = '';

    /** @var array  ハッシュ規約 (table => [col => ['type'=>..., ...]]) */
    private $hashColumns = [];

    /** @var PDO|mysqli データベース接続オブジェクト */
    private $connection;

    /**
     * Database constructor.
     * @param array $config 設定配列
     */
    public function __construct($config = []) {
        $this->type = $config['type'] ?? 'mysqli';
        $this->host = $config['host'] ?? 'localhost';
        $this->dbname = $config['dbname'] ?? '';
        $this->user = $config['user'] ?? '';
        $this->pass = $config['pass'] ?? '';
        $this->charset = $config['charset'] ?? 'utf8mb4';
        $this->encryptionKey = $config['encryption_key'] ?? '';
        $this->encryptColumns = $config['encrypt_columns'] ?? [];
        $this->pepper       = $config['pepper_key']   ?? '';
        $this->hashColumns  = $config['hash_columns'] ?? [];

        $this->connect();
    }

    /**
     * データベースに接続
     */
    private function connect() {
        if ($this->type === 'pdo') {
            $dsn = "mysql:host={$this->host};dbname={$this->dbname};charset={$this->charset}";
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ];
            try {
                $this->connection = new PDO($dsn, $this->user, $this->pass, $options);
            } catch (PDOException $e) {
                throw new Exception("PDO接続失敗: " . $e->getMessage());
            }
        } elseif ($this->type === 'mysqli') {
            $this->connection = new mysqli($this->host, $this->user, $this->pass, $this->dbname);
            if ($this->connection->connect_error) {
                throw new Exception("MySQLi接続失敗: " . $this->connection->connect_error);
            }
            $this->connection->set_charset($this->charset);
        } else {
            throw new Exception("不明な接続タイプです: " . $this->type);
        }
    }

    /**
     * 値を暗号化
     * @param string|null $text
     * @return string|null 暗号化された文字列
     */
    public function encrypt($text) {
        if ($this->encryptionKey === '' || $text === null) return $text;

        $key = hash('sha256', $this->encryptionKey, true);
        $iv = openssl_random_pseudo_bytes(16);
        $encrypted = openssl_encrypt($text, 'aes-256-cbc', $key, 0, $iv);

        // IVを暗号文に結合して返す（base64で安全に）
        return base64_encode($iv . $encrypted);
    }

    /**
     * 値を復号化
     * @param string|null $text
     * @return string|null 復号化された文字列
     */
    public function decrypt($text) {
        if ($this->encryptionKey === '' || $text === null) return $text;

        $key = hash('sha256', $this->encryptionKey, true);
        $data = base64_decode($text);

        // 前16バイトをIVとして使用
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);

        return openssl_decrypt($encrypted, 'aes-256-cbc', $key, 0, $iv);
    }

    /**
     * パラメータ型を自動推測（mysqli用）
     * @param array $params
     * @return string 型文字列
     */
    private function guessParamTypes($params) {
        $types = '';
        foreach ($params as $param) {
            if (is_int($param)) $types .= 'i';
            elseif (is_float($param)) $types .= 'd';
            elseif (is_null($param)) $types .= 's';
            elseif (is_string($param)) $types .= 's';
            else $types .= 'b';
        }
        return $types;
    }

    // ========= ここから：暗号化/復号のヘルパ =========

    /** 復号の安全呼び出し（失敗しても値を壊さない） */
    private function tryDecrypt($val) {
        if ($val === null || $this->encryptionKey === '') return $val;
        try {
            return $this->decrypt($val);
        } catch (\Throwable $e) {
            return $val;
        }
    }

    /**
     * 列メタに基づいて復号
     * @param array $rows  フェッチ済み（assoc）
     * @param array $colMeta [出力名 => ['table'=>原テーブル, 'orgname'=>原カラム]]
     */
    private function decryptResultsWithMeta(array $rows, array $colMeta): array {
        if ($this->encryptionKey === '' || !$rows) return $rows;

        foreach ($rows as &$row) {
            foreach ($row as $outName => $val) {
                $meta = $colMeta[$outName] ?? null;

                $table = '';
                $org   = '';

                if ($meta) {
                    $table = $meta['table']   ?? '';
                    $org   = $meta['orgname'] ?? '';
                }

                // フォールバック: エイリアスが "table__column" 形式ならそれを採用
                if (($table === '' || $org === '') && strpos($outName, '__') !== false) {
                    [$t, $c] = explode('__', $outName, 2);
                    $t = trim($t); $c = trim($c);
                    if ($table === '') $table = $t;
                    if ($org   === '') $org   = $c;
                }

                if ($table !== '' && $org !== '' &&
                    isset($this->encryptColumns[$table]) &&
                    in_array($org, $this->encryptColumns[$table], true)) {
                    $row[$outName] = $this->tryDecrypt($val);
                }
            }
        }
        return $rows;
    }

    /** PDO: 列メタ作成 */
    private function buildColMetaPDO(PDOStatement $stmt): array {
        $count = $stmt->columnCount();
        $colMeta = [];
        for ($i = 0; $i < $count; $i++) {
            $m = $stmt->getColumnMeta($i) ?: [];
            $out = $m['name'] ?? '';
            if ($out === '') continue;
            // ※ PDO(MySQL)は table/orgname が空のこともある
            $colMeta[$out] = [
                'table'   => $m['table']   ?? '',
                'orgname' => $m['name']    ?? $out,
            ];
        }
        return $colMeta;
    }

    /** MySQLi: 列メタ作成 */
    private function buildColMetaMySQLi(mysqli_result $res): array {
        $fields = $res->fetch_fields();
        $colMeta = [];
        foreach ($fields as $f) {
            $out = $f->name; // 出力名（AS後）
            $colMeta[$out] = [
                'table'   => $f->orgtable ?: $f->table ?: '',
                'orgname' => $f->orgname ?: $f->name,
            ];
        }
        return $colMeta;
    }

    /**
     * SELECT を実行してメタに基づき復号して返す（JOIN対応）
     * @return array [success, error, data]
     */
    private function fetchSelectDecrypted(string $sql, array $params = []): array {
        $ret = ['success'=>false,'error'=>'','data'=>[]];

        if ($this->type === 'pdo') {
            try {
                $stmt = $this->connection->prepare($sql);
                $stmt->execute($params);
                $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
                $colMeta = $this->buildColMetaPDO($stmt);
                $ret['data'] = $this->decryptResultsWithMeta($data, $colMeta);
                $ret['success'] = true;
            } catch (PDOException $e) {
                $ret['error'] = $e->getMessage();
            }
            return $ret;
        }

        // mysqli
        $stmt = $this->connection->prepare($sql);
        if (!$stmt) {
            $ret['error'] = $this->connection->error;
            return $ret;
        }
        if (!empty($params)) {
            $types = $this->guessParamTypes($params);
            $stmt->bind_param($types, ...$params);
        }
        if (!$stmt->execute()) {
            $ret['error'] = $stmt->error;
            $stmt->close();
            return $ret;
        }
        $res = $stmt->get_result();
        $colMeta = $this->buildColMetaMySQLi($res);
        $data = $res->fetch_all(MYSQLI_ASSOC);
        $stmt->close();

        $ret['data'] = $this->decryptResultsWithMeta($data, $colMeta);
        $ret['success'] = true;
        return $ret;
    }

    // ========= ここまで：復号系ヘルパ =========

    /**
     * INSERT/UPDATEのパラメータを暗号化
     * @param string $sql
     * @param array $params
     * @return array 暗号化済みパラメータ
     */
    private function encryptParams($sql, $params) {
      if ($this->encryptionKey === '' && empty($this->hashColumns)) return $params;

      $sql_clean = preg_replace('/\s+/', ' ', trim($sql));

      $table = '';
      $mode  = '';
      if (preg_match('/^\s*INSERT\s+INTO\s+`?([\w.]+)`?/i', $sql_clean, $m)) {
        $table = $m[1]; $mode = 'insert';
      } elseif (preg_match('/^\s*UPDATE\s+`?([\w.]+)`?/i', $sql_clean, $m)) {
        $table = $m[1]; $mode = 'update';
      }

      $encCols  = $this->encryptColumns[$table] ?? [];
      $hashCols = array_keys($this->hashColumns[$table] ?? []);
      if (!$encCols && !$hashCols) return $params;

      // SET 対象カラムの順序抽出
      $colOrder = [];
      if ($mode === 'insert') {
        if (preg_match('/INSERT\s+INTO\s+`?[\w.]+`?\s*\(([^)]+)\)\s*VALUES\s*\(([^)]*)\)/i', $sql_clean, $m2)) {
          $colOrder = array_map(fn($s)=>trim(trim($s),'` '), explode(',', $m2[1]));
        } elseif (preg_match('/INSERT\s+INTO\s+`?[\w.]+`?\s+SET\s+(.+?)(?:\s+ON\s+DUPLICATE|\s*$)/i', $sql_clean, $m2)) {
          foreach (array_map('trim', explode(',', $m2[1])) as $a)
            if (preg_match('/`?(\w+)`?\s*=/i', $a, $mm)) $colOrder[] = $mm[1];
        }
        if (preg_match('/ON\s+DUPLICATE\s+KEY\s+UPDATE\s+(.+)$/i', $sql_clean, $dup)) {
          foreach (array_map('trim', explode(',', $dup[1])) as $a)
            if (preg_match('/`?(\w+)`?\s*=/i', $a, $mm)) $colOrder[] = $mm[1];
        }
      } else { // UPDATE
        if (preg_match('/UPDATE\s+`?[\w.]+`?\s+SET\s+(.+?)(?:\s+WHERE|\s*$)/i', $sql_clean, $m2)) {
          foreach (array_map('trim', explode(',', $m2[1])) as $a)
            if (preg_match('/`?(\w+)`?\s*=/i', $a, $mm)) $colOrder[] = $mm[1];
        }
      }
      if (!$colOrder) return $params;

      $new = [];
      $N = count($colOrder);
      foreach ($params as $i => $val) {
        if ($i < $N) {
          $col = $colOrder[$i] ?? '';

          // 1) ハッシュ（あれば最優先）
          if (isset(($this->hashColumns[$table] ?? [])[$col])) {
            $val = $this->applyHashForColumn($table, $col, $val); // 下で定義
            $new[] = $val;
            continue;
          }

          // 2) 暗号化（ハッシュ指定が無い場合のみ）
          if (in_array($col, $encCols, true)) {
            $val = $this->encrypt($val);
          }
          $new[] = $val;
        } else {
          $new[] = $val;
        }
      }
      return $new;
    }

    // ========= INSERT ... SELECT のエミュレーション =========

    /** INSERT ... SELECT 判定 */
    private function isInsertSelect(string $sql): bool {
        $sql_clean = preg_replace('/\s+/', ' ', trim($sql));
        return (bool)preg_match(
            '/^\s*INSERT\s+INTO\s+`?[\w.]+`?\s*\([^)]+\)\s*SELECT\b/i',
            $sql_clean
        );
    }

    /**
     * INSERT ... SELECT を解析
     * @return array|null [table, cols[], selectSql] or null
     */
    private function parseInsertSelect(string $sql): ?array {
        $sql_clean = preg_replace('/\s+/', ' ', trim($sql));
        if (!preg_match(
            '/^\s*INSERT\s+INTO\s+`?([\w.]+)`?\s*\(([^)]+)\)\s*SELECT\s+(.+)$/i',
            $sql_clean, $m
        )) {
            return null;
        }
        $table = $m[1];
        $cols  = array_map(fn($s)=>trim(trim($s),'` '), explode(',', $m[2]));
        $selectSql = 'SELECT ' . $m[3];
        return [$table, $cols, $selectSql];
    }

    /**
     * INSERT ... SELECT をアプリ側でエミュレーション（SELECT→復号→INSERT）
     * @return array ['success'=>bool,'error'=>string,'data'=>[],'last_insert_id'=>?]
     */
    private function emulateInsertSelect(string $sql, array $params): array {
        $parsed = $this->parseInsertSelect($sql);
        if (!$parsed) {
            return ['success'=>false,'error'=>'Unsupported INSERT ... SELECT form','data'=>[]];
        }
        [$targetTable, $targetCols, $selectSql] = $parsed;

        // 1) SELECT（JOIN対応）して復号
        $selParams = $this->applyHashForWhereParams($selectSql, $params, '');
        $sel = $this->fetchSelectDecrypted($selectSql, $params);
        if (!$sel['success']) return $sel;
        $rows = $sel['data'];
        if (!$rows) return ['success'=>true,'error'=>'','data'=>[]];

        // 2) VALUES バルクINSERT
        $place = '(' . implode(',', array_fill(0, count($targetCols), '?')) . ')';
        $chunkSize = 1000; // 過大なSQLを避ける
        $chunks = array_chunk($rows, $chunkSize);
        $lastId = null;

        // 既存トランザクションに配慮しつつ、PDOのみ内部トラングラップ
        $pdoManagedTx = false;
        if ($this->type === 'pdo') {
            // 既にトランザクション中かどうか判定（PDOは inTransaction あり）
            if (!$this->connection->inTransaction()) {
                $this->connection->beginTransaction();
                $pdoManagedTx = true;
            }
        }

        foreach ($chunks as $chunk) {
            $valuesSqlParts = [];
            $binds = [];
            foreach ($chunk as $r) {
                $rowParams = [];
                foreach ($targetCols as $c) {
                    // SELECT 側で AS を挿入先カラム名と揃えておくと安全
                    $rowParams[] = $r[$c] ?? null;
                }
                $valuesSqlParts[] = $place;
                array_push($binds, ...$rowParams);
            }

            $insertSql = sprintf(
                'INSERT INTO `%s` (%s) VALUES %s',
                $targetTable,
                implode(',', array_map(fn($c)=>'`'.$c.'`', $targetCols)),
                implode(',', $valuesSqlParts)
            );

            // 暗号化カラムは encryptParams() に任せる
            $encBinds = $this->encryptParams($insertSql, $binds);

            if ($this->type === 'pdo') {
                $stmt = $this->connection->prepare($insertSql);
                $stmt->execute($encBinds);
                $lastId = $this->connection->lastInsertId();
            } else { // mysqli
                $stmt = $this->connection->prepare($insertSql);
                if (!$stmt) {
                    if ($this->type === 'pdo' && $pdoManagedTx) $this->connection->rollBack();
                    return ['success'=>false,'error'=>$this->connection->error,'data'=>[]];
                }
                $types = $this->guessParamTypes($encBinds);
                // 可変個数バインド
                $stmt->bind_param($types, ...$encBinds);
                if (!$stmt->execute()) {
                    $err = $stmt->error;
                    $stmt->close();
                    return ['success'=>false,'error'=>$err,'data'=>[]];
                }
                $lastId = $this->connection->insert_id;
                $stmt->close();
            }
        }

        if ($this->type === 'pdo' && $pdoManagedTx) {
            $this->connection->commit();
        }

        return ['success'=>true,'error'=>'','data'=>[],'last_insert_id'=>$lastId];
    }

    // ========= ここまで INSERT ... SELECT エミュ =========

    /**
     * SQLクエリ実行関数
     * @param string $sql
     * @param array $params
     * @return array ['success' => bool, 'error' => string, 'data' => array, （insertの場合のみ）'last_insert_id' => int]
     */
    public function query($sql, $params = []) {
      $result = ['success' => false, 'error' => '', 'data' => []];

      // INSERT ... SELECT はアプリ側で擬似実行（SELECT→復号→INSERT）
      if ($this->isInsertSelect($sql)) {
        return $this->emulateInsertSelect($sql, $params);
      }

      $isSelect         = preg_match('/^\s*(SELECT|SHOW)\b/i', $sql);
      $isInsertOrUpdate = preg_match('/^\s*(INSERT|UPDATE)\b/i', $sql);
      $isDelete         = preg_match('/^\s*DELETE\b/i', $sql);

      if ($isInsertOrUpdate) {
        // 1) SET側: ハッシュ→暗号（encryptParams内でハッシュ優先）
        $params = $this->encryptParams($sql, $params);

        // 2) WHERE側: HMACのみ適用（Argon2idは不可）
        $targetTable = '';
        if (preg_match('/^\s*UPDATE\s+`?([\w.]+)`?/i', preg_replace('/\s+/', ' ', trim($sql)), $m)) {
          $targetTable = $m[1]; // テーブル名省略の col=? に備えて渡す
        }
        $params = $this->applyHashForWhereParams($sql, $params, $targetTable);

      } elseif ($isSelect || $isDelete) {
        // 検索/削除系は WHERE の HMAC だけ
        $params = $this->applyHashForWhereParams($sql, $params, '');
      }

      if ($this->type === 'pdo') {
        try {
          $stmt = $this->connection->prepare($sql);
          $stmt->execute($params);

          if ($isSelect) {
            // JOIN対応の復号ルート
            $data = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $colMeta = $this->buildColMetaPDO($stmt);
            $result['data'] = $this->decryptResultsWithMeta($data, $colMeta);
          }

          $result['success'] = true;

          if ($isInsertOrUpdate) {
            $result['last_insert_id'] = $this->connection->lastInsertId();
          }
        } catch (PDOException $e) {
          $result['error'] = $e->getMessage();
        }
        return $result;
      }

      // mysqli
      if (!empty($params)) {
        $stmt = $this->connection->prepare($sql);
        if (!$stmt) {
          $result['error'] = $this->connection->error;
          return $result;
        }
        $types = $this->guessParamTypes($params);
        $stmt->bind_param($types, ...$params);

        if (!$stmt->execute()) {
          $result['error'] = $stmt->error;
          $stmt->close();
          return $result;
        }

        if ($stmt->field_count > 0) {
          $res = $stmt->get_result();
          $data = $res->fetch_all(MYSQLI_ASSOC);
          $colMeta = $this->buildColMetaMySQLi($res);
          $result['data'] = $this->decryptResultsWithMeta($data, $colMeta);
        }
        $stmt->close();
      } else {
        $queryResult = $this->connection->query($sql);
        if ($queryResult === false) {
          $result['error'] = $this->connection->error;
          return $result;
        }

        if ($queryResult instanceof mysqli_result) {
          $colMeta = $this->buildColMetaMySQLi($queryResult);
          $data = $queryResult->fetch_all(MYSQLI_ASSOC);
          $result['data'] = $this->decryptResultsWithMeta($data, $colMeta);
        }
      }

      $result['success'] = true;
      if ($isInsertOrUpdate) {
        $result['last_insert_id'] = $this->connection->insert_id;
      }
      return $result;
    }

    /**
     * データベース切断処理
     */
    public function close() {
        if ($this->type === 'pdo') {
            $this->connection = null;
        } elseif ($this->type === 'mysqli' && $this->connection instanceof mysqli) {
            $this->connection->close();
        }
    }

    /**
     * トランザクションを開始する
     * @return bool 成功時 true
     */
    public function beginTransaction() {
        if ($this->type === 'pdo') {
            return $this->connection->beginTransaction();
        } elseif ($this->type === 'mysqli') {
            return $this->connection->begin_transaction();
        }
        return false;
    }

    /**
     * トランザクションをコミットする
     * @return bool 成功時 true
     */
    public function commit() {
        if ($this->type === 'pdo') {
            return $this->connection->commit();
        } elseif ($this->type === 'mysqli') {
            return $this->connection->commit();
        }
        return false;
    }

    /**
     * トランザクションをロールバックする
     * @return bool 成功時 true
     */
    public function rollback() {
        if ($this->type === 'pdo') {
            return $this->connection->rollBack();
        } elseif ($this->type === 'mysqli') {
            return $this->connection->rollback();
        }
        return false;
    }

    /** email正規化: 前後空白除去 + 小文字化（必要ならIDN対応等を追加） */
    private function normalizeEmail(?string $v): ?string {
      if ($v === null) return null;
      $v = trim($v);
      $v = mb_convert_kana($v, 'as', 'UTF-8');
      $v = mb_strtolower($v, 'UTF-8');
      return $v;
    }

    /** 数値系文字列（電話番号・郵便番号など）の正規化
     * - 全角数字 → 半角
     * - 数字以外（ハイフン・空白など）を除去
     * - 前後空白除去
     */
    private function normalizeNumberLike(?string $v): ?string {
      if ($v === null) return null;
      $v = trim($v);
      $v = mb_convert_kana($v, 'n', 'UTF-8'); // 全角→半角
      $v = preg_replace('/[^0-9]/', '', $v);  // 数字以外を除去
      return $v;
    }

    /** HMAC-SHA256 (hex) */
    private function hmacSha256(?string $v): ?string {
      if ($v === null) return null;
      $pepper = (string)$this->pepper;
      return hash_hmac('sha256', $v, $pepper, false); // hex文字列
    }

    /** Argon2id */
    private function argon2idHash(?string $v): ?string {
      if ($v === null) return null;

      // 1) Argon2id が使えるなら最優先（PHP 7.3+ & libargon2 が必要）
      if (defined('PASSWORD_ARGON2ID')) {
        $opts = [];
        if (defined('PASSWORD_ARGON2_DEFAULT_MEMORY_COST')) $opts['memory_cost'] = PASSWORD_ARGON2_DEFAULT_MEMORY_COST;
        if (defined('PASSWORD_ARGON2_DEFAULT_TIME_COST'))   $opts['time_cost']   = PASSWORD_ARGON2_DEFAULT_TIME_COST;
        if (defined('PASSWORD_ARGON2_DEFAULT_THREADS'))     $opts['threads']     = PASSWORD_ARGON2_DEFAULT_THREADS;
        return password_hash($v, PASSWORD_ARGON2ID, $opts);
      }

      // 2) Argon2i が使えるなら次善（PHP 7.2+ & libargon2）
      if (defined('PASSWORD_ARGON2I')) {
        return password_hash($v, PASSWORD_ARGON2I);
      }

      // 3) それも無ければ BCRYPT にフォールバック（PHP 5.5+）
      //    例としてコスト12（環境に合わせて調整）
      return password_hash($v, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    /**
     * 指定カラム用の派生（hash系）を適用
     * - $table: 対象テーブル（INSERT/UPDATEの対象テーブル）
     * - $col  : 対象カラム名（INSERT/UPDATEの左辺）
     * - $val  : 入力値（? にバインドされる予定の値）
     * 返り値: 変換後の値（指定が無ければ元のまま）
     */
    private function applyHashForColumn(string $table, string $col, $val) {
      $rule = $this->hashColumns[$table][$col] ?? null;
      if (!$rule) return $val;

      $type = strtolower($rule['type'] ?? '');
      if ($type === 'hmac_sha256') {
        // 正規化オプション
        $norm = strtolower($rule['normalize'] ?? '');
        if ($norm === 'email') {
          $val = $this->normalizeEmail((string)$val);
        } elseif ($norm === 'number') {
          $val = $this->normalizeNumberLike((string)$val);
        }
        return $this->hmacSha256((string)$val);
      } elseif ($type === 'argon2id') {
        return $this->argon2idHash((string)$val);
      }
      return $val;
    }

    /**
     * WHERE句の ? に対し、決定論的ハッシュ（HMAC）を自動適用する
     * - INSERT/UPDATE では SET 側で消費した ? の"残り"に対して適用
     * - SELECT では全 ? が対象（JOINのONは対象外想定）
     * 制約: シンプルな "col = ?" / "table.col = ?" / "`table`.`col` = ?" / AND連結 のみ対応
     */
    private function applyHashForWhereParams(string $sql, array $params, string $targetTableForUpdate = ''): array {
      if (empty($this->hashColumns)) return $params;

      $sql_clean = preg_replace('/\s+/', ' ', trim($sql));
      $whereCols = [];

      // WHERE 句抽出
      if (preg_match('/\bWHERE\s+(.+?)(?:\s+GROUP|\s+ORDER|\s+LIMIT|$)/i', $sql_clean, $m)) {
        $w = $m[1];

        // col = ? を左から順に拾う（括弧やOR/AND混在は基本OK、関数やIN(?)は対象外）
        $re = '/(?:^|\s|\()([`.\w]+)\s*=\s*\?/i';
        if (preg_match_all($re, $w, $mm)) {
          foreach ($mm[1] as $raw) {
            // raw: table.col / `table`.`col` / col
            $raw = trim($raw, " \t\n\r\0\x0B`");
            $parts = explode('.', $raw);
            if (count($parts) === 2) {
              $t = $parts[0];
              $c = $parts[1];
            } else {
              // テーブル名が省略された時：UPDATEなら対象テーブル、SELECTなら不明（第一FROMを仮採用）
              $t = $targetTableForUpdate;
              if ($t === '' && preg_match('/\bFROM\s+`?([\w.]+)`?/i', $sql_clean, $fm)) {
                $t = $fm[1];
              }
              $c = $parts[0];
            }
            $whereCols[] = [$t, $c];
          }
        }
      }

      if (empty($whereCols)) return $params;

      // WHERE 側の?に順番に適用（HMACのみ。Argon2idは不可）
      $out = $params;
      $pi  = 0;
      // SET側で使った?個数を推測（INSERT/UPDATE時のみ）
      $setCount = 0;
      if (preg_match('/^\s*UPDATE\b/i', $sql_clean)) {
        if (preg_match('/\bSET\s+(.+?)(?:\s+WHERE|\s*$)/i', $sql_clean, $sm)) {
          $setPart = $sm[1];
          $setCount = substr_count($setPart, '?');
        }
      } elseif (preg_match('/^\s*INSERT\b/i', $sql_clean)) {
        if (preg_match('/\)\s*VALUES\s*\(([^)]*)\)/i', $sql_clean, $im)) {
          $setCount = substr_count($im[1], '?');
        } elseif (preg_match('/\bSET\s+(.+?)(?:\s+ON\s+DUPLICATE|\s*$)/i', $sql_clean, $im2)) {
          $setCount = substr_count($im2[1], '?');
        }
      }
      $pi = $setCount; // WHEREの先頭?は配列中この位置から

      foreach ($whereCols as [$t, $c]) {
        if (!isset($out[$pi])) { $pi++; continue; }
        $rule = $this->hashColumns[$t][$c] ?? null;
        if ($rule && strtolower($rule['type'] ?? '') === 'hmac_sha256') {
          // 正規化
          $val = $out[$pi];
          if (strtolower($rule['normalize'] ?? '') === 'email') {
            $val = $this->normalizeEmail((string)$val);
          }
          $out[$pi] = $this->hmacSha256((string)$val);
        }
        $pi++;
      }
      return $out;
    }
}
