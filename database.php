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
        if ($this->encryptionKey === '') return $params;

        $sql_clean = preg_replace('/\s+/', ' ', trim($sql));

        $table = '';
        $mode  = '';
        if (preg_match('/^\s*INSERT\s+INTO\s+`?([\w.]+)`?/i', $sql_clean, $m)) {
            $table = $m[1];
            $mode  = 'insert';
        } elseif (preg_match('/^\s*UPDATE\s+`?([\w.]+)`?/i', $sql_clean, $m)) {
            $table = $m[1];
            $mode  = 'update';
        }

        $encCols = $this->encryptColumns[$table] ?? [];
        if (!$encCols) return $params;

        $colOrder = [];
        if ($mode === 'insert') {
            if (preg_match('/INSERT\s+INTO\s+`?[\w.]+`?\s*\(([^)]+)\)\s*VALUES\s*\(([^)]*)\)/i', $sql_clean, $m2)) {
                $colOrder = array_map(
                    fn($s) => trim(trim($s), '` '),
                    explode(',', $m2[1])
                );
            } elseif (preg_match('/INSERT\s+INTO\s+`?[\w.]+`?\s+SET\s+(.+?)(?:\s+ON\s+DUPLICATE|\s*$)/i', $sql_clean, $m2)) {
                $assigns = array_map('trim', explode(',', $m2[1]));
                foreach ($assigns as $a) {
                    if (preg_match('/`?(\w+)`?\s*=/i', $a, $mm)) $colOrder[] = $mm[1];
                }
            }

            if (preg_match('/ON\s+DUPLICATE\s+KEY\s+UPDATE\s+(.+)$/i', $sql_clean, $dup)) {
                $assigns = array_map('trim', explode(',', $dup[1]));
                foreach ($assigns as $a) {
                    if (preg_match('/`?(\w+)`?\s*=/i', $a, $mm)) $colOrder[] = $mm[1];
                }
            }
        } else {
            if (preg_match('/UPDATE\s+`?[\w.]+`?\s+SET\s+(.+?)(?:\s+WHERE|\s*$)/i', $sql_clean, $m2)) {
                $assigns = array_map('trim', explode(',', $m2[1]));
                foreach ($assigns as $a) {
                    if (preg_match('/`?(\w+)`?\s*=/i', $a, $mm)) $colOrder[] = $mm[1];
                }
            }
        }

        if (!$colOrder) return $params;

        $new = [];
        $N = count($colOrder);
        foreach ($params as $i => $val) {
            if ($i < $N) {
                $col = $colOrder[$i] ?? '';
                $new[] = (in_array($col, $encCols, true)) ? $this->encrypt($val) : $val;
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

        $isSelect = preg_match('/^\s*(SELECT|SHOW)\b/i', $sql);
        $isInsertOrUpdate = preg_match('/^\s*(INSERT|UPDATE)\b/i', $sql);

        if ($isInsertOrUpdate) {
            $params = $this->encryptParams($sql, $params);
        }

        if ($this->type === 'pdo') {
            try {
                $stmt = $this->connection->prepare($sql);
                $stmt->execute($params);

                if ($isSelect) {
                    // JOIN対応の復号ルートを常用
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
}
