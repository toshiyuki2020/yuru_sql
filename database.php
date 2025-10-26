<?php

/**
 * Class Database
 * データベース接続・クエリ実行・暗号化/復号・トランザクション操作を提供するクラス。
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

    /** @var array テーブルごとの暗号化対象カラム */
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

      if (!$colOrder) {
        return $params;
      }

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

    /**
     * SELECT結果を復号化
     * @param string $sql
     * @param array $rows
     * @return array 復号化済み結果
     */
    private function decryptResults($sql, $rows) {
        if ($this->encryptionKey === '') return $rows;

        $sql_clean = preg_replace('/\s+/', ' ', $sql);
        preg_match('/FROM\s+`?(\w+)`?/i', $sql_clean, $match);
        $table = $match[1] ?? '';
        if (!isset($this->encryptColumns[$table])) return $rows;

        foreach ($rows as &$row) {
            foreach ($this->encryptColumns[$table] as $col) {
                if (isset($row[$col])) {
                    $row[$col] = $this->decrypt($row[$col]);
                }
            }
        }
        return $rows;
    }

    /**
     * SQLクエリ実行関数
     * @param string $sql
     * @param array $params
     * @return array ['success' => bool, 'error' => string, 'data' => array, （inserの場合のみ）'last_insert_id' => int]
     */
    public function query($sql, $params = []) {
        $result = ['success' => false, 'error' => '', 'data' => []];

        $isSelect = preg_match('/^\s*(SELECT|SHOW)/i', $sql);
        $isInsertOrUpdate = preg_match('/^\s*(INSERT|UPDATE)/i', $sql);

        if ($isInsertOrUpdate) {
            $params = $this->encryptParams($sql, $params);
        }

        if ($this->type === 'pdo') {
            try {
                $stmt = $this->connection->prepare($sql);
                $stmt->execute($params);
                if ($isSelect) {
                    $data = $stmt->fetchAll();
                    $result['data'] = $this->decryptResults($sql, $data);
                }
                $result['success'] = true;
            } catch (PDOException $e) {
                $result['error'] = $e->getMessage();
            }
        } elseif ($this->type === 'mysqli') {
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
                    return $result;
                }

                if ($stmt->field_count > 0) {
                    $res = $stmt->get_result();
                    $data = $res->fetch_all(MYSQLI_ASSOC);
                    $result['data'] = $this->decryptResults($sql, $data);
                }
                $stmt->close();
            } else {
                $queryResult = $this->connection->query($sql);
                if ($queryResult === false) {
                    $result['error'] = $this->connection->error;
                    return $result;
                }

                if ($queryResult instanceof mysqli_result) {
                    $data = $queryResult->fetch_all(MYSQLI_ASSOC);
                    $result['data'] = $this->decryptResults($sql, $data);
                }
            }
            $result['success'] = true;
        }

        if ($isInsertOrUpdate) {
            if ($this->type === 'pdo') {
                $result['last_insert_id'] = $this->connection->lastInsertId();
            } elseif ($this->type === 'mysqli') {
                $result['last_insert_id'] = $this->connection->insert_id;
            }
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

    // ...（既存の close() メソッドの後に追加してOK）
}
