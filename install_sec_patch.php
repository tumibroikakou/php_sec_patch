<?php
/**
 * Автоустановщик mitigation-патча CVE-2026-109618 / CVE-2026-109619
 * (advisory php.net от 21.10.2026).
 *
 * Скрипт самодостаточный: guard-файл зашит внутрь в base64.
 *
 * Использование:
 *   php install_sec_patch.php                # цель - каталог, где лежит файл
 *   php install_sec_patch.php <путь_сайта>   # или явно указать корень сайта
 *   php install_sec_patch.php <путь> --status     # статические проверки
 *   php install_sec_patch.php <путь> --test       # живые проверки сайта
 *   php install_sec_patch.php <путь> --uninstall  # полный откат
 *
 * При установке:
 *   1. Создаёт <site>/sec_patch_cve2026.php (guard).
 *   2. Дописывает в <site>/.user.ini блок митигаций (создаёт файл при
 *      отсутствии). auto_prepend_file пишется с абсолютным путём.
 *   3. Дописывает в <site>/.htaccess блок для mod_php (если файла нет -
 *      создаёт).
 *
 * Абсолютный путь в auto_prepend_file покрывает и точки входа в
 * подкаталогах (adm/ и т.п.) - отдельные хуки не нужны.
 *
 * Идемпотентен: повторный запуск обновляет путь, а не дублирует блоки.
 * Совместимо с PHP 7.4+.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("CLI only\n");
}

/* Зашитый guard (base64 от sec_patch_cve2026.php) */
define('SEC_PATCH_PAYLOAD_B64', 'PD9waHAKCmlmIChkZWZpbmVkKCdTRUNfUEFUQ0hfQ1ZFXzIwMjZfTE9BREVEJykpIHsKICAgIHJldHVybjsKfQpkZWZpbmUoJ1NFQ19QQVRDSF9DVkVfMjAyNl9MT0FERUQnLCAxKTsKCiRHTE9CQUxTWydTRUNfUEFUQ0hfQ0ZHJ10gPSBhcnJheSgKICAgICdtZW1vcnlfbGltaXQnICAgICAgICAgICAgICAgICAgPT4gJy0xJywKICAgICdtYXhfaW5wdXRfY291bnQnICAgICAgICAgICAgICAgPT4gMTAwMCwKICAgICdtYXhfaW5wdXRfZGVwdGgnICAgICAgICAgICAgICAgPT4gNSwKICAgICdibG9ja19zZXNzaW9uX3VwbG9hZF9wcm9ncmVzcycgPT4gdHJ1ZSwKICAgICdibG9ja19taXNzaW5nX2NvbnRlbnRfbGVuZ3RoJyAgPT4gdHJ1ZSwKICAgICdsb2dfZmlsZScgICAgICAgICAgICAgICAgICAgICAgPT4gX19ESVJfXyAuICcvc2VjLXBhdGNoLWN2ZTIwMjYubG9nJywKICAgICdsb2dfZmF0YWxfZXJyb3JzJyAgICAgICAgICAgICAgPT4gdHJ1ZSwKKTsKCmlmICghZnVuY3Rpb25fZXhpc3RzKCdzZWNwX2xvZycpKSB7CgpmdW5jdGlvbiBzZWNwX2xvZygkcmVhc29uKQp7CiAgICAkY2ZnID0gJEdMT0JBTFNbJ1NFQ19QQVRDSF9DRkcnXTsKICAgICRsaW5lID0gc3ByaW50ZigKICAgICAgICAiWyVzXSAlcyB8IFVSST0lcyB8IElQPSVzIHwgVUE9JXMgfCBNZXRob2Q9JXMgfCBDTD0lc1xuIiwKICAgICAgICBkYXRlKCdZLW0tZCBIOmk6cycpLAogICAgICAgICRyZWFzb24sCiAgICAgICAgaXNzZXQoJF9TRVJWRVJbJ1JFUVVFU1RfVVJJJ10pID8gJF9TRVJWRVJbJ1JFUVVFU1RfVVJJJ10gOiAnLScsCiAgICAgICAgaXNzZXQoJF9TRVJWRVJbJ1JFTU9URV9BRERSJ10pID8gJF9TRVJWRVJbJ1JFTU9URV9BRERSJ10gOiAnLScsCiAgICAgICAgaXNzZXQoJF9TRVJWRVJbJ0hUVFBfVVNFUl9BR0VOVCddKSA/IHN1YnN0cigkX1NFUlZFUlsnSFRUUF9VU0VSX0FHRU5UJ10sIDAsIDIwMCkgOiAnLScsCiAgICAgICAgaXNzZXQoJF9TRVJWRVJbJ1JFUVVFU1RfTUVUSE9EJ10pID8gJF9TRVJWRVJbJ1JFUVVFU1RfTUVUSE9EJ10gOiAnLScsCiAgICAgICAgaXNzZXQoJF9TRVJWRVJbJ0NPTlRFTlRfTEVOR1RIJ10pID8gJF9TRVJWRVJbJ0NPTlRFTlRfTEVOR1RIJ10gOiAnbm9uZScKICAgICk7CiAgICBpZiAoQGZpbGVfcHV0X2NvbnRlbnRzKCRjZmdbJ2xvZ19maWxlJ10sICRsaW5lLCBGSUxFX0FQUEVORCB8IExPQ0tfRVgpID09PSBmYWxzZSkgewogICAgICAgIGVycm9yX2xvZygnW3NlY19wYXRjaF9jdmUyMDI2XSAnIC4gdHJpbSgkbGluZSkpOwogICAgfQp9CgpmdW5jdGlvbiBzZWNwX2Jsb2NrKCRyZWFzb24pCnsKICAgIHNlY3BfbG9nKCdCTE9DS0VEOiAnIC4gJHJlYXNvbik7CiAgICBpZiAoIWhlYWRlcnNfc2VudCgpKSB7CiAgICAgICAgaGVhZGVyKCdIVFRQLzEuMSA0MDAgQmFkIFJlcXVlc3QnLCB0cnVlLCA0MDApOwogICAgfQogICAgZWNobyAnQmFkIFJlcXVlc3QnOwogICAgZXhpdDsKfQoKZnVuY3Rpb24gc2VjcF9jaGVja19kZXB0aCgkZGF0YSwgJGRlcHRoLCAmJGNvdW50KQp7CiAgICAkY2ZnID0gJEdMT0JBTFNbJ1NFQ19QQVRDSF9DRkcnXTsKICAgIGlmICgkZGVwdGggPiAkY2ZnWydtYXhfaW5wdXRfZGVwdGgnXSkgewogICAgICAgIHNlY3BfYmxvY2soJ2lucHV0IG5lc3RpbmcgZGVwdGggPiAnIC4gJGNmZ1snbWF4X2lucHV0X2RlcHRoJ10pOwogICAgfQogICAgZm9yZWFjaCAoJGRhdGEgYXMgJHYpIHsKICAgICAgICAkY291bnQrKzsKICAgICAgICBpZiAoJGNvdW50ID4gJGNmZ1snbWF4X2lucHV0X2NvdW50J10pIHsKICAgICAgICAgICAgc2VjcF9ibG9jaygnaW5wdXQgdmFyaWFibGUgY291bnQgPiAnIC4gJGNmZ1snbWF4X2lucHV0X2NvdW50J10pOwogICAgICAgIH0KICAgICAgICBpZiAoaXNfYXJyYXkoJHYpKSB7CiAgICAgICAgICAgIHNlY3BfY2hlY2tfZGVwdGgoJHYsICRkZXB0aCArIDEsICRjb3VudCk7CiAgICAgICAgfQogICAgfQp9CgokY2ZnID0gJEdMT0JBTFNbJ1NFQ19QQVRDSF9DRkcnXTsKCmlmICgkY2ZnWydtZW1vcnlfbGltaXQnXSAhPT0gJycgJiYgZnVuY3Rpb25fZXhpc3RzKCdpbmlfc2V0JykpIHsKICAgICRjdXJyZW50ID0gaW5pX2dldCgnbWVtb3J5X2xpbWl0Jyk7CiAgICBpZiAoJGN1cnJlbnQgIT09ICRjZmdbJ21lbW9yeV9saW1pdCddKSB7CiAgICAgICAgQGluaV9zZXQoJ21lbW9yeV9saW1pdCcsICRjZmdbJ21lbW9yeV9saW1pdCddKTsKICAgIH0KfQoKaWYgKCRjZmdbJ2Jsb2NrX3Nlc3Npb25fdXBsb2FkX3Byb2dyZXNzJ10gJiYgIWVtcHR5KCRfUE9TVCkpIHsKICAgIGZvcmVhY2ggKCRfUE9TVCBhcyAka2V5ID0+ICR2YWwpIHsKICAgICAgICBpZiAoaXNfc3RyaW5nKCRrZXkpICYmIHN0cmlwb3MoJGtleSwgJ1BIUF9TRVNTSU9OX1VQTE9BRF9QUk9HUkVTUycpICE9PSBmYWxzZSkgewogICAgICAgICAgICB1bnNldCgkX1BPU1RbJGtleV0pOwogICAgICAgICAgICBzZWNwX2xvZygnQkxPQ0tFRDogc2Vzc2lvbi51cGxvYWRfcHJvZ3Jlc3Mga2V5IGluIFBPU1QgKENWRS0yMDI2LTEwOTYxOSBwYXRoKScpOwogICAgICAgIH0KICAgIH0KfQoKaWYgKCFlbXB0eSgkX1NFUlZFUlsnUkVRVUVTVF9NRVRIT0QnXSkpIHsKICAgIGlmICgkY2ZnWydibG9ja19taXNzaW5nX2NvbnRlbnRfbGVuZ3RoJ10KICAgICAgICAmJiBpbl9hcnJheSgkX1NFUlZFUlsnUkVRVUVTVF9NRVRIT0QnXSwgYXJyYXkoJ1BPU1QnLCAnUFVUJyksIHRydWUpCiAgICAgICAgJiYgIWlzc2V0KCRfU0VSVkVSWydDT05URU5UX0xFTkdUSCddKQogICAgKSB7CiAgICAgICAgc2VjcF9ibG9jaygncmVxdWVzdCBib2R5IHdpdGhvdXQgQ29udGVudC1MZW5ndGgnKTsKICAgIH0KCiAgICAkaW5wdXRDb3VudCA9IDA7CiAgICBzZWNwX2NoZWNrX2RlcHRoKCRfR0VULCAxLCAkaW5wdXRDb3VudCk7CiAgICBzZWNwX2NoZWNrX2RlcHRoKCRfUE9TVCwgMSwgJGlucHV0Q291bnQpOwogICAgc2VjcF9jaGVja19kZXB0aCgkX0ZJTEVTLCAxLCAkaW5wdXRDb3VudCk7Cn0KCmZ1bmN0aW9uIHNlY3Bfc2h1dGRvd25fY2hlY2soKQp7CiAgICAkY2ZnID0gJEdMT0JBTFNbJ1NFQ19QQVRDSF9DRkcnXTsKICAgICRlcnIgPSBlcnJvcl9nZXRfbGFzdCgpOwogICAgaWYgKCRlcnIgPT09IG51bGwpIHsKICAgICAgICByZXR1cm47CiAgICB9CiAgICAkZmF0YWxUeXBlcyA9IGFycmF5KAogICAgICAgIEVfRVJST1IgPT4gdHJ1ZSwgRV9QQVJTRSA9PiB0cnVlLCBFX0NPUkVfRVJST1IgPT4gdHJ1ZSwKICAgICAgICBFX0NPTVBJTEVfRVJST1IgPT4gdHJ1ZSwgRV9VU0VSX0VSUk9SID0+IHRydWUsCiAgICApOwogICAgaWYgKGlzc2V0KCRmYXRhbFR5cGVzWyRlcnJbJ3R5cGUnXV0pKSB7CiAgICAgICAgc2VjcF9sb2coc3ByaW50ZigKICAgICAgICAgICAgJ0ZBVEFMOiAlcyBpbiAlczolZCcsCiAgICAgICAgICAgICRlcnJbJ21lc3NhZ2UnXSwKICAgICAgICAgICAgJGVyclsnZmlsZSddLAogICAgICAgICAgICAkZXJyWydsaW5lJ10KICAgICAgICApKTsKICAgIH0KfQoKaWYgKCRjZmdbJ2xvZ19mYXRhbF9lcnJvcnMnXSkgewogICAgcmVnaXN0ZXJfc2h1dGRvd25fZnVuY3Rpb24oJ3NlY3Bfc2h1dGRvd25fY2hlY2snKTsKfQoKfQo=');

define('SEC_PATCH_MARKER', 'sec-patch-cve2026');

/* ------------------------------ helpers --------------------------------- */

function out($s) { echo $s . "\n"; }

function fail($s) { out("ОШИБКА: $s"); exit(1); }

function guard_source()
{
    $src = base64_decode(SEC_PATCH_PAYLOAD_B64, true);
    if ($src === false || strpos($src, '<?php') !== 0) {
        fail('повреждён встроенный payload guard-файла');
    }
    return $src;
}

/* ------------------------------ main ------------------------------------ */

$target = __DIR__; // по умолчанию - каталог, где лежит сам установщик
$mode = 'install';
foreach (array_slice($argv, 1) as $o) {
    $flag = strtolower($o);
    if ($flag === '--uninstall') {
        $mode = 'uninstall';
    } elseif ($flag === '--status') {
        $mode = 'status';
    } elseif ($flag === '--test') {
        $mode = 'test';
    } else {
        $target = rtrim($o, '/\\'); // первый не-флаговый аргумент = путь
    }
}

if (!is_dir($target)) {
    fail("каталог не найден: $target");
}
$targetAbs = str_replace('\\', '/', realpath($target));
out("Цель: $targetAbs");
out("Режим: $mode");
out('');

$guardFile   = $targetAbs . '/sec_patch_cve2026.php';
$userIniFile = $targetAbs . '/.user.ini';
$htaccessFile= $targetAbs . '/.htaccess';

$iniBegin    = '; BEGIN ' . SEC_PATCH_MARKER;
$iniEnd      = '; END '   . SEC_PATCH_MARKER;
$htBegin     = '# BEGIN ' . SEC_PATCH_MARKER;
$htEnd       = '# END '   . SEC_PATCH_MARKER;

/* --------------------------- живые проверки ------------------------------ */

/**
 * Минимальный HTTP-клиент на сокетах (без зависимостей).
 * Возвращает array(http_code, body) или null при ошибке соединения.
 */
function secp_http($url, $postBody = null, $chunked = false)
{
    $u = parse_url($url);
    if (!$u || empty($u['host'])) {
        return null;
    }
    $scheme = isset($u['scheme']) ? strtolower($u['scheme']) : 'http';
    $host = $u['host'];
    $port = isset($u['port']) ? (int)$u['port'] : ($scheme === 'https' ? 443 : 80);
    $path = (isset($u['path']) && $u['path'] !== '') ? $u['path'] : '/';
    if (isset($u['query'])) {
        $path .= '?' . $u['query'];
    }
    $transport = ($scheme === 'https') ? 'ssl' : 'tcp';
    // Проверку сертификата отключаем сознательно: клиент ходит на свой же сайт, где самоподписанный сертификат - обычное дело.
    $ctx = stream_context_create(array('ssl' => array(
        'SNI_enabled' => true,
        'verify_peer' => false,
        'verify_peer_name' => false,
        'allow_self_signed' => true,
    )));
    $sock = @stream_socket_client(
        $transport . '://' . $host . ':' . $port, $errno, $errstr, 10,
        STREAM_CLIENT_CONNECT, $ctx
    );
    if (!$sock) {
        return null;
    }
    if ($postBody !== null) {
        if ($chunked) {
            // запрос БЕЗ Content-Length, тело чанками (тест CVE-2026-109618)
            $req = "POST $path HTTP/1.1\r\nHost: $host\r\n"
                 . "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                 . dechex(strlen($postBody)) . "\r\n" . $postBody . "\r\n0\r\n\r\n";
        } else {
            $req = "POST $path HTTP/1.1\r\nHost: $host\r\n"
                 . "Content-Type: application/x-www-form-urlencoded\r\n"
                 . 'Content-Length: ' . strlen($postBody) . "\r\n"
                 . "Connection: close\r\n\r\n" . $postBody;
        }
    } else {
        $req = "GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n";
    }
    fwrite($sock, $req);
    $resp = '';
    while (!feof($sock)) {
        $resp .= fread($sock, 8192);
    }
    fclose($sock);
    if (!preg_match('/HTTP\/1\.[01]\s+(\d{3})/', $resp, $m)) {
        return null;
    }
    $body = '';
    $pos = strpos($resp, "\r\n\r\n");
    if ($pos !== false) {
        $body = substr($resp, $pos + 4);
        if (preg_match('/Transfer-Encoding:\s*chunked/i', substr($resp, 0, $pos))) {
            $decoded = '';
            $p = 0;
            while (($nl = strpos($body, "\r\n", $p)) !== false) {
                $len = hexdec(substr($body, $p, $nl - $p));
                if ($len === 0) {
                    break;
                }
                $decoded .= substr($body, $nl + 2, $len);
                $p = $nl + 2 + $len + 2;
            }
            $body = $decoded;
        }
    }
    return array((int)$m[1], $body);
}

/**
 * Живые проверки патча на работающем сайте.
 */
function secp_live_checks($targetAbs, $url)
{
    out('');
    out("--- Живые проверки ($url) ---");

    // 1. chunked POST без Content-Length -> ожидаем 400 от guard'а
    $r = secp_http($url, 'a=1', true);
    if ($r === null) {
        out('  [??] сайт недоступен по этому адресу, проверьте вручную:');
        out("       curl -X POST -H \"Transfer-Encoding: chunked\" --data-binary \"a=1\" $url");
    } elseif ($r[0] === 400) {
        out('  [OK] chunked POST без Content-Length -> HTTP 400 (guard блокирует)');
    } else {
        out('  [!!] chunked POST -> HTTP ' . $r[0] . ', ожидался 400 — guard не сработал');
    }

    // 2. PHP_SESSION_UPLOAD_PROGRESS -> обычный ответ + запись в лог guard'а
    $logFile = $targetAbs . '/sec-patch-cve2026.log';
    $logSize = is_file($logFile) ? (int)filesize($logFile) : 0;
    $r = secp_http($url, 'PHP_SESSION_UPLOAD_PROGRESS=test', false);
    clearstatcache(true, $logFile); // сбросить stat-кэш PHP
    $logGrew = false;
    if (is_file($logFile) && (int)filesize($logFile) > $logSize) {
        $tail = (string)file_get_contents($logFile, false, null, $logSize);
        $logGrew = (stripos($tail, 'session.upload_progress') !== false);
    }
    if ($r === null) {
        out('  [??] сайт недоступен, проверьте вручную:');
        out("       curl -X POST -d \"PHP_SESSION_UPLOAD_PROGRESS=test\" $url");
    } elseif ($r[0] !== 400 && $logGrew) {
        out('  [OK] PHP_SESSION_UPLOAD_PROGRESS -> HTTP ' . $r[0] . ', попытка зафиксирована в логе');
    } elseif ($r[0] !== 400) {
        out('  [~?] PHP_SESSION_UPLOAD_PROGRESS -> HTTP ' . $r[0] . ', но записи в логе нет');
        out('       (проверьте права на запись sec-patch-cve2026.log)');
    } else {
        out('  [!!] PHP_SESSION_UPLOAD_PROGRESS -> HTTP 400 — неожиданная блокировка');
    }

    // 3. ini-проба: временный файл в корне сайта, значения ini в веб-контексте
    $probe = 'sec_patch_probe_' . bin2hex(random_bytes(4)) . '.php';
    $probeFile = $targetAbs . '/' . $probe;
    file_put_contents(
        $probeFile,
        '<?php echo ini_get("session.upload_progress.enabled"),"|",ini_get("memory_limit"),"|",ini_get("auto_prepend_file");'
    );
    $r = secp_http(rtrim($url, '/') . '/' . $probe);
    @unlink($probeFile);
    if ($r === null) {
        out('  [??] не удалось выполнить ini-пробу');
    } else {
        $v = explode('|', trim($r[1]));
        $enabled = isset($v[0]) ? trim($v[0]) : '';
        $memlim  = isset($v[1]) ? trim($v[1]) : '';
        $prepend = isset($v[2]) ? trim($v[2]) : '';
        out('  ini в веб-контексте: session.upload_progress.enabled=' . ($enabled === '' ? "''" : $enabled)
            . ', memory_limit=' . ($memlim === '' ? "''" : $memlim)
            . ', auto_prepend_file=' . ($prepend === '' ? "''" : $prepend));
        out($enabled === '0' || $enabled === ''
            ? '  [OK] session.upload_progress отключён'
            : '  [!!] session.upload_progress.enabled=' . $enabled . ' — настройка не применилась');
        out($memlim === '-1'
            ? '  [OK] memory_limit = -1'
            : '  [!!] memory_limit = ' . $memlim . ' — настройка не применилась');
        out(strpos($prepend, 'sec_patch_cve2026.php') !== false
            ? '  [OK] auto_prepend_file указывает на guard'
            : '  [!!] auto_prepend_file = ' . $prepend . ' — guard не подключён');
    }
}

/* ------------------------------ status ---------------------------------- */

/* Основной код не выполняется, если определён SEC_PATCH_NO_MAIN
 * (позволяет подключать функции установщика из тестов). */
if (!defined('SEC_PATCH_NO_MAIN')) {

if ($mode === 'status') {
    out('--- Статические проверки ---');
    out('guard файл:            ' . (is_file($guardFile) ? 'ЕСТЬ' : 'нет'));
    $ini = is_file($userIniFile) ? file_get_contents($userIniFile) : '';
    out('.user.ini блок:        ' . (strpos($ini, $iniBegin) !== false ? 'ЕСТЬ' : 'нет'));
    out('.user.ini prepend:     ' . (preg_match('/^auto_prepend_file\s*=/m', $ini) ? 'ЕСТЬ' : 'нет'));
    $ht = is_file($htaccessFile) ? file_get_contents($htaccessFile) : '';
    out('.htaccess блок:        ' . (strpos($ht, $htBegin) !== false ? 'ЕСТЬ' : 'нет'));
    out('');
    out('Живые проверки сайта: php install_sec_patch.php --test');
    exit(0);
}

/* ------------------------------- test ----------------------------------- */

if ($mode === 'test') {
    // URL выводим из имени папки сайта (для прода /var/www/site.ru -> https://site.ru/)
    $base = basename($targetAbs);
    $url = 'https://' . $base . '/';
    if (secp_http($url) === null) {
        $url = 'http://' . $base . '/';
        if (secp_http($url) === null) {
            $url = '';
        }
    }
    if ($url === '') {
        out('Сайт по адресу https/http://' . $base . '/ недоступен.');
        out('Проверьте вручную:');
        out('  curl -X POST -H "Transfer-Encoding: chunked" --data-binary "a=1" https://' . $base . '/');
        out('  curl -X POST -d "PHP_SESSION_UPLOAD_PROGRESS=test" https://' . $base . '/');
        out('  php -r "echo ini_get(\'session.upload_progress.enabled\');"');
    } else {
        secp_live_checks($targetAbs, $url);
    }
    exit(0);
}

/* ---------------------------- uninstall --------------------------------- */

if ($mode === 'uninstall') {
    if (is_file($guardFile)) { @unlink($guardFile); out('удалён guard-файл'); }
    if (is_file($userIniFile)) {
        $c = file_get_contents($userIniFile);
        $c = preg_replace('/' . preg_quote($iniBegin, '/') . '.*?' . preg_quote($iniEnd, '/') . '\n?/s', '', $c);
        file_put_contents($userIniFile, $c);
        out('блок удалён из .user.ini');
    }
    if (is_file($htaccessFile)) {
        $c = file_get_contents($htaccessFile);
        $c = preg_replace('/' . preg_quote($htBegin, '/') . '.*?' . preg_quote($htEnd, '/') . '\n?/s', '', $c);
        file_put_contents($htaccessFile, $c);
        out('блок удалён из .htaccess');
    }
    out('');
    out('Готово. Перезапустите PHP-FPM, если он используется.');
    exit(0);
}

/* ----------------------------- install ---------------------------------- */

// 1. Guard-файл
$payload = guard_source();
if (is_file($guardFile)) {
    if (md5_file($guardFile) !== md5($payload)) {
        copy($guardFile, $guardFile . '.bak');
        file_put_contents($guardFile, $payload);
        out('[1/3] guard-файл обновлён (старая версия сохранена в sec_patch_cve2026.php.bak)');
    } else {
        out('[1/3] guard-файл уже актуален');
    }
} else {
    file_put_contents($guardFile, $payload);
    out('[1/3] создан guard-файл sec_patch_cve2026.php');
}

// 2. .user.ini
$iniBlock = $iniBegin . "\n"
    . "; Митигации CVE-2026-109618 / CVE-2026-109619 (advisory php.net 21.10.2026)\n"
    . "session.upload_progress.enabled = 0\n"
    . "memory_limit = -1\n"
    . "auto_prepend_file = " . $targetAbs . "/sec_patch_cve2026.php\n"
    . $iniEnd . "\n";

if (is_file($userIniFile)) {
    $c = file_get_contents($userIniFile);
    if (strpos($c, $iniBegin) !== false) {
        // обновляем существующий блок (путь мог измениться)
        $c = preg_replace(
            '/' . preg_quote($iniBegin, '/') . '.*?' . preg_quote($iniEnd, '/') . '\n?/s',
            $iniBlock,
            $c
        );
        file_put_contents($userIniFile, $c);
        out('[2/3] блок в .user.ini обновлён');
    } else {
        // чужой auto_prepend_file конфликтует с нашим
        if (preg_match('/^\s*auto_prepend_file\s*=/m', $c)) {
            out('[2/3] ВНИМАНИЕ: в .user.ini уже задан чужой auto_prepend_file —');
            out('      блок митигаций добавлен БЕЗ строки auto_prepend_file.');
            out('      Решите конфликт вручную: два prepend-файла задать нельзя.');
            $blockNoPrepend = str_replace(
                'auto_prepend_file = ' . $targetAbs . "/sec_patch_cve2026.php\n", '', $iniBlock
            );
            file_put_contents($userIniFile, "\n" . $blockNoPrepend, FILE_APPEND);
        } else {
            file_put_contents($userIniFile, "\n" . $iniBlock, FILE_APPEND);
            out('[2/3] блок митигаций дописан в .user.ini');
        }
    }
} else {
    file_put_contents($userIniFile, $iniBlock);
    out('[2/3] создан .user.ini с блоком митигаций');
}

// 3. .htaccess (только для mod_php; при FPM игнорируется)
$htBlock = $htBegin . "\n"
    . "# Митигации CVE-2026-109618 / CVE-2026-109619 (mod_php; при FPM игнорируется)\n"
    . "<IfModule mod_php7.c>\n"
    . "    php_flag session.upload_progress.enabled 0\n"
    . "    php_value memory_limit -1\n"
    . "    php_value auto_prepend_file " . $targetAbs . "/sec_patch_cve2026.php\n"
    . "</IfModule>\n"
    . $htEnd . "\n";

if (is_file($htaccessFile)) {
    $c = file_get_contents($htaccessFile);
    if (strpos($c, $htBegin) !== false) {
        $c = preg_replace(
            '/' . preg_quote($htBegin, '/') . '.*?' . preg_quote($htEnd, '/') . '\n?/s',
            $htBlock,
            $c
        );
        file_put_contents($htaccessFile, $c);
        out('[3/3] блок в .htaccess обновлён');
    } else {
        file_put_contents($htaccessFile, "\n" . $htBlock, FILE_APPEND);
        out('[3/3] блок дописан в .htaccess');
    }
} else {
    file_put_contents($htaccessFile, $htBlock);
    out('[3/3] создан .htaccess с блоком митигаций');
}

out('');
out('Готово. Проверка:');
out('  1) Откройте сайт — должен работать.');
out('  2) php install_sec_patch.php --status  # статические проверки');
out('  3) php install_sec_patch.php --test    # живые проверки сайта');
out('  4) Перезапустите PHP-FPM (для CVE-2026-109619 это обязательно).');
} // end SEC_PATCH_NO_MAIN
