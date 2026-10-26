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
 *   3. Вставляет в НАЧАЛО <site>/.htaccess блок (если файла нет -
 *      создаёт): до rewrite-правил сайта, чтобы chunked-запросы
 *      блокировались до любых редиректов (например, редиректа
 *      на www-домен).
 *
 * Абсолютный путь в auto_prepend_file покрывает и точки входа в
 * подкаталогах (adm/ и т.п.) - отдельные хуки не нужны.
 *
 * Идемпотентен: повторный запуск обновляет путь, а не дублирует блоки.
 * Совместимо с PHP 5.3+ в CLI (сервер может работать на PHP 5.x).
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("CLI only\n");
}

/* Зашитый guard (base64 от sec_patch_cve2026.php) */
define('SEC_PATCH_PAYLOAD_B64', 'PD9waHAKCmlmIChkZWZpbmVkKCdTRUNfUEFUQ0hfQ1ZFXzIwMjZfTE9BREVEJykpIHsKICAgIHJldHVybjsKfQpkZWZpbmUoJ1NFQ19QQVRDSF9DVkVfMjAyNl9MT0FERUQnLCAxKTsKCiRHTE9CQUxTWydTRUNfUEFUQ0hfQ0ZHJ10gPSBhcnJheSgKICAgICdtZW1vcnlfbGltaXQnICAgICAgICAgICAgICAgICAgPT4gJy0xJywKICAgICdtYXhfaW5wdXRfY291bnQnICAgICAgICAgICAgICAgPT4gMTAwMCwKICAgICdtYXhfaW5wdXRfZGVwdGgnICAgICAgICAgICAgICAgPT4gNSwKICAgICdibG9ja19zZXNzaW9uX3VwbG9hZF9wcm9ncmVzcycgPT4gdHJ1ZSwKICAgICdibG9ja19taXNzaW5nX2NvbnRlbnRfbGVuZ3RoJyAgPT4gdHJ1ZSwKICAgICdsb2dfZmlsZScgICAgICAgICAgICAgICAgICAgICAgPT4gX19ESVJfXyAuICcvc2VjLXBhdGNoLWN2ZTIwMjYubG9nJywKICAgICdsb2dfZmF0YWxfZXJyb3JzJyAgICAgICAgICAgICAgPT4gdHJ1ZSwKKTsKCmlmICghZnVuY3Rpb25fZXhpc3RzKCdzZWNwX2xvZycpKSB7CgpmdW5jdGlvbiBzZWNwX2xvZygkcmVhc29uKQp7CiAgICAkY2ZnID0gJEdMT0JBTFNbJ1NFQ19QQVRDSF9DRkcnXTsKICAgICRsaW5lID0gc3ByaW50ZigKICAgICAgICAiWyVzXSAlcyB8IFVSST0lcyB8IElQPSVzIHwgVUE9JXMgfCBNZXRob2Q9JXMgfCBDTD0lc1xuIiwKICAgICAgICBkYXRlKCdZLW0tZCBIOmk6cycpLAogICAgICAgICRyZWFzb24sCiAgICAgICAgaXNzZXQoJF9TRVJWRVJbJ1JFUVVFU1RfVVJJJ10pID8gJF9TRVJWRVJbJ1JFUVVFU1RfVVJJJ10gOiAnLScsCiAgICAgICAgaXNzZXQoJF9TRVJWRVJbJ1JFTU9URV9BRERSJ10pID8gJF9TRVJWRVJbJ1JFTU9URV9BRERSJ10gOiAnLScsCiAgICAgICAgaXNzZXQoJF9TRVJWRVJbJ0hUVFBfVVNFUl9BR0VOVCddKSA/IHN1YnN0cigkX1NFUlZFUlsnSFRUUF9VU0VSX0FHRU5UJ10sIDAsIDIwMCkgOiAnLScsCiAgICAgICAgaXNzZXQoJF9TRVJWRVJbJ1JFUVVFU1RfTUVUSE9EJ10pID8gJF9TRVJWRVJbJ1JFUVVFU1RfTUVUSE9EJ10gOiAnLScsCiAgICAgICAgaXNzZXQoJF9TRVJWRVJbJ0NPTlRFTlRfTEVOR1RIJ10pID8gJF9TRVJWRVJbJ0NPTlRFTlRfTEVOR1RIJ10gOiAnbm9uZScKICAgICk7CiAgICBpZiAoQGZpbGVfcHV0X2NvbnRlbnRzKCRjZmdbJ2xvZ19maWxlJ10sICRsaW5lLCBGSUxFX0FQUEVORCB8IExPQ0tfRVgpICE9PSBmYWxzZSkgewogICAgICAgIHJldHVybjsKICAgIH0KICAgICRmYWxsYmFjayA9IHJ0cmltKHN5c19nZXRfdGVtcF9kaXIoKSwgJy9cXCcpIC4gJy9zZWMtcGF0Y2gtY3ZlMjAyNi5sb2cnOwogICAgaWYgKEBmaWxlX3B1dF9jb250ZW50cygkZmFsbGJhY2ssICRsaW5lLCBGSUxFX0FQUEVORCB8IExPQ0tfRVgpICE9PSBmYWxzZSkgewogICAgICAgIGlmIChlbXB0eSgkR0xPQkFMU1snU0VDX1BBVENIX0xPR19GQUxMQkFDS19OT1RFRCddKSkgewogICAgICAgICAgICAkR0xPQkFMU1snU0VDX1BBVENIX0xPR19GQUxMQkFDS19OT1RFRCddID0gdHJ1ZTsKICAgICAgICAgICAgZXJyb3JfbG9nKCdbc2VjX3BhdGNoX2N2ZTIwMjZdIGxvZyBmaWxlIG5vdCB3cml0YWJsZTogJyAuICRjZmdbJ2xvZ19maWxlJ10KICAgICAgICAgICAgICAgIC4gJyAtIHVzaW5nIGZhbGxiYWNrOiAnIC4gJGZhbGxiYWNrKTsKICAgICAgICB9CiAgICAgICAgcmV0dXJuOwogICAgfQogICAgZXJyb3JfbG9nKCdbc2VjX3BhdGNoX2N2ZTIwMjZdICcgLiB0cmltKCRsaW5lKSk7Cn0KCmZ1bmN0aW9uIHNlY3BfbG9nX2RpYWcoKQp7CiAgICAkY2ZnID0gJEdMT0JBTFNbJ1NFQ19QQVRDSF9DRkcnXTsKICAgICRmaWxlID0gJGNmZ1snbG9nX2ZpbGUnXTsKICAgIGlmIChpc19maWxlKCRmaWxlKSkgewogICAgICAgIGlmICghaXNfd3JpdGFibGUoJGZpbGUpKSB7CiAgICAgICAgICAgIGVycm9yX2xvZygnW3NlY19wYXRjaF9jdmUyMDI2XSBsb2cgZmlsZSBub3Qgd3JpdGFibGU6ICcgLiAkZmlsZQogICAgICAgICAgICAgICAgLiAnIChjaGVjayBvd25lci9wZXJtaXNzaW9uczsgZmFsbGJhY2s6ICcgLiBzeXNfZ2V0X3RlbXBfZGlyKCkgLiAnKScpOwogICAgICAgIH0KICAgICAgICByZXR1cm47CiAgICB9CiAgICBpZiAoIWlzX3dyaXRhYmxlKGRpcm5hbWUoJGZpbGUpKSkgewogICAgICAgIGVycm9yX2xvZygnW3NlY19wYXRjaF9jdmUyMDI2XSBsb2cgZGlyZWN0b3J5IG5vdCB3cml0YWJsZTogJyAuIGRpcm5hbWUoJGZpbGUpCiAgICAgICAgICAgIC4gJyAoY2hlY2sgb3duZXIvcGVybWlzc2lvbnM7IGZhbGxiYWNrOiAnIC4gc3lzX2dldF90ZW1wX2RpcigpIC4gJyknKTsKICAgIH0KfQoKZnVuY3Rpb24gc2VjcF9ibG9jaygkcmVhc29uKQp7CiAgICBzZWNwX2xvZygnQkxPQ0tFRDogJyAuICRyZWFzb24pOwogICAgaWYgKCFoZWFkZXJzX3NlbnQoKSkgewogICAgICAgIGhlYWRlcignSFRUUC8xLjEgNDAwIEJhZCBSZXF1ZXN0JywgdHJ1ZSwgNDAwKTsKICAgIH0KICAgIGVjaG8gJ0JhZCBSZXF1ZXN0JzsKICAgIGV4aXQ7Cn0KCmZ1bmN0aW9uIHNlY3BfY2hlY2tfZGVwdGgoJGRhdGEsICRkZXB0aCwgJiRjb3VudCkKewogICAgJGNmZyA9ICRHTE9CQUxTWydTRUNfUEFUQ0hfQ0ZHJ107CiAgICBpZiAoJGRlcHRoID4gJGNmZ1snbWF4X2lucHV0X2RlcHRoJ10pIHsKICAgICAgICBzZWNwX2Jsb2NrKCdpbnB1dCBuZXN0aW5nIGRlcHRoID4gJyAuICRjZmdbJ21heF9pbnB1dF9kZXB0aCddKTsKICAgIH0KICAgIGZvcmVhY2ggKCRkYXRhIGFzICR2KSB7CiAgICAgICAgJGNvdW50Kys7CiAgICAgICAgaWYgKCRjb3VudCA+ICRjZmdbJ21heF9pbnB1dF9jb3VudCddKSB7CiAgICAgICAgICAgIHNlY3BfYmxvY2soJ2lucHV0IHZhcmlhYmxlIGNvdW50ID4gJyAuICRjZmdbJ21heF9pbnB1dF9jb3VudCddKTsKICAgICAgICB9CiAgICAgICAgaWYgKGlzX2FycmF5KCR2KSkgewogICAgICAgICAgICBzZWNwX2NoZWNrX2RlcHRoKCR2LCAkZGVwdGggKyAxLCAkY291bnQpOwogICAgICAgIH0KICAgIH0KfQoKJGNmZyA9ICRHTE9CQUxTWydTRUNfUEFUQ0hfQ0ZHJ107CgppZiAoZW1wdHkoJEdMT0JBTFNbJ1NFQ19QQVRDSF9MT0dfRElBR19ET05FJ10pKSB7CiAgICAkR0xPQkFMU1snU0VDX1BBVENIX0xPR19ESUFHX0RPTkUnXSA9IHRydWU7CiAgICBzZWNwX2xvZ19kaWFnKCk7Cn0KCmlmICgkY2ZnWydtZW1vcnlfbGltaXQnXSAhPT0gJycgJiYgZnVuY3Rpb25fZXhpc3RzKCdpbmlfc2V0JykpIHsKICAgICRjdXJyZW50ID0gaW5pX2dldCgnbWVtb3J5X2xpbWl0Jyk7CiAgICBpZiAoJGN1cnJlbnQgIT09ICRjZmdbJ21lbW9yeV9saW1pdCddKSB7CiAgICAgICAgQGluaV9zZXQoJ21lbW9yeV9saW1pdCcsICRjZmdbJ21lbW9yeV9saW1pdCddKTsKICAgIH0KfQoKaWYgKCRjZmdbJ2Jsb2NrX3Nlc3Npb25fdXBsb2FkX3Byb2dyZXNzJ10gJiYgIWVtcHR5KCRfUE9TVCkpIHsKICAgIGZvcmVhY2ggKCRfUE9TVCBhcyAka2V5ID0+ICR2YWwpIHsKICAgICAgICBpZiAoaXNfc3RyaW5nKCRrZXkpICYmIHN0cmlwb3MoJGtleSwgJ1BIUF9TRVNTSU9OX1VQTE9BRF9QUk9HUkVTUycpICE9PSBmYWxzZSkgewogICAgICAgICAgICB1bnNldCgkX1BPU1RbJGtleV0pOwogICAgICAgICAgICBzZWNwX2xvZygnQkxPQ0tFRDogc2Vzc2lvbi51cGxvYWRfcHJvZ3Jlc3Mga2V5IGluIFBPU1QgKENWRS0yMDI2LTEwOTYxOSBwYXRoKScpOwogICAgICAgIH0KICAgIH0KfQoKaWYgKCFlbXB0eSgkX1NFUlZFUlsnUkVRVUVTVF9NRVRIT0QnXSkpIHsKICAgICRpc1Byb2JlID0gZmFsc2U7CiAgICBpZiAoaXNzZXQoJF9TRVJWRVJbJ0hUVFBfWF9TRUNfUEFUQ0hfUFJPQkUnXSkKICAgICAgICAmJiBzdHJpcG9zKCRfU0VSVkVSWydIVFRQX1hfU0VDX1BBVENIX1BST0JFJ10sICdjaHVua2VkJykgIT09IGZhbHNlCiAgICApIHsKICAgICAgICAkaXNQcm9iZSA9IHRydWU7CiAgICB9CiAgICAkcHJvYmVWaWFQb3N0ID0gZmFsc2U7CiAgICBpZiAoaXNzZXQoJF9QT1NUWydzZWNfcGF0Y2hfcHJvYmUnXSkgJiYgJF9QT1NUWydzZWNfcGF0Y2hfcHJvYmUnXSA9PT0gJ2NodW5rZWQnKSB7CiAgICAgICAgJHByb2JlVmlhUG9zdCA9IHRydWU7CiAgICB9CiAgICBpZiAoJGlzUHJvYmUgfHwgJHByb2JlVmlhUG9zdCkgewogICAgICAgIHNlY3BfbG9nKHNwcmludGYoCiAgICAgICAgICAgICJQUk9CRTogVEU9JyVzJyBDTD0nJXMnIFJFUVVFU1RfTUVUSE9EPSVzIiwKICAgICAgICAgICAgaXNzZXQoJF9TRVJWRVJbJ0hUVFBfVFJBTlNGRVJfRU5DT0RJTkcnXSkgPyAkX1NFUlZFUlsnSFRUUF9UUkFOU0ZFUl9FTkNPRElORyddIDogJycsCiAgICAgICAgICAgIGlzc2V0KCRfU0VSVkVSWydDT05URU5UX0xFTkdUSCddKSA/ICRfU0VSVkVSWydDT05URU5UX0xFTkdUSCddIDogJycsCiAgICAgICAgICAgICRfU0VSVkVSWydSRVFVRVNUX01FVEhPRCddCiAgICAgICAgKSk7CiAgICB9CgogICAgJGlzQ2h1bmtlZCA9IGlzc2V0KCRfU0VSVkVSWydIVFRQX1RSQU5TRkVSX0VOQ09ESU5HJ10pCiAgICAgICAgJiYgc3RyaXBvcygkX1NFUlZFUlsnSFRUUF9UUkFOU0ZFUl9FTkNPRElORyddLCAnY2h1bmtlZCcpICE9PSBmYWxzZTsKCiAgICBpZiAoISRpc1Byb2JlICYmICRjZmdbJ2Jsb2NrX21pc3NpbmdfY29udGVudF9sZW5ndGgnXSkgewogICAgICAgIGlmICgkaXNDaHVua2VkKSB7CiAgICAgICAgICAgIHNlY3BfYmxvY2soJ2NodW5rZWQgVHJhbnNmZXItRW5jb2RpbmcgcmVxdWVzdCAoQ1ZFLTIwMjYtMTA5NjE4IHBhdGgpJyk7CiAgICAgICAgfQogICAgICAgIGlmIChpbl9hcnJheSgkX1NFUlZFUlsnUkVRVUVTVF9NRVRIT0QnXSwgYXJyYXkoJ1BPU1QnLCAnUFVUJyksIHRydWUpCiAgICAgICAgICAgICYmICFpc3NldCgkX1NFUlZFUlsnQ09OVEVOVF9MRU5HVEgnXSkKICAgICAgICApIHsKICAgICAgICAgICAgc2VjcF9ibG9jaygncmVxdWVzdCBib2R5IHdpdGhvdXQgQ29udGVudC1MZW5ndGgnKTsKICAgICAgICB9CiAgICB9CgogICAgJGlucHV0Q291bnQgPSAwOwogICAgc2VjcF9jaGVja19kZXB0aCgkX0dFVCwgMSwgJGlucHV0Q291bnQpOwogICAgc2VjcF9jaGVja19kZXB0aCgkX1BPU1QsIDEsICRpbnB1dENvdW50KTsKICAgIHNlY3BfY2hlY2tfZGVwdGgoJF9GSUxFUywgMSwgJGlucHV0Q291bnQpOwp9CgpmdW5jdGlvbiBzZWNwX3NodXRkb3duX2NoZWNrKCkKewogICAgJGNmZyA9ICRHTE9CQUxTWydTRUNfUEFUQ0hfQ0ZHJ107CiAgICAkZXJyID0gZXJyb3JfZ2V0X2xhc3QoKTsKICAgIGlmICgkZXJyID09PSBudWxsKSB7CiAgICAgICAgcmV0dXJuOwogICAgfQogICAgJGZhdGFsVHlwZXMgPSBhcnJheSgKICAgICAgICBFX0VSUk9SID0+IHRydWUsIEVfUEFSU0UgPT4gdHJ1ZSwgRV9DT1JFX0VSUk9SID0+IHRydWUsCiAgICAgICAgRV9DT01QSUxFX0VSUk9SID0+IHRydWUsIEVfVVNFUl9FUlJPUiA9PiB0cnVlLAogICAgKTsKICAgIGlmIChpc3NldCgkZmF0YWxUeXBlc1skZXJyWyd0eXBlJ11dKSkgewogICAgICAgIHNlY3BfbG9nKHNwcmludGYoCiAgICAgICAgICAgICdGQVRBTDogJXMgaW4gJXM6JWQnLAogICAgICAgICAgICAkZXJyWydtZXNzYWdlJ10sCiAgICAgICAgICAgICRlcnJbJ2ZpbGUnXSwKICAgICAgICAgICAgJGVyclsnbGluZSddCiAgICAgICAgKSk7CiAgICB9Cn0KCmlmICgkY2ZnWydsb2dfZmF0YWxfZXJyb3JzJ10pIHsKICAgIHJlZ2lzdGVyX3NodXRkb3duX2Z1bmN0aW9uKCdzZWNwX3NodXRkb3duX2NoZWNrJyk7Cn0KCn0K');

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

/**
 * PHP 5.x-совместимая генерация случайных байтов (nonce/имена временных
 * файлов). Приоритет: random_bytes (PHP 7+) ->
 * openssl_random_pseudo_bytes (при загруженном extension) -> fallback
 * mt_rand/uniqid (криптографически приемлем для nonce/токенов).
 */
function sec_patch_random_bytes($n)
{
    if (function_exists('random_bytes')) {
        return random_bytes($n);
    }
    if (function_exists('openssl_random_pseudo_bytes')) {
        $b = openssl_random_pseudo_bytes($n);
        if ($b !== false) {
            return $b;
        }
    }
    $b = '';
    while (strlen($b) < $n) {
        $b .= sha1(uniqid(mt_rand(), true), true);
    }
    return substr($b, 0, $n);
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
function secp_http($url, $postBody = null, $chunked = false, $followRedirects = false, $extraHeaders = array())
{
    $hops = 0;
    $code = null;
    $body = '';
    while ($url !== null && $hops <= 3) {
        $resp = secp_http_request($url, $postBody, $chunked, $extraHeaders);
        if ($resp === null) {
            return null;
        }
        $code = $resp[0];
        $body = $resp[1];
        if ($followRedirects
            && ($code === 301 || $code === 302 || $code === 307 || $code === 308)
            && preg_match('/^Location:\s*(\S+)/im', $resp[2], $m)
        ) {
            $url = secp_resolve_url($url, trim($m[1]));
            $hops++;
            continue;
        }
        break;
    }
    if ($code === null) {
        return null;
    }
    return array($code, $body);
}

/** Резолвит Location относительно базового URL. */
function secp_resolve_url($base, $loc)
{
    if (strpos($loc, '://') !== false) {
        return $loc;
    }
    $u = parse_url($base);
    if (!$u || empty($u['host'])) {
        return null;
    }
    $scheme = isset($u['scheme']) ? strtolower($u['scheme']) : 'http';
    $port = isset($u['port']) ? ':' . $u['port'] : '';
    if ($loc !== '' && $loc[0] === '/') {
        return $scheme . '://' . $u['host'] . $port . $loc;
    }
    $path = isset($u['path']) ? $u['path'] : '/';
    $dir = substr($path, 0, strrpos($path, '/') + 1);
    return $scheme . '://' . $u['host'] . $port . $dir . $loc;
}

function secp_http_request($url, $postBody, $chunked, $extraHeaders = array())
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
    $extra = '';
    foreach ($extraHeaders as $hdr) {
        $extra .= $hdr . "\r\n";
    }
    if ($postBody !== null) {
        if ($chunked) {
            // запрос БЕЗ Content-Length, тело чанками (тест CVE-2026-109618)
            $req = "POST $path HTTP/1.1\r\nHost: $host\r\n" . $extra
                 . "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                 . dechex(strlen($postBody)) . "\r\n" . $postBody . "\r\n0\r\n\r\n";
        } else {
            $req = "POST $path HTTP/1.1\r\nHost: $host\r\n" . $extra
                 . "Content-Type: application/x-www-form-urlencoded\r\n"
                 . 'Content-Length: ' . strlen($postBody) . "\r\n"
                 . "Connection: close\r\n\r\n" . $postBody;
        }
    } else {
        $req = "GET $path HTTP/1.1\r\nHost: $host\r\n" . $extra
             . "Connection: close\r\n\r\n";
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
    $headers = '';
    $pos = strpos($resp, "\r\n\r\n");
    if ($pos !== false) {
        $headers = substr($resp, 0, $pos);
        $body = substr($resp, $pos + 4);
        if (preg_match('/Transfer-Encoding:\s*chunked/i', $headers)) {
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
    return array((int)$m[1], $body, $headers);
}

/**
 * Живые проверки патча на работающем сайте.
 */
function secp_live_checks($targetAbs, $url)
{
    out('');
    out("--- Живые проверки ($url) ---");

    // 1. chunked POST: сначала проба заголовков, затем проверка блокировки.
    // Проба: chunked POST с маркером (заголовок X-Sec-Patch-Probe: chunked +
    // POST-поле sec_patch_probe=chunked). Guard с поддержкой пробы пишет в лог
    // строку "PROBE: TE='...' CL='...' REQUEST_METHOD=..." и НЕ блокирует
    // запрос. По значениям TE/CL в PROBE различаем три исхода.
    $logFile = $targetAbs . '/sec-patch-cve2026.log';
    $logSize = is_file($logFile) ? (int)filesize($logFile) : 0;

    $r = secp_http($url, 'sec_patch_probe=chunked', true, true,
        array('X-Sec-Patch-Probe: chunked'));
    clearstatcache(true, $logFile);
    $probeTE = null;
    $probeCL = '';
    if (is_file($logFile) && (int)filesize($logFile) > $logSize) {
        $tail = (string)file_get_contents($logFile, false, null, $logSize);
        if (preg_match("/PROBE: TE='([^']*)' CL='([^']*)'/", $tail, $m)) {
            $probeTE = $m[1];
            $probeCL = $m[2];
        }
    }

    if ($r === null) {
        out('  [??] сайт недоступен по этому адресу, проверьте вручную:');
        out("       curl -L -X POST -H \"Transfer-Encoding: chunked\" --data-binary \"a=1\" $url");
    } elseif ($probeTE === null) {
        out('  [!!] PROBE-строки в логе нет (ответ пробы HTTP ' . $r[0] . '):');
        out('       guard не получил пробный запрос либо лог недоступен.');
        out('       Проверьте: 1) auto_prepend_file на конечном домене (после');
        out('       редиректов, например non-www -> www); 2) права на запись:');
        out('       ' . $logFile);
        out('       3) если guard старой версии без поддержки пробы - перезапустите');
        out('       установщик, он обновит sec_patch_cve2026.php.');
    } elseif (stripos($probeTE, 'chunked') !== false) {
        // Transfer-Encoding доходит до PHP: проверяем фактическую блокировку
        // повторным chunked POST уже БЕЗ маркера
        $r2 = secp_http($url, 'a=1', true, true);
        if ($r2 !== null && $r2[0] === 400) {
            out('  [OK] chunked POST -> HTTP 400 (guard блокирует, TE доходит до PHP)');
        } else {
            out('  [!!] PROBE показал Transfer-Encoding: chunked, но повторный');
            out('       chunked POST без маркера -> HTTP '
                . (is_array($r2) ? $r2[0] : 'нет ответа') . ', ожидался 400.');
            out('       Guard не блокирует chunked: перезапустите установщик');
            out('       (обновит sec_patch_cve2026.php) и проверьте, что в конфиге');
            out('       guard-файла block_missing_content_length = true.');
        }
    } else {
        out('  [~] Transfer-Encoding не доходит до PHP (нормализуется на уровне');
        out("      nginx/прокси): PROBE: TE='" . $probeTE . "' CL='" . $probeCL . "'.");
        out('      PHP-уровень блокировки неприменим, риск chunked-smuggling в PHP');
        out('      снят на уровне прокси - это НЕ провал.');
        out('      Правило .htaccess (RewriteCond %{HTTP:Transfer-Encoding}) по той');
        out('      же причине за nginx тоже не сработает: Apache получает запрос');
        out('      уже с Content-Length и без Transfer-Encoding.');
    }

    // 2. PHP_SESSION_UPLOAD_PROGRESS -> обычный ответ + запись в лог guard'а
    $logSize = is_file($logFile) ? (int)filesize($logFile) : 0;
    $r = secp_http($url, 'PHP_SESSION_UPLOAD_PROGRESS=test', false, true);
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
    $probe = 'sec_patch_probe_' . bin2hex(sec_patch_random_bytes(4)) . '.php';
    $probeFile = $targetAbs . '/' . $probe;
    file_put_contents(
        $probeFile,
        '<?php echo ini_get("session.upload_progress.enabled"),"|",ini_get("memory_limit"),"|",ini_get("auto_prepend_file");'
    );
    $r = secp_http(rtrim($url, '/') . '/' . $probe, null, false, true);
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
$guardExisted = is_file($guardFile);
file_put_contents($guardFile, $payload);
out($guardExisted
    ? '[1/3] guard-файл sec_patch_cve2026.php обновлён'
    : '[1/3] создан guard-файл sec_patch_cve2026.php');

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

// 3. .htaccess (только для mod_php; при FPM игнорируется).
// Блок вставляется В НАЧАЛО файла, до rewrite-правил сайта: правила с
// флагом [L] (например, редирект site.ru -> www.site.ru) обрывают
// обработку до нашего блока, и chunked-запросы уходят в 301 вместо
// блокировки. IfModule покрывает mod_php5 (PHP 5.x), mod_php7 и mod_php
// (PHP 7/8): на PHP 5.x блок только с mod_php7.c полностью игнорируется.
$htPhp = "    php_flag session.upload_progress.enabled 0\n"
    . "    php_value memory_limit -1\n"
    . "    php_value auto_prepend_file " . $targetAbs . "/sec_patch_cve2026.php\n";
$htBlock = $htBegin . "\n"
    . "# Митигации CVE-2026-109618 / CVE-2026-109619 (mod_php; при FPM игнорируется)\n"
    . "# Блок до rewrite-правил сайта: chunked-запросы блокируются до редиректов.\n"
    . "RewriteEngine On\n"
    . "RewriteCond %{HTTP:Transfer-Encoding} chunked [NC]\n"
    . "RewriteRule .* - [R=400,L]\n"
    . "<IfModule mod_php5.c>\n" . $htPhp . "</IfModule>\n"
    . "<IfModule mod_php7.c>\n" . $htPhp . "</IfModule>\n"
    . "<IfModule mod_php.c>\n" . $htPhp . "</IfModule>\n"
    . $htEnd . "\n";

if (is_file($htaccessFile)) {
    $c = file_get_contents($htaccessFile);
    if (strpos($c, $htBlock) === 0) {
        out('[3/3] блок в .htaccess уже актуален (в начале файла)');
    } else {
        // Старый блок мог быть дописан в конец файла, после rewrite-правил
        // сайта: правила с флагом [L] обрывают обработку раньше, и блок
        // не срабатывает. Удаляем старый блок и вставляем новый в начало.
        $c = preg_replace(
            '/' . preg_quote($htBegin, '/') . '.*?' . preg_quote($htEnd, '/') . '\n?/s',
            '',
            $c
        );
        file_put_contents($htaccessFile, $htBlock . $c);
        out('[3/3] блок в .htaccess обновлён и перенесён в начало файла (до rewrite-правил сайта)');
    }
} else {
    file_put_contents($htaccessFile, $htBlock);
    out('[3/3] создан .htaccess с блоком митигаций');
}

out('');

// Самодиагностика лог-файла: guard пишет сюда попытки эксплуатации.
$logFile = $targetAbs . '/sec-patch-cve2026.log';
if (@file_put_contents($logFile, '', FILE_APPEND | LOCK_EX) === false) {
    out('ВНИМАНИЕ: тестовая запись в лог не удалась: ' . $logFile);
    out('  Проверьте owner/права каталога сайта (запись должна быть доступна');
    out('  пользователю, от которого работает PHP).');
    out('  Guard будет использовать fallback: '
        . (function_exists('sys_get_temp_dir') ? sys_get_temp_dir() : '/tmp'));
} else {
    out('Лог-файл доступен для записи: ' . $logFile);
}

out('');
out('Готово. Проверка:');
out('  1) Откройте сайт — должен работать.');
out('  2) php install_sec_patch.php --status  # статические проверки');
out('  3) php install_sec_patch.php --test    # живые проверки сайта');
out('  4) Перезапустите PHP-FPM (для CVE-2026-109619 это обязательно).');
out('  5) Учтите: .user.ini кэшируется (user_ini.cache_ttl, по умолчанию 300');
out('     секунд) — настройки применяются не мгновенно.');
} // end SEC_PATCH_NO_MAIN
