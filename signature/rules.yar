rule Crackme_Strings
{
    meta:
        severity = "low"
        description = "Строки проверки ключа/пароля (возможная точка входа в логику)"
    strings:
        $a = "password" nocase ascii wide
        $b = "serial" nocase ascii wide
        $c = "license" nocase ascii wide
        $d = "wrong" nocase ascii wide
        $e = "correct" nocase ascii wide
        $f = "try again" nocase ascii wide
        $g = "invalid" nocase ascii wide
        $h = "access" nocase ascii wide
    condition:
        2 of them
}

rule Crypto_AES_Sbox
{
    meta:
        severity = "medium"
        description = "Начало таблицы S-box алгоритма AES"
    strings:
        $sbox = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
    condition:
        $sbox
}

rule Crypto_SHA256_Constants
{
    meta:
        severity = "medium"
        description = "Константы раундов SHA-256"
    strings:
        $k = { 98 2F 8A 42 91 44 37 71 }
    condition:
        $k
}

rule Crypto_MD5_Init
{
    meta:
        severity = "medium"
        description = "Начальные значения MD5"
    strings:
        $init = { 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 }
    condition:
        $init
}

rule Embedded_URL
{
    meta:
        severity = "medium"
        description = "Зашитый в файл URL"
    strings:
        $url = /https?:\/\/[a-zA-Z0-9\.\-\/_]{4,}/ ascii wide
    condition:
        $url
}

rule AntiVM_Strings
{
    meta:
        severity = "medium"
        description = "Строки проверки виртуальной машины"
    strings:
        $a = "VMware" nocase ascii wide
        $b = "VirtualBox" nocase ascii wide
        $c = "VBOX" ascii wide
        $d = "QEMU" ascii wide
    condition:
        any of them
}

rule Shell_Commands
{
    meta:
        severity = "medium"
        description = "Запуск командной оболочки"
    strings:
        $a = "cmd.exe" nocase ascii wide
        $b = "powershell" nocase ascii wide
        $c = "/bin/sh" ascii
    condition:
        any of them
}

rule UPX_Packed
{
    meta:
        severity = "high"
        description = "Файл упакован UPX"
    strings:
        $a = "UPX0"
        $b = "UPX1"
    condition:
        all of them
}