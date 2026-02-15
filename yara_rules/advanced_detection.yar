rule Windows_Trojan_Generic {
    meta:
        description = "Detecta patrones comunes de troyanos en Windows"
        author = "Security Agent"
    strings:
        $s1 = "RegSetValueEx" nocase
        $s2 = "CreateRemoteThread" nocase
        $s3 = "WriteProcessMemory" nocase
        $s4 = "ShellExecute" nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Ransomware_Indicators {
    meta:
        description = "Detecta funciones comunes usadas por ransomware"
    strings:
        $s1 = ".crypt" nocase
        $s2 = ".locked" nocase
        $s3 = "vssadmin.exe delete shadows" nocase
        $s4 = "DECRYPT_INSTRUCTIONS" nocase
    condition:
        any of them
}

rule Suspicious_Network_Activity {
    meta:
        description = "Detecta scripts que intentan conexiones reversas"
    strings:
        $s1 = "socket.socket" nocase
        $s2 = "connect((" nocase
        $s3 = "subprocess.PIPE" nocase
        $s4 = "/bin/bash" nocase
        $s5 = "cmd.exe /c" nocase
    condition:
        3 of them
}
