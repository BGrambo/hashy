hashTypes = {
    'MD2': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': None,
        'salt': False
    },
    'MD5': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': 0,
        'salt': False
    },
    'MD5($pass.$salt)': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': 10,
        'salt': True
    },
    'MD5($salt.$pass)': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': 20,
        'salt': True
    },
    'MD5(utf16le($pass).$salt)': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': 30,
        'salt': True
    },
    'MD5($salt.utf16le($pass))': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': 40,
        'salt': True
    },
    'HMAC-MD5 (key = $pass)': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': 50,
        'salt': True
    },
    'HMAC-MD5 (key = $salt)': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': 60,
        'salt': True
    },
    'SHA-0': {
        'regex': r'^[a-f0-9]{40}$',
        'hashcat': None,
        'salt': False
    },
    'SHA-1': {
        'regex': r'^[a-f0-9]{40}$',
        'hashcat': 100,
        'salt': False
    },
    'SHA-1($pass.$salt)': {
        'regex': r'^[a-f0-9]{40}$',
        'hashcat': 110,
        'salt': True
    },
    'SHA-1($salt.$pass)': {
        'regex': r'^[a-f0-9]{40}$',
        'hashcat': 120,
        'salt': True
    },
    'SHA-1(utf16le($pass).$salt)': {
        'regex': r'^[a-f0-9]{40}$',
        'hashcat': 130,
        'salt': True
    },
    'SHA-1($salt.utf16le($pass))': {
        'regex': r'^[a-f0-9]{40}$',
        'hashcat': 140,
        'salt': True
    },
    'HMAC-SHA1 (key = $pass) ': {
        'regex': r'^[a-f0-9]{40}$',
        'hashcat': 150,
        'salt': True
    },
    'HMAC-SHA1 (key = $salt) ': {
        'regex': r'^[a-f0-9]{40}$',
        'hashcat': 160,
        'salt': True
    },
    'SHA-1(utf16le($pass))': {
        'regex': r'^[a-f0-9]{40}$',
        'hashcat': 170,
        'salt': False
    },
    'MySQL323': {
        'regex': r'^[a-f0-9]{16}$',
        'hashcat': 200,
        'salt': False
    },
    'MySQL4.1': {
        'regex': r'^[a-f0-9]{40}$',
        'hashcat': 300,
        'salt': False
    },
    'MySQL5': {
        'regex': r'^[a-f0-9]{40}$',
        'hashcat': 300,
        'salt': False
    },
    'phpass': {
        'regex': r'^\$(?:P|H)\$(?:[a-zA-Z0-9./]{16}){1,2}[a-zA-Z0-9./]{1,}$',
        'hashcat': 400,
        'salt': False
    },
    'Wordpress (MD5)': {
        'regex': r'^\$P\$(?:[a-zA-Z0-9./]{16}){1,2}[a-zA-Z0-9./]{1,}$',
        'hashcat': 400,
        'salt': False
    },
    'Joomla (MD5)': {
        'regex': r'^\$P\$(?:[a-zA-Z0-9./]{16}){1,2}[a-zA-Z0-9./]{1,}$',
        'hashcat': 400,
        'salt': False
    },
    'phpBB3 (MD5)': {
        'regex': r'^\$H\$(?:[a-zA-Z0-9./]{16}){1,2}[a-zA-Z0-9./]{1,}$',
        'hashcat': 400,
        'salt': False
    },
    'md5crypt': {
        'regex': r'^\$1\$(?:[a-zA-Z0-9./]{8})\$(?:[a-zA-Z0-9./]{22})$',
        'hashcat': 500,
        'salt': False
    },
    'MD5 (Unix)': {
        'regex': r'^\$1\$(?:[a-zA-Z0-9./]{8})\$(?:[a-zA-Z0-9./]{22})$',
        'hashcat': 500,
        'salt': False
    },
    'Cisco-IOS $1$ (MD5)': {
        'regex': r'^\$1\$(?:[a-zA-Z0-9./]{8})\$(?:[a-zA-Z0-9./]{22})$',
        'hashcat': 500,
        'salt': False
    },
    # JUNIPER IVE IS A WORK IN PROGRESS.
    'BLAKE2b-512': {
        'regex': r'^\$BLAKE2\$[a-fA-F0-9]{128}',
        'hashcat': 600,
        'salt': False
    },
    'BLAKE2b-512($pass.$salt)': {
        'regex': r'^\$BLAKE2\$[a-fA-F0-9]{128}',
        'hashcat': 610,
        'salt': True
    },
    'BLAKE2b-512($salt.$pass)': {
        'regex': r'^\$BLAKE2\$[a-fA-F0-9]{128}',
        'hashcat': 620,
        'salt': True
    },
    'MD4': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': 900,
        'salt': False
    },
    'NTLM hash (NT LAN Manager)': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': 1000,
        'salt': False
    },
    'SHA-224': {
        'regex': r'^[a-f0-9]{56}$',
        'hashcat': 11700,
        'salt': False
    },
    'SHA-256': {
        'regex': r'^[a-f0-9]{64}$',
        'hashcat': 1400,
        'salt': False
    },
    'SHA-384': {
        'regex': r'^[a-f0-9]{96}$',
        'hashcat': 10800,
        'salt': False
    },
    'SHA-512': {
        'regex': r'^[a-f0-9]{128}$',
        'hashcat': 1700,
        'salt': False
    },
    'SHA-512/224': {
        'regex': r'^[a-f0-9]{56}$',
        'hashcat': None,
        'salt': False
    },
    'SHA-512/256': {
        'regex': r'^[a-f0-9]{64}$',
        'hashcat': None,
        'salt': False
    },
    'RIPEMD-128': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': None,
        'salt': False
    },
    'RIPEMD-160': {
        'regex': r'^[a-f0-9]{40}$',
        'hashcat': 6000,
        'salt': False
    },
    'RIPEMD-256': {
        'regex': r'^[a-f0-9]{64}$',
        'hashcat': None,
        'salt': False
    },
    'RIPEMD-320': {
        'regex': r'^[a-f0-9]{80}$',
        'hashcat': None,
        'salt': False
    },
    'Whirlpool': {
        'regex': r'^[a-f0-9]{128}$',
        'hashcat': 6100,
        'salt': False
    },
    'Tiger': {
        'regex': r'^[a-f0-9]{48}$',
        'hashcat': None,
        'salt': False
    },
    'GOST R 34.11-94': {
        'regex': r'^[a-f0-9]{64}$',
        'hashcat': 6900,
        'salt': False
    },
    'GOST R 34.11-2012 (Streebog)': {
        'regex': r'^[a-f0-9]{64}$',
        'hashcat': 11700,
        'salt': False
    },
    'LM hash (LAN Manager)': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': 3000,
        'salt': False
    },
    'bcrypt': {
        'regex': r'^\$2[ayb]?\$[0-9]{2}\$[A-Za-z0-9./]{53}$',
        'hashcat': 3200,
        'salt': False
    },
    'scrypt': {
        'regex': None,
        'hashcat': 8900,
        'salt': False
    },
    'Argon2': {
        'regex': r'^\$argon2[id]?\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]{43}$',
        'hashcat': 9700,
        'salt': False
    }
}
