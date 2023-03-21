import regex as re
import pyperclip
from beautifultable import BeautifulTable

hashTypes = {
    'MD2': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': None
    },
    'MD4': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': 900
    },
    'MD5': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': 0
    },
    'SHA-0': {
        'regex': r'^[a-f0-9]{40}$',
        'hashcat': None
    },
    'SHA-1': {
        'regex': r'^[a-f0-9]{40}$',
        'hashcat': 100
    },
    'SHA-224': {
        'regex': r'^[a-f0-9]{56}$',
        'hashcat': 11700
    },
    'SHA-256': {
        'regex': r'^[a-f0-9]{64}$',
        'hashcat': 1400
    },
    'SHA-384': {
        'regex': r'^[a-f0-9]{96}$',
        'hashcat': 10800
    },
    'SHA-512': {
        'regex': r'^[a-f0-9]{128}$',
        'hashcat': 1700
    },
    'SHA-512/224': {
        'regex': r'^[a-f0-9]{56}$',
        'hashcat': None
    },
    'SHA-512/256': {
        'regex': r'^[a-f0-9]{64}$',
        'hashcat': None
    },
    'RIPEMD-128': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': None
    },
    'RIPEMD-160': {
        'regex': r'^[a-f0-9]{40}$',
        'hashcat': 6000
    },
    'RIPEMD-256': {
        'regex': r'^[a-f0-9]{64}$',
        'hashcat': None
    },
    'RIPEMD-320': {
        'regex': r'^[a-f0-9]{80}$',
        'hashcat': None
    },
    'Whirlpool': {
        'regex': r'^[a-f0-9]{128}$',
        'hashcat': 6100
    },
    'Tiger': {
        'regex': r'^[a-f0-9]{48}$',
        'hashcat': None
    },
    'GOST R 34.11-94': {
        'regex': r'^[a-f0-9]{64}$',
        'hashcat': 6900
    },
    'GOST R 34.11-2012 (Streebog)': {
        'regex': r'^[a-f0-9]{64}$',
        'hashcat': 11700
    },
    'LM hash (LAN Manager)': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': 3000
    },
    'NTLM hash (NT LAN Manager)': {
        'regex': r'^[a-f0-9]{32}$',
        'hashcat': 1000
    },
    'bcrypt': {
        'regex': r'^\$2[ayb]?\$[0-9]{2}\$[A-Za-z0-9./]{53}$',
        'hashcat': 3200
    },
    'scrypt': {
        'regex': None,
        'hashcat': 8900
    },
    'Argon2': {
        'regex': r'^\$argon2[id]?\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]{43}$',
        'hashcat': 9700
    },
}


class HashClassifier():
    def __init__(self, submittedHash):
        self.submittedHash = submittedHash
        self.classifications = self.classify()

    def classify(self):
        classifications = []

        for hashType in hashTypes.keys():
            currentHash = hashTypes[hashType]
            if currentHash['regex'] is not None:
                regexResult = bool(re.search(currentHash['regex'], self.submittedHash, re.IGNORECASE))
                if regexResult:
                    classifications.append(hashType)

        return classifications

    def saltFinder(submittedHash):
        if ':' not in submittedHash:
            return False
        else:
            characterCount = len(re.findall(':', submittedHash))
            if characterCount == 1:
                # We will need to find the position of the colon, and segregate the before/after and run against classifier.
                print('investigating...')

    def clipBoard(self):
        userInput = input('Would you like to copy a command to the clipboard (Yy/Nn): ')
        if userInput.lower() == 'y':
            userSelect = int(input('Which row would you like to send to the clipboard: '))
            if userSelect <= len(self.classifications):
                hashcatMode = str(hashTypes[self.classifications[userSelect]]['hashcat'])
                command = self.command(hashcatMode)
                pyperclip.copy(command)
                if command == pyperclip.paste():
                    print('Successfully copied to the clipboard...')
            else:
                print('Please select a row that exists...')
                self.clipBoard()

    def command(self, submittedMode):
        command = 'hashcat ' + '-m' + submittedMode + ' ' + '-a0' + ' ' + '$(echo ' + self.submittedHash \
                  + ' > value.hash && echo value.hash)' + ' ' + '/usr/share/wordlists/rockyou.txt'
        return command

    def table(self):
        table = BeautifulTable()
        table.columns.header = ['#', 'Hash Type', 'Hashcat Mode', 'Command']
        rowID = 0
        for classification in self.classifications:
            hashType = classification
            hashcatMode = str(hashTypes[classification]['hashcat'])
            if hashcatMode != 'None':
                command = self.command(hashcatMode)
            else:
                command = hashcatMode
            table.rows.append([rowID, hashType, hashcatMode, command])
            rowID += 1
        print(table)


def main():

    submittedHash = input('Hash: ')

    if submittedHash:
        results = HashClassifier(submittedHash)
        results.table()
        results.clipBoard()
        if input('Again? (Y/N): ').lower() == 'y':
            main()
    else:
        print('Please enter a hash...')
        main()


main()
