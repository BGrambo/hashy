import regex as re
import pyperclip
from beautifultable import BeautifulTable

import hashLibrary
hashTypes = hashLibrary.hashTypes


class HashClassifier:
    def __init__(self, submittedHash):
        self.submittedHash = submittedHash.strip()
        self.classifications = self.classify()

        self.attackType = 0
        self.wordList = '/usr/share/wordlists/rockyou.txt'

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
                hashType = hashTypes[self.classifications[userSelect]]
                command = self.command(hashType, hashcatMode)
                pyperclip.copy(command)
                if command == pyperclip.paste():
                    print('Successfully copied to the clipboard...')
            else:
                print('Please select a row that exists...')
                self.clipBoard()

    def command(self, submittedType, submittedMode):
        if hashTypes[submittedType]['salt']:
            command = 'hashcat ' + '-m' + submittedMode + ' ' + '-a' + str(self.attackType) + ' ' + \
                      '$(echo ' + self.submittedHash + ':<salt or key>' \
                      + ' > value.hash && echo value.hash)' + ' ' + self.wordList
        else:
            command = 'hashcat ' + '-m' + submittedMode + ' ' + '-a' + str(self.attackType) + ' ' + \
                      '$(echo ' + self.submittedHash \
                      + ' > value.hash && echo value.hash)' + ' ' + self.wordList
        return command

    def table(self):
        table = BeautifulTable()
        table.columns.header = ['#', 'Hash Type', 'Hashcat Mode', 'Command']
        rowID = 0
        for classification in self.classifications:
            hashType = classification
            hashcatMode = str(hashTypes[classification]['hashcat'])
            if hashcatMode != 'None':
                command = self.command(hashType, hashcatMode)
            else:
                command = hashcatMode
            table.rows.append([rowID, hashType, hashcatMode, command])
            rowID += 1
        table.columns.width = [5, len(max(self.classifications, key=len)) + 2, 10, len(self.submittedHash) + 107]
        print(table)


def main():

    submittedHash = input('Hash: ')

    if submittedHash:
        results = HashClassifier(submittedHash)
        if results.classifications:
            results.table()
            results.clipBoard()
        else:
            print('No classifications were found...')
        if input('Again? (Y/N): ').lower() == 'y':
            main()
    else:
        print('Please enter a hash...')
        main()


main()
