from hashlib import sha256

def updateHash(*args):
    hashingText = ""
    h = sha256()

    for arg in args:
        hashingText += str(arg)

    h.update(hashingText.encode('utf-8'))  
    return h.hexdigest()

class Integrity():
    data = None
    hash = None
    nonce = 0
    previous_hash = "0" * 64

    def __init__(self, data, number=0) -> None:
        self.data = data
        self.number = number

    def hash(self):
        return updateHash(self.previous_hash, 
                          self.number, 
                          self.data, 
                          self.nonce)

    def __str__(self) -> str:
        return str("BLOCK#: %s\nHASH: %s\nPrevious: %s\nData: %s\nNonce: %s" % (self.number, self.hash(), self.previous_hash, self.data, self.nonce))


class IntegrityChain():
    def __init__(self, chain=[]) -> None:
        self.difficulty = 4
        self.chain = chain
    
    def add(self, block) -> None:
        self.chain.append(block)

    def remove(self, block):
        self.chain.remove(block)
    
    def mine(self, block):
        try:
            block.previous_hash = self.chain[-1].hash()
        except IndexError:
            pass
        
        while True:
            if block.hash()[:self.difficulty] == "0" * self.difficulty:
                self.add(block)
                break
            else:
                block.nonce += 1
            
        
    def isValid(self):
        for i in range(1, len(self.chain)):
            print(self.chain[i].data)
            _previous  = self.chain[i].previous_hash
            _current = self.chain[i-1].hash()
            print(_previous, _current)
            if _previous != _current and _current[:self.difficulty] != "0" * self.difficulty:
                return False

        return True

def main():
    blockchain = IntegrityChain()
    database = ["First Project", "AI Projet", "ML Project", "END"]
    
    num = 0
    for data in database:
        num += 1
        blockchain.mine(Integrity(data, num))

    blockchain.chain[2].data = "New data" # Last block is not validated we need to add another last block to fix this
    
    print(blockchain.isValid())

if __name__ == "__main__":
    main()