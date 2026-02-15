#!/usr/bin/env python3
"""
AVA BLOCKCHAIN SECURITY LAYER v96.0
Distributed Blockchain-based Threat Intelligence & Token Security

🔐 FEATURES:
- Immutable Threat Ledger
- Distributed Consensus for Threat Detection
- Token-based Access Control
- Cryptographic Security Proofs
- Decentralized Blacklist Sharing

Created by: Danny Nico Hildebrand
Date: 2026-02-15
"""

import hashlib
import json
import time
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import secrets


class ThreatSeverity(Enum):
    """Bedrohungsschweregrade"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class Block:
    """Ein Block in der Security Blockchain"""
    index: int
    timestamp: float
    threat_data: Dict
    previous_hash: str
    nonce: int = 0
    hash: str = ""
    
    def calculate_hash(self) -> str:
        """Berechnet Block-Hash (SHA-256)"""
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'threat_data': self.threat_data,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def mine_block(self, difficulty: int = 4):
        """Proof of Work Mining"""
        target = '0' * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()


@dataclass
class SecurityToken:
    """Security Access Token (Blockchain-basiert)"""
    token_id: str
    owner: str
    permissions: List[str]
    issued_at: float
    expires_at: float
    signature: str
    
    def is_valid(self) -> bool:
        """Prüft Token-Gültigkeit"""
        return time.time() < self.expires_at
    
    def has_permission(self, permission: str) -> bool:
        """Prüft ob Token Berechtigung hat"""
        return permission in self.permissions and self.is_valid()


class BlockchainSecurityLedger:
    """
    🔐 BLOCKCHAIN SECURITY LEDGER
    
    Immutable, distributed ledger für Security Events
    Jede Bedrohung wird in der Blockchain gespeichert
    """
    
    def __init__(self, difficulty: int = 4):
        self.chain: List[Block] = []
        self.difficulty = difficulty
        self.pending_threats: List[Dict] = []
        
        # Genesis Block
        self._create_genesis_block()
        
        print("🔐 BLOCKCHAIN SECURITY LEDGER INITIALIZED")
        print(f"   Mining Difficulty: {difficulty}")
        print(f"   Genesis Block: {self.chain[0].hash[:16]}...")
    
    def _create_genesis_block(self):
        """Erstellt Genesis Block"""
        genesis = Block(
            index=0,
            timestamp=time.time(),
            threat_data={
                'type': 'GENESIS',
                'message': 'AVA Security Blockchain v96.0 Genesis Block',
                'creator': 'Danny Nico Hildebrand',
                'date': '2026-02-15'
            },
            previous_hash='0' * 64
        )
        genesis.mine_block(self.difficulty)
        self.chain.append(genesis)
    
    def add_threat_to_ledger(self, threat_data: Dict) -> Block:
        """Fügt Bedrohung zur Blockchain hinzu"""
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            threat_data=threat_data,
            previous_hash=self.chain[-1].hash
        )
        
        print(f"⛏️  Mining block {new_block.index}...")
        start_time = time.time()
        new_block.mine_block(self.difficulty)
        mining_time = time.time() - start_time
        
        self.chain.append(new_block)
        
        print(f"✅ Block mined in {mining_time:.2f}s")
        print(f"   Hash: {new_block.hash[:32]}...")
        print(f"   Nonce: {new_block.nonce}")
        
        return new_block
    
    def verify_chain(self) -> bool:
        """Verifiziert Blockchain-Integrität"""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            # Hash-Validierung
            if current.hash != current.calculate_hash():
                print(f"❌ Block {i} hash is invalid!")
                return False
            
            # Previous-Hash Validierung
            if current.previous_hash != previous.hash:
                print(f"❌ Block {i} previous_hash is invalid!")
                return False
            
            # Proof of Work Validierung
            if not current.hash.startswith('0' * self.difficulty):
                print(f"❌ Block {i} PoW is invalid!")
                return False
        
        return True
    
    def get_threat_history(self, ip: Optional[str] = None) -> List[Dict]:
        """Holt Bedrohungs-Historie aus Blockchain"""
        threats = []
        for block in self.chain[1:]:  # Skip genesis
            if ip and block.threat_data.get('ip') != ip:
                continue
            threats.append({
                'block_index': block.index,
                'timestamp': block.timestamp,
                'data': block.threat_data,
                'hash': block.hash
            })
        return threats
    
    def export_chain(self, filename: str = "security_blockchain.json"):
        """Exportiert Blockchain"""
        chain_data = []
        for block in self.chain:
            chain_data.append({
                'index': block.index,
                'timestamp': block.timestamp,
                'threat_data': block.threat_data,
                'previous_hash': block.previous_hash,
                'nonce': block.nonce,
                'hash': block.hash
            })
        
        with open(filename, 'w') as f:
            json.dump({
                'difficulty': self.difficulty,
                'blocks': chain_data,
                'length': len(self.chain),
                'verified': self.verify_chain()
            }, f, indent=2)
        
        print(f"💾 Blockchain exported to {filename}")
        return filename


class TokenManager:
    """
    🎫 TOKEN MANAGER
    
    Verwaltet Security Access Tokens
    Blockchain-basierte Token-Ausgabe und Validierung
    """
    
    def __init__(self, blockchain: BlockchainSecurityLedger):
        self.blockchain = blockchain
        self.tokens: Dict[str, SecurityToken] = {}
        self.revoked_tokens: set = set()
        
        print("🎫 TOKEN MANAGER INITIALIZED")
    
    def issue_token(self, owner: str, permissions: List[str], 
                   duration: int = 3600) -> SecurityToken:
        """Gibt neuen Token aus"""
        token_id = secrets.token_urlsafe(32)
        
        issued_at = time.time()
        expires_at = issued_at + duration
        
        # Erstelle Signatur
        signature_data = f"{token_id}:{owner}:{issued_at}:{expires_at}"
        signature = hashlib.sha256(signature_data.encode()).hexdigest()
        
        token = SecurityToken(
            token_id=token_id,
            owner=owner,
            permissions=permissions,
            issued_at=issued_at,
            expires_at=expires_at,
            signature=signature
        )
        
        self.tokens[token_id] = token
        
        # Log in Blockchain
        self.blockchain.add_threat_to_ledger({
            'type': 'TOKEN_ISSUED',
            'token_id': token_id,
            'owner': owner,
            'permissions': permissions,
            'expires_at': expires_at
        })
        
        print(f"🎫 Token issued to {owner}")
        print(f"   Token ID: {token_id[:16]}...")
        print(f"   Permissions: {permissions}")
        print(f"   Expires: {datetime.fromtimestamp(expires_at)}")
        
        return token
    
    def verify_token(self, token_id: str, required_permission: str = None) -> bool:
        """Verifiziert Token"""
        if token_id in self.revoked_tokens:
            return False
        
        if token_id not in self.tokens:
            return False
        
        token = self.tokens[token_id]
        
        if not token.is_valid():
            return False
        
        if required_permission and not token.has_permission(required_permission):
            return False
        
        return True
    
    def revoke_token(self, token_id: str, reason: str = "Manual revocation"):
        """Widerruft Token"""
        self.revoked_tokens.add(token_id)
        
        # Log in Blockchain
        self.blockchain.add_threat_to_ledger({
            'type': 'TOKEN_REVOKED',
            'token_id': token_id,
            'reason': reason,
            'revoked_at': time.time()
        })
        
        print(f"🚫 Token revoked: {token_id[:16]}...")
        print(f"   Reason: {reason}")


class DistributedThreatIntelligence:
    """
    🌐 DISTRIBUTED THREAT INTELLIGENCE
    
    Teilt Bedrohungsinformationen über Blockchain
    Konsens-basierte Threat Detection
    """
    
    def __init__(self, blockchain: BlockchainSecurityLedger):
        self.blockchain = blockchain
        self.threat_votes: Dict[str, Dict] = {}
        self.consensus_threshold = 0.66  # 66% Konsens erforderlich
        
        print("🌐 DISTRIBUTED THREAT INTELLIGENCE INITIALIZED")
    
    def report_threat(self, reporter: str, threat_data: Dict) -> bool:
        """Meldet Bedrohung (erfordert Konsens)"""
        threat_id = hashlib.sha256(
            json.dumps(threat_data, sort_keys=True).encode()
        ).hexdigest()[:16]
        
        if threat_id not in self.threat_votes:
            self.threat_votes[threat_id] = {
                'data': threat_data,
                'reporters': [],
                'votes': 0,
                'total_nodes': 10  # Angenommen 10 Nodes im Netzwerk
            }
        
        # Stimme hinzufügen
        if reporter not in self.threat_votes[threat_id]['reporters']:
            self.threat_votes[threat_id]['reporters'].append(reporter)
            self.threat_votes[threat_id]['votes'] += 1
        
        # Konsens prüfen
        votes = self.threat_votes[threat_id]['votes']
        total = self.threat_votes[threat_id]['total_nodes']
        consensus = votes / total
        
        if consensus >= self.consensus_threshold:
            # Konsens erreicht - in Blockchain schreiben
            self.blockchain.add_threat_to_ledger({
                'type': 'THREAT_CONFIRMED',
                'threat_id': threat_id,
                'threat_data': threat_data,
                'votes': votes,
                'consensus': consensus,
                'reporters': self.threat_votes[threat_id]['reporters']
            })
            
            print(f"✅ THREAT CONFIRMED BY CONSENSUS ({consensus*100:.1f}%)")
            print(f"   Threat ID: {threat_id}")
            print(f"   Votes: {votes}/{total}")
            
            return True
        else:
            print(f"⏳ Waiting for consensus: {votes}/{total} ({consensus*100:.1f}%)")
            return False


# Global instances
_blockchain_ledger = None
_token_manager = None
_threat_intelligence = None


def get_blockchain_ledger() -> BlockchainSecurityLedger:
    """Singleton für Blockchain Ledger"""
    global _blockchain_ledger
    if _blockchain_ledger is None:
        _blockchain_ledger = BlockchainSecurityLedger(difficulty=4)
    return _blockchain_ledger


def get_token_manager() -> TokenManager:
    """Singleton für Token Manager"""
    global _token_manager
    if _token_manager is None:
        blockchain = get_blockchain_ledger()
        _token_manager = TokenManager(blockchain)
    return _token_manager


def get_threat_intelligence() -> DistributedThreatIntelligence:
    """Singleton für Threat Intelligence"""
    global _threat_intelligence
    if _threat_intelligence is None:
        blockchain = get_blockchain_ledger()
        _threat_intelligence = DistributedThreatIntelligence(blockchain)
    return _threat_intelligence


if __name__ == "__main__":
    print("\n" + "="*80)
    print("🔐 BLOCKCHAIN SECURITY LAYER v96.0 - DEMO")
    print("="*80 + "\n")
    
    # Initialize
    blockchain = get_blockchain_ledger()
    token_mgr = get_token_manager()
    threat_intel = get_threat_intelligence()
    
    print("\n" + "-"*80 + "\n")
    
    # Demo: Issue tokens
    print("DEMO: Token Issuance")
    admin_token = token_mgr.issue_token("admin", ["read", "write", "admin"], 3600)
    user_token = token_mgr.issue_token("user1", ["read"], 1800)
    
    print("\n" + "-"*80 + "\n")
    
    # Demo: Report threats
    print("DEMO: Distributed Threat Reporting")
    threat_data = {
        'ip': '192.168.1.100',
        'attack_type': 'sql_injection',
        'severity': 'HIGH'
    }
    
    for i in range(7):  # 7 nodes report
        threat_intel.report_threat(f"node_{i}", threat_data)
    
    print("\n" + "-"*80 + "\n")
    
    # Verify blockchain
    print("DEMO: Blockchain Verification")
    is_valid = blockchain.verify_chain()
    print(f"✅ Blockchain is {'VALID' if is_valid else 'INVALID'}")
    print(f"📊 Total Blocks: {len(blockchain.chain)}")
    
    # Export
    print("\n" + "-"*80 + "\n")
    blockchain.export_chain()
