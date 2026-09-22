"""Communication protocol definitions for media capture agents."""

import json
import hashlib
from typing import Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class AgentProtocol:
    """Defines the communication protocol between agent and main server."""
    
    def __init__(self, config: Dict[str, Any]):
        self.version = config.get("version", "1.0")
        self.max_message_size = config.get("max_message_size", 1024 * 1024)  # 1MB default
        self.timeout = config.get("timeout", 30)  # 30 seconds default
        
    def encode_message(self, data: Dict[str, Any], message_type: str, 
                      timestamp: Optional[datetime] = None) -> bytes:
        """Encode message data into bytes."""
        if timestamp is None:
            timestamp = datetime.utcnow()
            
        message = {
            "type": message_type,
            "timestamp": timestamp.isoformat(),
            "data": data,
            "version": self.version
        }
        
        # Add signature for integrity
        message_str = json.dumps(message, sort_keys=True)
        signature = hashlib.sha256(message_str.encode()).hexdigest()
        message["signature"] = signature
        
        return json.dumps(message).encode()
        
    def decode_message(self, message_bytes: bytes) -> Dict[str, Any]:
        """Decode bytes into message data."""
        try:
            message = json.loads(message_bytes.decode())
            
            # Verify signature
            if not self._verify_signature(message):
                raise ValueError("Message signature verification failed")
                
            return message
        except Exception as e:
            logger.error(f"Failed to decode message: {e}")
            raise
            
    def _verify_signature(self, message: Dict[str, Any]) -> bool:
        """Verify message integrity using signature."""
        if "signature" not in message:
            return False
            
        # Remove signature for verification
        message_copy = message.copy()
        signature = message_copy.pop("signature")
        
        # Recalculate signature
        message_str = json.dumps(message_copy, sort_keys=True)
        recalculated_signature = hashlib.sha256(message_str.encode()).hexdigest()
        
        return signature == recalculated_signature
        
    def validate_message(self, message: Dict[str, Any]) -> bool:
        """Validate message structure."""
        required_fields = ["type", "timestamp", "data"]
        return all(field in message for field in required_fields)
