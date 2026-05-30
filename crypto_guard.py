import time
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from typing import Dict, Tuple, Optional

class JITIdentityEngine:
    def __init__(self):
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._public_key = self._private_key.public_key()
        self.private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()
        )
        self.public_pem = self._public_key.with_output_type(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) if hasattr(self._public_key, 'with_output_type') else self._public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.token_ttl = 30

    def issue_workload_token(self, workload_id: str, service_type: str) -> str:
        now = int(time.time())
        payload = {"iss": "shadowbound.internal", "sub": workload_id, "aud": "trust.boundary", "iat": now, "exp": now + self.token_ttl, "type": service_type}
        return jwt.encode(payload, self.private_pem, algorithm="RS256")

    def verify_workload_token(self, token: str) -> Optional[Dict]:
        try:
            return jwt.decode(token, self.public_pem, audience="trust.boundary", algorithms=["RS256"])
        except:
            return None

class BehavioralGuard:
    def __init__(self):
        self.telemetry_matrix: Dict[str, Tuple[int, float]] = {}
        self.MAX_REQUESTS = 100
        self.WINDOW = 10.0
        self.isolated_workloads = set()

    def inspect_traffic(self, workload_id: str) -> bool:
        if workload_id in self.isolated_workloads: return False
        now = time.time()
        if workload_id not in self.telemetry_matrix:
            self.telemetry_matrix[workload_id] = (1, now)
            return True
        count, start_time = self.telemetry_matrix[workload_id]
        if now - start_time < self.WINDOW:
            if count >= self.MAX_REQUESTS:
                self.isolated_workloads.add(workload_id)
                return False
            self.telemetry_matrix[workload_id] = (count + 1, start_time)
        else:
            self.telemetry_matrix[workload_id] = (1, now)
        return True

jit_engine = JITIdentityEngine()
behavioral_guard = BehavioralGuard()
          
