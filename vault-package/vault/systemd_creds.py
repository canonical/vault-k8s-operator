import subprocess
from pathlib import Path

from ops.charm import logger

SYSTEMD_ENCRYPTED_CREDENTIAL_STORE = Path("/etc/credstore.encrypted/")

class SystemdCreds:

    def __init__(self, encrypted_credential_store_path: Path = SYSTEMD_ENCRYPTED_CREDENTIAL_STORE):
        self.encrypted_credential_store_path = encrypted_credential_store_path


    def decrypt( self, name: str) -> str:
        """Decrypt a token from the systemd encrypted credential store."""
        path = self.encrypted_credential_store_path / name
        decrypted_token = subprocess.run(
            ["systemd-creds", "decrypt", f"--name={name}", path],
            capture_output=True,
            text=True,
        )
        logger.info("Decrypted token:", decrypted_token.stdout.strip())
        if decrypted_token.returncode != 0:
            logger.error("Failed to decrypt token. stderr: %s", decrypted_token.stderr.strip())
            raise RuntimeError("Token decryption failed")
        return decrypted_token.stdout.strip()

    def encrypt( self, name: str, value: str) -> None:
        path = self.encrypted_credential_store_path / name
        encrypted_token = subprocess.run(
            [
                "systemd-creds",
                "encrypt",
                f"--name={name}",
                "-",  # Take input from stdin
                path,  # Output location
            ],
            input=value,
            capture_output=True,
            text=True,
        )
        if encrypted_token.returncode != 0:
            logger.error("Failed to encrypt token. stderr: %s", encrypted_token.stderr.strip())
            raise RuntimeError("Token encryption failed")
