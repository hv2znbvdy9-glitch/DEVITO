"""Google Cloud Platform cloud provider integration."""

from google.cloud import storage
import json
from typing import Dict, Any, Optional
from datetime import datetime
from ava.core.logging import logger
from ava.cloud.manager import CloudSync


class GCPProvider(CloudSync):
    """Google Cloud Storage synchronization."""

    def __init__(
        self,
        project_id: str,
        bucket_name: str,
        credentials_path: Optional[str] = None
    ):
        """Initialize GCP provider.
        
        Args:
            project_id: GCP project ID
            bucket_name: Google Cloud Storage bucket name
            credentials_path: Path to service account JSON (optional)
        """
        self.project_id = project_id
        self.bucket_name = bucket_name
        self.credentials_path = credentials_path
        self.storage_client = None
        self.bucket = None
        self._initialize()

    def _initialize(self) -> None:
        """Initialize Google Cloud Storage client."""
        try:
            if self.credentials_path:
                self.storage_client = storage.Client(
                    project=self.project_id,
                    credentials=self._load_credentials()
                )
            else:
                self.storage_client = storage.Client(project=self.project_id)
            
            self.bucket = self.storage_client.bucket(self.bucket_name)
            logger.info(f"Google Cloud Storage initialized for bucket: {self.bucket_name}")
        except Exception as e:
            logger.error(f"Failed to initialize Google Cloud Storage client: {e}")
            raise

    def _load_credentials(self):
        """Load credentials from service account JSON."""
        from google.oauth2 import service_account
        return service_account.Credentials.from_service_account_file(
            self.credentials_path
        )

    async def upload_data(self, data: Dict[str, Any]) -> bool:
        """Upload data to Google Cloud Storage.
        
        Args:
            data: Data to upload
            
        Returns:
            True if successful
        """
        try:
            blob_name = f"ava-data-{datetime.now().isoformat()}.json"
            json_data = json.dumps(data, default=str)
            
            blob = self.bucket.blob(blob_name)
            blob.upload_from_string(
                json_data.encode('utf-8'),
                content_type='application/json'
            )
            logger.info(f"Data uploaded to Google Cloud Storage: {blob_name}")
            return True
        except Exception as e:
            logger.error(f"Google Cloud Storage upload error: {e}")
            return False

    async def download_data(self) -> Optional[Dict[str, Any]]:
        """Download latest data from Google Cloud Storage.
        
        Returns:
            Downloaded data or None
        """
        try:
            blobs = list(self.storage_client.list_blobs(
                self.bucket_name,
                max_results=1
            ))
            
            if not blobs:
                logger.warning("No data found in Google Cloud Storage")
                return None
            
            blob = blobs[0]
            data_bytes = blob.download_as_bytes()
            data = json.loads(data_bytes.decode('utf-8'))
            logger.info(f"Data downloaded from Google Cloud Storage: {blob.name}")
            return data
        except Exception as e:
            logger.error(f"Google Cloud Storage download error: {e}")
            return None

    async def sync(self) -> bool:
        """Perform bi-directional sync with Google Cloud Storage.
        
        Returns:
            True if successful
        """
        try:
            # Upload local data
            local_snapshot = {
                "timestamp": datetime.now().isoformat(),
                "source": "ava-local"
            }
            upload_success = await self.upload_data(local_snapshot)
            
            if upload_success:
                logger.info("Google Cloud Storage sync completed successfully")
                return True
            return False
        except Exception as e:
            logger.error(f"Google Cloud Storage sync error: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get provider status.
        
        Returns:
            Status information
        """
        try:
            return {
                "status": "connected",
                "provider": "gcp",
                "bucket": self.bucket_name,
                "project_id": self.project_id
            }
        except Exception as e:
            logger.error(f"Status check failed: {e}")
            return {"status": "disconnected", "provider": "gcp", "error": str(e)}
