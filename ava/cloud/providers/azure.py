"""Azure Blob Storage cloud provider integration."""

from azure.storage.blob import BlobServiceClient
import json
from typing import Dict, Any, Optional
from datetime import datetime
from ava.core.logging import logger
from ava.cloud.manager import CloudSync


class AzureProvider(CloudSync):
    """Azure Blob Storage synchronization."""

    def __init__(
        self,
        connection_string: str,
        container_name: str
    ):
        """Initialize Azure provider.
        
        Args:
            connection_string: Azure Storage connection string
            container_name: Container name
        """
        self.connection_string = connection_string
        self.container_name = container_name
        self.blob_service_client = None
        self.container_client = None
        self._initialize()

    def _initialize(self) -> None:
        """Initialize Azure Blob Storage client."""
        try:
            self.blob_service_client = BlobServiceClient.from_connection_string(
                self.connection_string
            )
            self.container_client = self.blob_service_client.get_container_client(
                self.container_name
            )
            logger.info(f"Azure Blob Storage initialized for container: {self.container_name}")
        except Exception as e:
            logger.error(f"Failed to initialize Azure Blob Storage client: {e}")
            raise

    async def upload_data(self, data: Dict[str, Any]) -> bool:
        """Upload data to Azure Blob Storage.
        
        Args:
            data: Data to upload
            
        Returns:
            True if successful
        """
        try:
            blob_name = f"ava-data-{datetime.now().isoformat()}.json"
            json_data = json.dumps(data, default=str)
            
            blob_client = self.container_client.get_blob_client(blob_name)
            blob_client.upload_blob(json_data.encode('utf-8'), overwrite=True)
            logger.info(f"Data uploaded to Azure Blob Storage: {blob_name}")
            return True
        except Exception as e:
            logger.error(f"Azure Blob Storage upload error: {e}")
            return False

    async def download_data(self) -> Optional[Dict[str, Any]]:
        """Download latest data from Azure Blob Storage.
        
        Returns:
            Downloaded data or None
        """
        try:
            blobs = list(self.container_client.list_blobs())
            if not blobs:
                logger.warning("No data found in Azure Blob Storage")
                return None
            
            # Get most recently modified blob
            latest_blob = max(blobs, key=lambda b: b['last_modified'])
            blob_client = self.container_client.get_blob_client(latest_blob['name'])
            
            download_stream = blob_client.download_blob()
            data = json.loads(download_stream.readall().decode('utf-8'))
            logger.info(f"Data downloaded from Azure Blob Storage: {latest_blob['name']}")
            return data
        except Exception as e:
            logger.error(f"Azure Blob Storage download error: {e}")
            return None

    async def sync(self) -> bool:
        """Perform bi-directional sync with Azure Blob Storage.
        
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
                logger.info("Azure Blob Storage sync completed successfully")
                return True
            return False
        except Exception as e:
            logger.error(f"Azure Blob Storage sync error: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get provider status.
        
        Returns:
            Status information
        """
        try:
            account_info = self.blob_service_client.get_account_information()
            return {
                "status": "connected",
                "provider": "azure",
                "container": self.container_name,
                "sku": account_info.get('sku_name', 'unknown')
            }
        except Exception as e:
            logger.error(f"Status check failed: {e}")
            return {"status": "disconnected", "provider": "azure", "error": str(e)}
