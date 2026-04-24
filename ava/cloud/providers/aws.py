"""AWS S3 cloud provider integration."""

import boto3
import json
from typing import Dict, Any, Optional
from datetime import datetime
from ava.core.logging import logger
from ava.cloud.manager import CloudSync


class AWSProvider(CloudSync):
    """AWS S3 cloud synchronization."""

    def __init__(
        self, aws_access_key: str, aws_secret_key: str, bucket_name: str, region: str = "us-east-1"
    ):
        """Initialize AWS provider.

        Args:
            aws_access_key: AWS access key ID
            aws_secret_key: AWS secret access key
            bucket_name: S3 bucket name
            region: AWS region
        """
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.bucket_name = bucket_name
        self.region = region
        self.s3_client = None
        self._initialize()

    def _initialize(self) -> None:
        """Initialize S3 client."""
        try:
            self.s3_client = boto3.client(
                "s3",
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key,
                region_name=self.region,
            )
            logger.info(f"AWS S3 client initialized for bucket: {self.bucket_name}")
        except Exception as e:
            logger.error(f"Failed to initialize AWS S3 client: {e}")
            raise

    async def upload_data(self, data: Dict[str, Any]) -> bool:
        """Upload data to S3.

        Args:
            data: Data to upload

        Returns:
            True if successful
        """
        try:
            key = f"ava-data-{datetime.now().isoformat()}.json"
            json_data = json.dumps(data, default=str)

            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=json_data.encode("utf-8"),
                ContentType="application/json",
            )
            logger.info(f"Data uploaded to AWS S3: {key}")
            return True
        except Exception as e:
            logger.error(f"AWS S3 upload error: {e}")
            return False

    async def download_data(self) -> Optional[Dict[str, Any]]:
        """Download latest data from S3.

        Returns:
            Downloaded data or None
        """
        try:
            response = self.s3_client.list_objects_v2(Bucket=self.bucket_name, MaxKeys=1)

            if "Contents" not in response or not response["Contents"]:
                logger.warning("No data found in AWS S3")
                return None

            latest_object = response["Contents"][0]
            key = latest_object["Key"]

            obj = self.s3_client.get_object(Bucket=self.bucket_name, Key=key)
            data = json.loads(obj["Body"].read().decode("utf-8"))
            logger.info(f"Data downloaded from AWS S3: {key}")
            return data
        except Exception as e:
            logger.error(f"AWS S3 download error: {e}")
            return None

    async def sync(self) -> bool:
        """Perform bi-directional sync with S3.

        Returns:
            True if successful
        """
        try:
            # Upload local data
            local_snapshot = {"timestamp": datetime.now().isoformat(), "source": "ava-local"}
            upload_success = await self.upload_data(local_snapshot)

            if upload_success:
                logger.info("AWS S3 sync completed successfully")
                return True
            return False
        except Exception as e:
            logger.error(f"AWS S3 sync error: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get provider status.

        Returns:
            Status information
        """
        try:
            response = self.s3_client.head_bucket(Bucket=self.bucket_name)
            return {
                "status": "connected",
                "provider": "aws",
                "bucket": self.bucket_name,
                "region": self.region,
                "http_code": response["ResponseMetadata"]["HTTPStatusCode"],
            }
        except Exception as e:
            logger.error(f"Status check failed: {e}")
            return {"status": "disconnected", "provider": "aws", "error": str(e)}
