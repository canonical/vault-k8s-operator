#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""S3 helper functions."""

import logging
from typing import IO, List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from botocore.response import StreamingBody

logger = logging.getLogger(__name__)

AWS_DEFAULT_REGION = "us-east-1"


class S3:
    """A class representing an S3 session allowing S3 operations."""

    def __init__(
        self,
        access_key: str,
        secret_key: str,
        endpoint: str,
        region: Optional[str] = AWS_DEFAULT_REGION,
    ):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.endpoint = endpoint
        try:
            self.session = boto3.session.Session(  # type: ignore[reportAttributeAccessIssue]
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region,
            )
            custom_config = Config(
                retries={
                    "max_attempts": 1,
                },
            )
            self.s3 = self.session.resource("s3", endpoint_url=self.endpoint, config=custom_config)
        except (ClientError, BotoCoreError, ValueError) as e:
            logger.error("Error creating session: %s", e)
            raise e

    def create_bucket(self, bucket_name: str) -> bool:
        """Create S3 bucket.

        If the bucket already exists, it will be skipped.

        Args:
            bucket_name: S3 bucket name to be created.

        Returns:
            bool: True if the bucket was created, False otherwise.

        Raises:
            ConnectTimeoutError
        """
        bucket = self.s3.Bucket(bucket_name)
        try:
            # Checking if bucket already exists
            bucket.meta.client.head_bucket(Bucket=bucket_name)
            logger.info("Bucket %s exists.", bucket_name)
            return True
        except ClientError:
            logger.info("Bucket %s doesn't exist, creating it.", bucket_name)
            pass
        except BotoCoreError as e:
            logger.error("Failed to check whether bucket exists. %s", e)
            return False

        try:
            # AWS client doesn't allow LocationConstraint to be set to us-east-1
            # If that's the regions used, we don't set LocationConstraint
            # us-east-1 is the default region for AWS
            if self.region == AWS_DEFAULT_REGION:
                bucket = bucket.create()
            else:
                bucket.create(CreateBucketConfiguration={"LocationConstraint": self.region})
            bucket.wait_until_exists()
            return True
        except (BotoCoreError, ClientError) as error:
            logger.error(
                "Couldn't create bucket named '%s' in region=%s. %s",
                bucket_name,
                self.region,
                error,
            )
            return False

    def upload_content(
        self,
        content: IO[bytes],
        bucket_name: str,
        key: str,
    ) -> bool:
        """Upload the provided contents to the provided S3 bucket.

        Args:
            content: File like object containing the content to upload.
            bucket_name: S3 bucket name.
            key: S3 object key.

        Returns:
            bool: True if the upload was successful, False otherwise.

        Raises:
            ConnectTimeoutError
        """
        try:
            bucket = self.s3.Bucket(bucket_name)
            bucket.upload_fileobj(Key=key, Fileobj=content)
            return True
        except (BotoCoreError, ClientError) as e:
            logger.error("Error uploading content to bucket %s: %s", bucket_name, e)
            return False

    def get_object_key_list(self, bucket_name: str, prefix: str) -> List[str]:
        """Get list of object key in an S3 bucket.

        Args:
            bucket_name: S3 bucket name.
            prefix: Prefix to filter object keys by.

        Returns:
            List[str]: List of object keys.

        Raises:
            ClientError
            BotoCoreError
            ConnectTimeoutError
        """
        keys = []
        try:
            bucket = self.s3.Bucket(bucket_name)
            for obj in bucket.objects.filter(Prefix=prefix):
                keys.append(obj.key)
            return keys
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucket":
                logger.error("Bucket %s does not exist.", bucket_name)
                return []
            else:
                logger.error("Error getting objects list from bucket %s: %s", bucket_name, e)
                raise e
        except BotoCoreError as e:
            logger.error("Error getting objects list from bucket %s: %s", bucket_name, e)
            raise e

    def get_content(self, bucket_name: str, object_key: str) -> Optional[StreamingBody]:
        """Get object content from S3 bucket by key.

        Args:
            bucket_name: S3 bucket name.
            object_key: S3 object key.

        Returns:
            Optional[StreamingBody]: File like object with the content of the S3 object.

        Raises:
            ClientError
            BotoCoreError
            ConnectTimeoutError
        """
        bucket = self.s3.Bucket(bucket_name)
        try:
            obj = bucket.Object(object_key).get()
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                logger.error("Object %s does not exist.", object_key)
                return None
            elif e.response["Error"]["Code"] == "NoSuchBucket":
                logger.error("Bucket %s does not exist.", bucket_name)
                return None
            else:
                logger.error(
                    "Error getting object %s from bucket %s: %s", object_key, bucket_name, e
                )
                raise e
        except BotoCoreError as e:
            logger.error("Error getting object %s from bucket %s: %s", object_key, bucket_name, e)
            raise e

        return obj["Body"]
