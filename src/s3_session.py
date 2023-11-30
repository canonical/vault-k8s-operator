#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""S3 helper functions."""

import logging
from typing import IO, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

AWS_DEFAULT_REGION = "us-east-1"


class S3Session:
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
            self.session = boto3.session.Session(
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region,
            )
            self.session.resource("s3", endpoint_url=self.endpoint)
        except (ClientError, BotoCoreError, ValueError) as e:
            logger.error("Error creating AWS session: %s", e)
            raise e

    def create_s3_bucket(self, bucket_name: str) -> bool:
        """Create S3 bucket.

        If the bucket already exists, it will be skipped.

        Args:
            session: S3 session.
            region: S3 region.
            bucket_name: S3 bucket name.
            endpoint: S3 endpoint.

        Returns:
            bool: True if the bucket was created, False otherwise.
        """
        s3 = self.session.resource("s3", endpoint_url=self.endpoint)
        bucket = s3.Bucket(bucket_name)
        try:
            # Checking if bucket already exists
            bucket.meta.client.head_bucket(Bucket=bucket_name)
            logger.info("Bucket %s exists.", bucket_name)
            return True
        except ClientError:
            logger.info("Bucket %s doesn't exist, creating it.", bucket_name)
            pass
        except BotoCoreError as e:
            logger.error("Failed to check wether bucket exists. %s", e)
            return False
        except ValueError as e:
            logger.error("Error creating resource with provided endpoint: %s", e)
            return False
        try:
            # AWS client does't allow LocationConstraint to be set to us-east-1
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

    def upload_content_to_s3(
        self,
        content: IO[bytes],
        bucket_name: str,
        key: str,
    ) -> bool:
        """Uploads the provided contents to the provided S3 bucket.

        Args:
            session: S3 session.
            content: Byte contents to upload.
            bucket_name: S3 bucket name.
            endpoint: S3 endpoint.
            key: S3 object key.

        Returns:
            bool: True if the upload was successful, False otherwise.
        """
        try:
            s3 = self.session.resource("s3", endpoint_url=self.endpoint)
            bucket = s3.Bucket(bucket_name)
            bucket.put_object(Key=key, Body=content)
            return True
        except (BotoCoreError, ClientError) as e:
            logger.error("Error uploading content to bucket %s: %s", bucket_name, e)
            return False
