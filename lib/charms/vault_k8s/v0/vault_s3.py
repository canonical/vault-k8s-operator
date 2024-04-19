
#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""S3 helper functions for Vault charms.

## Usage
Add the following dependencies to the charm's requirements.txt file:

    ```
    boto3
    boto3-stubs[s3]
    ```

"""


import logging
from typing import IO, List, Optional, cast

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from botocore.response import StreamingBody
from mypy_boto3_s3.literals import BucketLocationConstraintType
from mypy_boto3_s3.service_resource import Bucket
from mypy_boto3_s3.type_defs import CreateBucketConfigurationTypeDef

# The unique Charmhub library identifier, never change it
LIBID = "6a14cfe8d3134db4a6c47c4cf7b7d5d6"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


logger = logging.getLogger(__name__)

AWS_DEFAULT_REGION = "us-east-1"


class S3Error(Exception):
    """Base class for S3 errors."""

    pass

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
        self.endpoint = endpoint
        self.region = region
        try:
            self.session = boto3.session.Session(
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=region,
            )
            custom_config = Config(
                retries={
                    "max_attempts": 1,
                },
            )
            self.s3 = self.session.resource("s3", endpoint_url=self.endpoint, config=custom_config)
        except (ClientError, BotoCoreError, ValueError) as e:
            raise S3Error(f"Error creating session: {e}")

    def create_bucket(self, bucket_name: str) -> bool:
        """Create S3 bucket.

        If the bucket already exists, it will be skipped.

        Args:
            bucket_name: S3 bucket name to be created.

        Returns:
            bool: True if the bucket was created, False otherwise.
        """
        bucket = self.s3.Bucket(name=bucket_name)
        if self._bucket_exists(bucket=bucket):
            logger.info("Bucket %s already exists.", bucket_name)
            return True
        return self._create_bucket(bucket=bucket)


    def _bucket_exists(self, bucket: Bucket) -> bool:
        """Return whether the bucket exists."""
        try:
            bucket.meta.client.head_bucket(Bucket=bucket.name)
        except (ClientError, BotoCoreError):
            return False
        return True

    def _create_bucket(self, bucket: Bucket) -> bool:
        """Create the S3 bucket."""
        try:
            if self.region == AWS_DEFAULT_REGION or self.region is None:
                bucket.create()
            else:
                region_literal = cast(BucketLocationConstraintType, self.region)
                create_bucket_configuration: CreateBucketConfigurationTypeDef = {
                    "LocationConstraint": region_literal
                }
                bucket.create(CreateBucketConfiguration=create_bucket_configuration)

            bucket.wait_until_exists()
            return True
        except (BotoCoreError, ClientError) as error:
            logger.error(
                "Couldn't create bucket named '%s' in region=%s. %s",
                bucket.name,
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
        """
        try:
            bucket = self.s3.Bucket(name=bucket_name)
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
        """
        keys = []
        try:
            bucket = self.s3.Bucket(bucket_name)
            for obj in bucket.objects.filter(Prefix=prefix):
                keys.append(obj.key)
            return keys
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucket":  # type: ignore[reportTypedDictNotRequiredAccess]
                logger.error("Bucket %s does not exist.", bucket_name)
                return []
            else:
                logger.error("Error getting objects list from bucket %s: %s", bucket_name, e)
                raise S3Error(f"Error getting objects list from bucket {bucket_name}: {e}")
        except BotoCoreError as e:
            logger.error("Error getting objects list from bucket %s: %s", bucket_name, e)
            raise S3Error(f"Error getting objects list from bucket {bucket_name}: {e}")

    def get_content(self, bucket_name: str, object_key: str) -> Optional[StreamingBody]:
        """Get object content from S3 bucket by key.

        Args:
            bucket_name: S3 bucket name.
            object_key: S3 object key.

        Returns:
            Optional[StreamingBody]: File like object with the content of the S3 object.
        """
        bucket = self.s3.Bucket(bucket_name)
        try:
            obj = bucket.Object(object_key).get()
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":  # type: ignore[reportTypedDictNotRequiredAccess]
                logger.error("Object %s does not exist.", object_key)
                return None
            elif e.response["Error"]["Code"] == "NoSuchBucket":  # type: ignore[reportTypedDictNotRequiredAccess]
                logger.error("Bucket %s does not exist.", bucket_name)
                return None
            else:
                logger.error(
                    "Error getting object %s from bucket %s: %s", object_key, bucket_name, e
                )
                raise S3Error(f"Error getting object {object_key} from bucket {bucket_name}: {e}")
        except BotoCoreError as e:
            logger.error("Error getting object %s from bucket %s: %s", object_key, bucket_name, e)
            raise S3Error(f"Error getting object {object_key} from bucket {bucket_name}: {e}")

        return obj["Body"]
