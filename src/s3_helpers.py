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


def create_s3_session(s3_parameters) -> Optional[boto3.session.Session]:
    """Creates S3 session.

    Args:
        s3_parameters: Dictionary of the S3 parameters.

    Returns:
        boto3.session.Session: S3 session.
    """
    try:
        session = boto3.session.Session(
            aws_access_key_id=s3_parameters["access-key"],
            aws_secret_access_key=s3_parameters["secret-key"],
            region_name=s3_parameters["region"],
        )
        session.resource("s3", endpoint_url=s3_parameters["endpoint"])
        return session
    except KeyError as e:
        logger.error("Missing required S3 parameter: %s", e)
        return None
    except ValueError as e:
        logger.error("Error creating resource: %s", e)
        return None


def create_s3_bucket(
    session: boto3.session.Session,
    bucket_name: str,
    endpoint: str,
    region: str,
) -> None:
    """Create S3 bucket.

    If the bucket already exists, it will be skipped.

    Args:
        session: S3 session.
        region: S3 region.
        bucket_name: S3 bucket name.
        endpoint: S3 endpoint.
    """
    s3 = session.resource("s3", endpoint_url=endpoint)
    bucket = s3.Bucket(bucket_name)
    try:
        # Checking if bucket already exists
        bucket.meta.client.head_bucket(Bucket=bucket_name)
        logger.info("Bucket %s exists.", bucket_name)
        return
    except ClientError:
        logger.info("Bucket %s doesn't exist, creating it.", bucket_name)
        pass
    except BotoCoreError as e:
        logger.error("Failed to check wether bucket exists. %s", e)
        raise e
    except ValueError as e:
        logger.error("Error creating resource with provided endpoint: %s", e)
        raise e
    try:
        # AWS client does't allow LocationConstraint to be set to us-east-1
        # If that's the regions used, we don't set LocationConstraint
        # us-east-1 is the default region for AWS
        if region == AWS_DEFAULT_REGION:
            bucket = bucket.create()
        else:
            bucket.create(CreateBucketConfiguration={"LocationConstraint": region})
        bucket.wait_until_exists()
    except (BotoCoreError, ClientError) as error:
        logger.error("Couldn't create bucket named '%s' in region=%s.", bucket_name, region)
        raise error


def upload_content_to_s3(
    session: boto3.session.Session,
    content: IO[bytes],
    bucket_name: str,
    endpoint: str,
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
        s3 = session.resource("s3", endpoint_url=endpoint)
        bucket = s3.Bucket(bucket_name)
        bucket.put_object(Key=key, Body=content)
        return True
    except (BotoCoreError, ClientError) as e:
        logger.error("Error uploading content to bucket %s: %s", bucket_name, e)
        return False
