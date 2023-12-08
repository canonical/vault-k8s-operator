#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import io
import unittest
from unittest.mock import Mock, patch

import boto3
from botocore.exceptions import ClientError

from s3_session import S3


class TestS3(unittest.TestCase):
    def test_given_valid_s3_parameters_when_create_s3_session_then_session_is_created(self):
        valid_s3_parameters = {
            "access-key": "ACCESS-KEY",
            "secret-key": "SECRET-KEY",
            "region": "REGION",
            "endpoint": "http://ENDPOINT",
        }
        s3 = S3(
            access_key=valid_s3_parameters["access-key"],
            secret_key=valid_s3_parameters["secret-key"],
            region=valid_s3_parameters["region"],
            endpoint=valid_s3_parameters["endpoint"],
        )
        self.assertIsInstance(s3.session, boto3.session.Session)

    def test_given_invalid_endpoint_when_create_s3_session_then_session_not_created(self):
        invalid_s3_parameters = {
            "access-key": "ACCESS-KEY",
            "secret-key": "SECRET-KEY",
            "region": "REGION",
            "endpoint": "invalid endpoint",
        }
        with self.assertRaises(ValueError):
            S3(
                access_key=invalid_s3_parameters["access-key"],
                secret_key=invalid_s3_parameters["secret-key"],
                region=invalid_s3_parameters["region"],
                endpoint=invalid_s3_parameters["endpoint"],
            )

    @patch("boto3.session.Session")
    def test_given_bucket_already_exists_when_create_bucket_then_bucket_not_created(
        self,
        patch_session,
    ):
        mock_resource = Mock()
        mock_bucket = Mock()

        patch_session.return_value.resource.return_value = mock_resource
        mock_resource.Bucket.return_value = mock_bucket

        valid_s3_parameters = {
            "access-key": "ACCESS-KEY",
            "secret-key": "SECRET-KEY",
            "region": "REGION",
            "endpoint": "http://ENDPOINT",
        }
        s3 = S3(
            access_key=valid_s3_parameters["access-key"],
            secret_key=valid_s3_parameters["secret-key"],
            region=valid_s3_parameters["region"],
            endpoint=valid_s3_parameters["endpoint"],
        )

        s3.create_bucket(bucket_name="whatever-bucket")

        patch_session.resource.Bucket.create.assert_not_called()

    @patch("boto3.session.Session")
    def test_given_bucket_not_created_when_create_bucket_then_bucket_created(
        self,
        patch_session,
    ):
        mock_resource = Mock()
        mock_bucket = Mock()
        mock_client = Mock()

        patch_session.return_value.resource.return_value = mock_resource
        mock_resource.Bucket.return_value = mock_bucket
        mock_bucket.meta.client = mock_client

        valid_s3_parameters = {
            "access-key": "ACCESS-KEY",
            "secret-key": "SECRET-KEY",
            "region": "REGION",
            "endpoint": "http://ENDPOINT",
        }

        mock_client.head_bucket.side_effect = ClientError(
            operation_name="NoSuchBucket",
            error_response={"Error": {"Message": "Random bucket exists error message"}},
        )

        s3 = S3(
            access_key=valid_s3_parameters["access-key"],
            secret_key=valid_s3_parameters["secret-key"],
            region=valid_s3_parameters["region"],
            endpoint=valid_s3_parameters["endpoint"],
        )

        s3.create_bucket(bucket_name="whatever-bucket")

        mock_bucket.create.assert_called_once()

    @patch("boto3.session.Session")
    def test_given_bucket_does_not_exist_when_upload_content_then_content_not_uploaded(
        self,
        patch_session,
    ):
        mock_resource = Mock()
        mock_bucket = Mock()
        mock_client = Mock()

        patch_session.return_value.resource.return_value = mock_resource
        mock_resource.Bucket.return_value = mock_bucket
        mock_bucket.meta.client = mock_client

        valid_s3_parameters = {
            "access-key": "ACCESS-KEY",
            "secret-key": "SECRET-KEY",
            "region": "REGION",
            "endpoint": "http://ENDPOINT",
        }
        s3 = S3(
            access_key=valid_s3_parameters["access-key"],
            secret_key=valid_s3_parameters["secret-key"],
            region=valid_s3_parameters["region"],
            endpoint=valid_s3_parameters["endpoint"],
        )

        mock_bucket.upload_fileobj.side_effect = ClientError(
            operation_name="NoSuchBucket",
            error_response={"Error": {"Message": "Random bucket exists error message"}},
        )
        self.assertFalse(
            s3.upload_content(
                bucket_name="whatever-bucket",
                content=io.BytesIO(b"whatever content"),
                key="whatever key",
            )
        )

    @patch("boto3.session.Session", new=Mock)
    def test_given_bucket_exists_when_upload_content_then_content_uploaded(self):
        valid_s3_parameters = {
            "access-key": "ACCESS-KEY",
            "secret-key": "SECRET-KEY",
            "region": "REGION",
            "endpoint": "http://ENDPOINT",
        }
        s3 = S3(
            access_key=valid_s3_parameters["access-key"],
            secret_key=valid_s3_parameters["secret-key"],
            region=valid_s3_parameters["region"],
            endpoint=valid_s3_parameters["endpoint"],
        )

        self.assertTrue(
            s3.upload_content(
                bucket_name="whatever-bucket",
                content=io.BytesIO(b"whatever content"),
                key="whatever key",
            )
        )
