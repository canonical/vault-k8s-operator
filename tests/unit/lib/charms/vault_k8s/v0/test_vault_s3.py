#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import io
import unittest
from unittest.mock import Mock, patch

import boto3
from botocore.exceptions import ClientError
from charms.vault_k8s.v0.vault_s3 import S3, S3Error


class TestS3(unittest.TestCase):
    VALID_S3_PARAMETERS = {
        "access-key": "ACCESS-KEY",
        "secret-key": "SECRET-KEY",
        "region": "REGION",
        "endpoint": "http://ENDPOINT",
    }

    def test_given_valid_s3_parameters_when_create_s3_session_then_session_is_created(self):
        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
        )
        self.assertIsInstance(s3.session, boto3.session.Session)

    def test_given_invalid_endpoint_when_create_s3_session_then_valueerror_is_raised(self):
        invalid_s3_parameters = {
            "access-key": "ACCESS-KEY",
            "secret-key": "SECRET-KEY",
            "region": "REGION",
            "endpoint": "invalid endpoint",
        }
        with self.assertRaises(S3Error):
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

        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
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

        mock_client.head_bucket.side_effect = ClientError(
            operation_name="NoSuchBucket",
            error_response={"Error": {"Message": "Random bucket exists error message"}},
        )

        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
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

        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
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
        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
        )

        self.assertTrue(
            s3.upload_content(
                bucket_name="whatever-bucket",
                content=io.BytesIO(b"whatever content"),
                key="whatever key",
            )
        )

    @patch("boto3.session.Session")
    def test_given_bucket_doesnt_exist_when_get_object_key_list_then_empty_list_is_returned(self, patch_session):
        mock_resource = Mock()

        patch_session.return_value.resource.return_value = mock_resource
        mock_resource.Bucket.side_effect = ClientError(
            operation_name="GetBucket",
            error_response={
                "Error": {"Message": "Random bucket exists error message", "Code" : "NoSuchBucket"},

                },
        )

        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
        )

        object_list = s3.get_object_key_list(bucket_name="whatever-bucket", prefix="whatever-prefix")

        self.assertEqual(object_list, [])

    @patch("boto3.session.Session")
    def test_given_client_error_when_get_object_key_list_then_s3_error_is_raised(self, patch_session):
        mock_resource = Mock()

        patch_session.return_value.resource.return_value = mock_resource
        mock_resource.Bucket.side_effect = ClientError(
            operation_name="GetBucket",
            error_response={
                "Error": {"Message": "Random bucket exists error message", "Code" : "RandomCode"},
            },
        )

        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
        )

        with self.assertRaises(S3Error):
            s3.get_object_key_list(bucket_name="whatever-bucket", prefix="whatever-prefix")

    @patch("boto3.session.Session")
    def test_given_bucket_contains_objects_when_get_object_key_list_then_object_list_is_returned(self, patch_session):
        mock_resource = Mock()
        mock_bucket = Mock()
        mock_object = Mock()

        patch_session.return_value.resource.return_value = mock_resource
        mock_resource.Bucket.return_value = mock_bucket
        mock_bucket.objects.filter.return_value = [mock_object]
        mock_object.key = "object-key"

        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
        )

        object_list = s3.get_object_key_list(bucket_name="whatever-bucket", prefix="whatever-prefix")

        self.assertEqual(object_list, ["object-key"])
