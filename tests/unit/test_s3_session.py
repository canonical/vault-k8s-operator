#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import io
import unittest
from unittest.mock import Mock, patch

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from botocore.response import StreamingBody

from s3_session import S3


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
    def test_given_bucket_does_not_exist_when_get_object_key_list_then_empty_list_is_returned(
        self,
        patch_session,
    ):
        mock_resource = Mock()
        mock_bucket = Mock()

        patch_session.return_value.resource.return_value = mock_resource
        mock_resource.Bucket.return_value = mock_bucket
        mock_bucket.objects.filter.side_effect = ClientError(
            operation_name="NoSuchBucket",
            error_response={
                "Error": {
                    "Message": "Random bucket exists error message",
                    "Code": "NoSuchBucket",
                },
            },
        )
        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
        )
        self.assertEqual(
            s3.get_object_key_list(
                bucket_name="whatever-bucket",
                prefix="whatever-prefix",
            ),
            [],
        )

    @patch("boto3.session.Session")
    def test_given_clienterror_when_get_object_key_list_then_error_is_raised(
        self,
        patch_session,
    ):
        mock_resource = Mock()
        mock_bucket = Mock()

        patch_session.return_value.resource.return_value = mock_resource
        mock_resource.Bucket.return_value = mock_bucket
        mock_bucket.objects.filter.side_effect = ClientError(
            operation_name="Error",
            error_response={
                "Error": {
                    "Message": "Random bucket error",
                    "Code": "SomeError",
                },
            },
        )
        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
        )
        with self.assertRaises(ClientError):
            s3.get_object_key_list(
                bucket_name="whatever-bucket",
                prefix="whatever-prefix",
            )

    @patch("boto3.session.Session")
    def test_given_botocoreerror_when_get_object_key_list_then_error_is_raised(
        self,
        patch_session,
    ):
        mock_resource = Mock()
        mock_bucket = Mock()

        patch_session.return_value.resource.return_value = mock_resource
        mock_resource.Bucket.return_value = mock_bucket
        mock_bucket.objects.filter.side_effect = BotoCoreError()
        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
        )
        with self.assertRaises(BotoCoreError):
            s3.get_object_key_list(
                bucket_name="whatever-bucket",
                prefix="whatever-prefix",
            )

    @patch("boto3.session.Session")
    def test_given_objects_in_bucket_when_get_object_key_list_then_object_key_list_is_returned(
        self,
        patch_session,
    ):
        mock_resource = Mock()
        mock_bucket = Mock()

        patch_session.return_value.resource.return_value = mock_resource
        mock_resource.Bucket.return_value = mock_bucket
        mock_bucket.objects.filter.return_value = [
            Mock(key="whatever-key-1"),
            Mock(key="whatever-key-2"),
        ]
        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
        )
        self.assertEqual(
            s3.get_object_key_list(
                bucket_name="whatever-bucket",
                prefix="whatever-prefix",
            ),
            ["whatever-key-1", "whatever-key-2"],
        )

    @patch("boto3.session.Session")
    def test_given_bucket_does_not_exist_when_get_content_then_none_is_returned(
        self,
        patch_session,
    ):
        mock_resource = Mock()
        mock_bucket = Mock()
        mock_object = Mock()

        patch_session.return_value.resource.return_value = mock_resource
        mock_resource.Bucket.return_value = mock_bucket
        mock_bucket.Object.return_value = mock_object
        mock_object.get.side_effect = ClientError(
            operation_name="NoSuchBucket",
            error_response={
                "Error": {
                    "Message": "Random bucket exists error message",
                    "Code": "NoSuchBucket",
                },
            },
        )
        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
        )
        self.assertIsNone(
            s3.get_content(
                bucket_name="whatever-bucket",
                object_key="whatever-key",
            )
        )

    @patch("boto3.session.Session")
    def test_given_object_does_not_exist_when_get_content_then_none_is_returned(
        self,
        patch_session,
    ):
        mock_resource = Mock()
        mock_bucket = Mock()
        mock_object = Mock()

        patch_session.return_value.resource.return_value = mock_resource
        mock_resource.Bucket.return_value = mock_bucket
        mock_bucket.Object.return_value = mock_object
        mock_object.get.side_effect = ClientError(
            operation_name="NoSuchKey",
            error_response={
                "Error": {
                    "Message": "Random object exists error message",
                    "Code": "NoSuchKey",
                },
            },
        )
        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
        )
        self.assertIsNone(
            s3.get_content(
                bucket_name="whatever-bucket",
                object_key="whatever-key",
            )
        )

    @patch("boto3.session.Session")
    def test_given_clienterror_when_get_content_then_error_is_raised(
        self,
        patch_session,
    ):
        mock_resource = Mock()
        mock_bucket = Mock()
        mock_object = Mock()

        patch_session.return_value.resource.return_value = mock_resource
        mock_resource.Bucket.return_value = mock_bucket
        mock_bucket.Object.return_value = mock_object
        mock_object.get.side_effect = ClientError(
            operation_name="Error",
            error_response={
                "Error": {
                    "Message": "Random ClientError",
                    "Code": "Error",
                },
            },
        )
        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
        )
        with self.assertRaises(ClientError):
            s3.get_content(
                bucket_name="whatever-bucket",
                object_key="whatever-key",
            )

    @patch("boto3.session.Session")
    def test_given_botocoreerror_when_get_content_then_error_is_raised(
        self,
        patch_session,
    ):
        mock_resource = Mock()
        mock_bucket = Mock()
        mock_object = Mock()

        patch_session.return_value.resource.return_value = mock_resource
        mock_resource.Bucket.return_value = mock_bucket
        mock_bucket.Object.return_value = mock_object
        mock_object.get.side_effect = BotoCoreError()
        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
        )
        with self.assertRaises(BotoCoreError):
            s3.get_content(
                bucket_name="whatever-bucket",
                object_key="whatever-key",
            )

    @patch("boto3.session.Session")
    def test_given_object_found_when_get_content_then_content_is_returned(
        self,
        patch_session,
    ):
        mock_resource = Mock()
        mock_bucket = Mock()
        mock_object = Mock()

        patch_session.return_value.resource.return_value = mock_resource
        mock_resource.Bucket.return_value = mock_bucket
        mock_bucket.Object.return_value = mock_object
        streaming_body = StreamingBody(
            io.BytesIO(b"whatever content"), content_length=len(b"whatever content")
        )
        mock_object.get.return_value = {"Body": streaming_body}
        s3 = S3(
            access_key=self.VALID_S3_PARAMETERS["access-key"],
            secret_key=self.VALID_S3_PARAMETERS["secret-key"],
            region=self.VALID_S3_PARAMETERS["region"],
            endpoint=self.VALID_S3_PARAMETERS["endpoint"],
        )
        self.assertEqual(
            s3.get_content(
                bucket_name="whatever-bucket",
                object_key="whatever-key",
            ).read(),  # type: ignore[union-attr]
            b"whatever content",
        )
