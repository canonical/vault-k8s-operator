#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import io
import unittest
from unittest.mock import Mock

import boto3
from botocore.exceptions import ClientError

from s3_helpers import create_s3_bucket, create_s3_session, upload_content_to_s3


class TestS3Helpers(unittest.TestCase):
    def test_given_valid_s3_parameters_when_create_s3_session_then_session_is_created(self):
        valid_s3_parameters = {
            "access-key": "ACCESS-KEY",
            "secret-key": "SECRET-KEY",
            "region": "REGION",
            "endpoint": "http://ENDPOINT",
        }
        session = create_s3_session(valid_s3_parameters)
        self.assertIsInstance(session, boto3.session.Session)

    def test_given_missing_s3_parameters_when_create_s3_session_then_session_not_created(self):
        incomplete_s3_parameters = {
            "access-key": "ACCESS-KEY",
            "secret-key": "SECRET-KEY",
            "region": "REGION",
        }
        self.assertIsNone(create_s3_session(incomplete_s3_parameters))

    def test_given_invalid_endpoint_when_create_s3_session_then_session_not_created(self):
        s3_parameters_with_invalid_endpoint = {
            "access-key": "ACCESS-KEY",
            "secret-key": "SECRET-KEY",
            "region": "REGION",
            "endpoint": "not a valid endpoint",
        }
        self.assertIsNone(create_s3_session(s3_parameters_with_invalid_endpoint))

    def test_given_cannot_connect_to_endpoint_when_create_s3_bucket_then_value_error_is_raised(
        self,
    ):
        valid_s3_parameters = {
            "access-key": "ACCESS-KEY",
            "secret-key": "SECRET-KEY",
            "region": "REGION",
            "endpoint": "http://ENDPOINT",
            "bucket-name": "BUCKET",
        }
        session = boto3.session.Session(
            aws_access_key_id=valid_s3_parameters["access-key"],
            aws_secret_access_key=valid_s3_parameters["secret-key"],
            region_name=valid_s3_parameters["region"],
        )
        with self.assertRaises(ValueError):
            create_s3_bucket(
                session=session,
                bucket_name=valid_s3_parameters["bucket-name"],
                region=valid_s3_parameters["region"],
                endpoint="invalid endpoint",
            )

    def test_given_bucket_already_exists_when_create_s3_bucket_then_bucket_not_created(
        self,
    ):
        mock_session = Mock()

        create_s3_bucket(
            session=mock_session,
            bucket_name="whatever bucket",
            region="whatever region",
            endpoint="whatever endpoint",
        )

        mock_session.resource.Bucket.create.assert_not_called()

    def test_given_bucket_not_created_when_create_s3_bucket_then_bucket_created(
        self,
    ):
        mock_session = Mock()
        mock_resource = Mock()
        mock_bucket = Mock()
        mock_client = Mock()

        mock_session.resource.return_value = mock_resource
        mock_resource.Bucket.return_value = mock_bucket
        mock_bucket.meta.client = mock_client
        mock_client.head_bucket.side_effect = ClientError(
            operation_name="NoSuchBucket",
            error_response={"Error": {"Message": "Random bucket exists error message"}},
        )

        create_s3_bucket(
            session=mock_session,
            bucket_name="whatever bucket",
            region="whatever region",
            endpoint="whatever endpoint",
        )

        mock_bucket.create.assert_called_once()

    def test_bucket_does_not_exist_when_upload_content_to_s3_then_content_not_uploaded(self):
        mock_session = Mock()
        mock_resource = Mock()
        mock_bucket = Mock()

        mock_session.resource.return_value = mock_resource
        mock_resource.Bucket.return_value = mock_bucket
        mock_bucket.put_object.side_effect = ClientError(
            operation_name="NoSuchBucket",
            error_response={"Error": {"Message": "Random bucket exists error message"}},
        )
        self.assertFalse(
            upload_content_to_s3(
                session=mock_session,
                bucket_name="whatever bucket",
                endpoint="whatever endpoint",
                content=io.BytesIO(b"whatever content"),
                key="whatever key",
            )
        )

    def test_given_bucket_exists_when_upload_content_to_s3_then_content_uploaded(self):
        mock_session = Mock()
        mock_resource = Mock()
        mock_bucket = Mock()

        mock_session.resource.return_value = mock_resource
        mock_resource.Bucket.return_value = mock_bucket

        self.assertTrue(
            upload_content_to_s3(
                session=mock_session,
                bucket_name="whatever bucket",
                endpoint="whatever endpoint",
                content=io.BytesIO(b"whatever content"),
                key="whatever key",
            )
        )
