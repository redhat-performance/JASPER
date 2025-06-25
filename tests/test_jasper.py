"""
Unit tests for the JASPER Jira Active Sprint Personal Reporter core functions.

These tests use Python's built-in unittest framework and unittest.mock for mocking
external dependencies such as network requests. The tests cover key API interaction
functions, configuration loading, and authentication logic in jasper.__main__.

Author: Dustin Black
License: Apache License, Version 2.0
"""

import unittest
from unittest.mock import patch, MagicMock
import os

import jasper.__main__ as jasper_main


class TestJasperMain(unittest.TestCase):
    """
    Unit tests for core functions in jasper.__main__ using unittest and unittest.mock.
    """

    def setUp(self):
        """
        Set up common test data for each test.
        """
        self.fake_jira_url = "https://jira.example.com"
        self.fake_api_token = "fake-token"
        self.fake_board_ids = [1, 2]
        self.fake_issue_key = "PROJ-123"

    @patch("jasper.__main__.requests.get")
    def test_get_active_sprints_success(self, mock_get):
        """
        Test get_active_sprints returns sprint IDs when the API call is successful.
        """
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"values": [{"id": 42}]}
        mock_get.return_value = mock_resp
        sprints = jasper_main.get_active_sprints(
            self.fake_jira_url, self.fake_api_token, self.fake_board_ids
        )
        self.assertEqual(sprints, [42])

    @patch("jasper.__main__.requests.get")
    def test_get_active_sprints_rate_limit(self, mock_get):
        """
        Test get_active_sprints handles HTTP 429 rate limiting and retries.
        """
        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_429.headers = {"Retry-After": "1"}
        resp_429.json.return_value = {}
        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.json.return_value = {"values": [{"id": 99}]}
        # Provide enough responses for each board in fake_board_ids
        mock_get.side_effect = [resp_429, resp_200, resp_429, resp_200]
        sprints = jasper_main.get_active_sprints(
            self.fake_jira_url, self.fake_api_token, self.fake_board_ids
        )
        self.assertEqual(sprints, [99, 99])

    @patch("jasper.__main__.requests.post")
    def test_add_comment_to_issue_success(self, mock_post):
        """
        Test add_comment_to_issue returns True when the comment is added successfully.
        """
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_post.return_value = mock_resp
        result = jasper_main.add_comment_to_issue(
            self.fake_jira_url, self.fake_api_token, self.fake_issue_key, "test comment"
        )
        self.assertTrue(result)

    @patch("jasper.__main__.requests.get")
    def test_get_issue_transitions_success(self, mock_get):
        """
        Test get_issue_transitions returns transitions when the API call is successful.
        """
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"transitions": [{"id": "1", "name": "Done"}]}
        mock_get.return_value = mock_resp
        transitions = jasper_main.get_issue_transitions(
            self.fake_jira_url, self.fake_api_token, self.fake_issue_key
        )
        self.assertEqual(transitions, [{"id": "1", "name": "Done"}])

    @patch("jasper.__main__.requests.post")
    def test_set_issue_transition_success(self, mock_post):
        """
        Test set_issue_transition returns True when the transition is successful.
        """
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_post.return_value = mock_resp
        result = jasper_main.set_issue_transition(
            self.fake_jira_url, self.fake_api_token, self.fake_issue_key, "1"
        )
        self.assertTrue(result)

    @patch("jasper.__main__.requests.get")
    def test_check_jira_auth_success(self, mock_get):
        """
        Test check_jira_auth returns True for a 200 OK response.
        """
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp
        self.assertTrue(
            jasper_main.check_jira_auth(self.fake_jira_url, self.fake_api_token)
        )

    @patch("jasper.__main__.requests.get")
    def test_check_jira_auth_failure(self, mock_get):
        """
        Test check_jira_auth returns False for a 401 Unauthorized response.
        """
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.reason = "Unauthorized"
        mock_get.return_value = mock_resp
        self.assertFalse(
            jasper_main.check_jira_auth(self.fake_jira_url, self.fake_api_token)
        )

    def test_load_config_local_and_home(self):
        """
        Test load_config loads a config file from the local directory.
        """
        config_content = "jira_url: https://jira.example.com\n"
        test_filename = "jasper_config.yaml"
        with open(test_filename, "w", encoding="utf-8") as f:
            f.write(config_content)
        try:
            config, path = jasper_main.load_config(test_filename)
            self.assertEqual(config["jira_url"], "https://jira.example.com")
            self.assertIn("jasper_config.yaml", path)
        finally:
            os.remove(test_filename)


if __name__ == "__main__":
    unittest.main()
