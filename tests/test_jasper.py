"""
Unit tests for the JASPER Jira Active Sprint Personal Reporter core functions.

These tests use Python's built-in unittest framework and unittest.mock for mocking
external dependencies such as network requests and keyring. The tests cover key API
interaction functions, configuration loading, and authentication logic in
jasper.__main__.

Author: Dustin Black
License: Apache License, Version 2.0
"""

import unittest
from unittest.mock import patch, MagicMock
import os
import requests
import json
import io
import yaml

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
        self.mock_issue_list = [
            {
                "key": "PROJ-123",
                "self": "https://jira.example.com/rest/api/2/issue/PROJ-123",
                "fields": {
                    "summary": "This is a test issue.",
                    "status": {"name": "In Progress"},
                    "priority": {"name": "High"},
                    "assignee": {"name": "example_user"},
                },
                "_jasper_assignee": "example_user",
            }
        ]

    @patch("jasper.__main__.keyring")
    @patch("jasper.__main__.requests.get")
    def test_get_active_sprints_success(self, mock_get, _):
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

    @patch("jasper.__main__.keyring")
    @patch("jasper.__main__.requests.get")
    def test_get_active_sprints_rate_limit(self, mock_get, _):
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
        self.assertEqual(sprints, [99])

    # --- Negative/Error Path Tests ---

    @patch("jasper.__main__.keyring")
    @patch("jasper.__main__.requests.get")
    def test_get_active_sprints_api_error(self, mock_get, _):
        """Test get_active_sprints returns empty list on API error."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.json.return_value = {}
        mock_get.return_value = mock_resp
        sprints = jasper_main.get_active_sprints(
            self.fake_jira_url, self.fake_api_token, self.fake_board_ids
        )
        self.assertEqual(sprints, [])

    @patch("jasper.__main__.keyring")
    @patch("jasper.__main__.requests.post")
    def test_add_comment_to_issue_failure(self, mock_post, _):
        """Test add_comment_to_issue returns False on non-201 response."""
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        # Simulate raise_for_status raising an HTTPError for 400
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError()
        mock_post.return_value = mock_resp
        result = jasper_main.add_comment_to_issue(
            self.fake_jira_url, self.fake_api_token, self.fake_issue_key, "fail comment"
        )
        self.assertFalse(result)

    @patch("jasper.__main__.keyring")
    @patch("jasper.__main__.requests.post")
    def test_set_issue_transition_failure(self, mock_post, _):
        """Test set_issue_transition returns False on non-204 response."""
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_post.return_value = mock_resp
        result = jasper_main.set_issue_transition(
            self.fake_jira_url, self.fake_api_token, self.fake_issue_key, "1"
        )
        self.assertFalse(result)

    @patch("jasper.__main__.keyring")
    @patch("jasper.__main__.requests.get")
    def test_get_issue_transitions_failure(self, mock_get, _):
        """Test get_issue_transitions returns empty list on non-200 response."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.json.return_value = {}
        mock_get.return_value = mock_resp
        transitions = jasper_main.get_issue_transitions(
            self.fake_jira_url, self.fake_api_token, self.fake_issue_key
        )
        self.assertEqual(transitions, [])

    def test_load_config_invalid_file(self):
        """Test load_config raises on invalid YAML file."""
        test_filename = "bad_config.yaml"
        with open(test_filename, "w", encoding="utf-8") as f:
            f.write("not: [valid yaml")
        try:
            with self.assertRaises(yaml.YAMLError):
                jasper_main.load_config(test_filename)
        finally:
            os.remove(test_filename)

    @patch("os.path.exists", return_value=False)
    def test_load_config_missing_file(self, mock_exists):
        """
        Test load_config raises FileNotFoundError when no config file is found
        in any of the search paths, regardless of the actual filesystem.
        """
        with self.assertRaises(FileNotFoundError):
            jasper_main.load_config("no_such_file.yaml")

        # Verify that the function actually checked for files
        self.assertTrue(mock_exists.called)

    # --- Keyring Interaction Tests ---

    @patch("jasper.__main__.keyring")
    def test_keyring_get_token(self, mock_keyring):
        """Test retrieving a token from keyring."""
        mock_keyring.get_password.return_value = "token-from-keyring"
        token = mock_keyring.get_password("jasper", "user")
        self.assertEqual(token, "token-from-keyring")
        mock_keyring.get_password.assert_called_with("jasper", "user")

    @patch("jasper.__main__.keyring")
    def test_keyring_set_token(self, mock_keyring):
        """Test storing a token in keyring."""
        mock_keyring.set_password.return_value = None
        jasper_main.keyring.set_password("jasper", "user", "new-token")
        mock_keyring.set_password.assert_called_with("jasper", "user", "new-token")

    # --- Positive Path Tests ---

    @patch("jasper.__main__.keyring")
    @patch("jasper.__main__.requests.post")
    def test_add_comment_to_issue_success(self, mock_post, _):
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

    @patch("jasper.__main__.keyring")
    @patch("jasper.__main__.requests.get")
    def test_get_issue_transitions_success(self, mock_get, _):
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

    @patch("jasper.__main__.keyring")
    @patch("jasper.__main__.requests.post")
    def test_set_issue_transition_success(self, mock_post, _):
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

    @patch("jasper.__main__.keyring")
    @patch("jasper.__main__.requests.get")
    def test_check_jira_auth_success(self, mock_get, _):
        """
        Test check_jira_auth returns True for a 200 OK response.
        """
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp
        self.assertTrue(
            jasper_main.check_jira_auth(self.fake_jira_url, self.fake_api_token)
        )

    @patch("jasper.__main__.keyring")
    @patch("jasper.__main__.requests.get")
    def test_check_jira_auth_failure(self, mock_get, _):
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

    @patch("jasper.__main__.keyring")
    def test_load_config_local_and_home(self, _):
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

    @patch("jasper.__main__.keyring")
    @patch("jasper.__main__.requests.post")
    def test_get_user_issues_in_sprints_success_multiple_users(self, mock_post, _):
        """
        Test get_user_issues_in_sprints constructs JQL correctly for multiple users.
        """
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"issues": []}
        mock_post.return_value = mock_resp

        jasper_main.get_user_issues_in_sprints(
            self.fake_jira_url, self.fake_api_token, ["user1", "user2"], [100]
        )

        mock_post.assert_called_once()
        # Extract the 'data' argument which is a JSON string and parse it
        sent_payload = json.loads(mock_post.call_args.kwargs["data"])
        self.assertIn('assignee in ("user1", "user2")', sent_payload["jql"])

    @patch("jasper.__main__.keyring")
    @patch("jasper.__main__.requests.post")
    def test_get_user_issues_in_sprints_success_single_user(self, mock_post, _):
        """
        Test get_user_issues_in_sprints constructs JQL correctly for a single user.
        """
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "issues": [
                {
                    "key": "PROJ-1",
                    "fields": {"summary": "Test issue", "assignee": {"name": "user1"}},
                }
            ]
        }
        mock_post.return_value = mock_resp

        issues = jasper_main.get_user_issues_in_sprints(
            self.fake_jira_url, self.fake_api_token, ["user1"], [100]
        )

        self.assertEqual(len(issues), 1)
        sent_payload = json.loads(mock_post.call_args.kwargs["data"])
        self.assertIn('assignee = "user1"', sent_payload["jql"])

    # --- main() Function Tests ---

    @patch("argparse.ArgumentParser.parse_args")
    @patch("jasper.__main__.load_config")
    @patch("jasper.__main__.get_api_token_with_auth_check", return_value="fake-token")
    @patch("jasper.__main__.get_active_sprints", return_value=[100])
    @patch("jasper.__main__.get_user_issues_in_sprints")
    @patch("sys.stdout", new_callable=io.StringIO)
    @patch("builtins.input", side_effect=["q"])
    def test_main_happy_path_quit(
        self,
        mock_input,
        mock_stdout,
        mock_get_issues,
        mock_sprints,
        mock_token,
        mock_config,
        mock_args,
    ):
        """Test main runs, displays issues, and quits."""
        mock_args.return_value = MagicMock(
            config="c.yaml",
            jira_url=None,
            usernames=None,
            board_ids=None,
            set_token=False,
            no_jasper_attribution=False,
        )
        mock_config.return_value = (
            {
                "jira_url": self.fake_jira_url,
                "usernames": ["example_user"],
                "board_ids": self.fake_board_ids,
            },
            "c.yaml",
        )
        mock_get_issues.return_value = self.mock_issue_list

        jasper_main.main()

        self.assertIn("PROJ-123", mock_stdout.getvalue())
        self.assertIn("This is a test issue", mock_stdout.getvalue())
        mock_input.assert_called_once()

    @patch("argparse.ArgumentParser.parse_args")
    @patch("jasper.__main__.load_config")
    @patch("jasper.__main__.get_api_token_with_auth_check", return_value="fake-token")
    @patch("jasper.__main__.get_active_sprints", return_value=[100])
    @patch("jasper.__main__.get_user_issues_in_sprints")
    @patch("jasper.__main__.webbrowser.open_new_tab")
    @patch("builtins.input", side_effect=["1", "o", "b", "q"])
    def test_main_action_open_in_browser(
        self,
        mock_input,
        mock_webbrowser,
        mock_get_issues,
        mock_sprints,
        mock_token,
        mock_config,
        mock_args,
    ):
        """Test main loop selecting an issue and opening it."""
        mock_args.return_value = MagicMock(
            config="c.yaml",
            jira_url=None,
            usernames=None,
            board_ids=None,
            set_token=False,
            no_jasper_attribution=False,
        )
        mock_config.return_value = (
            {
                "jira_url": self.fake_jira_url,
                "usernames": ["example_user"],
                "board_ids": self.fake_board_ids,
            },
            "c.yaml",
        )
        mock_get_issues.return_value = self.mock_issue_list

        jasper_main.main()

        mock_webbrowser.assert_called_with(f"{self.fake_jira_url}/browse/PROJ-123")

    @patch("argparse.ArgumentParser.parse_args")
    @patch("jasper.__main__.load_config")
    @patch("jasper.__main__.get_api_token_with_auth_check", return_value="fake-token")
    @patch("jasper.__main__.get_active_sprints", return_value=[100])
    @patch("jasper.__main__.get_user_issues_in_sprints")
    @patch("jasper.__main__.add_comment_to_issue")
    @patch("jasper.__main__.get_multiline_comment", return_value="Test comment")
    @patch("builtins.input", side_effect=["1", "c", "b", "q"])
    def test_main_action_add_comment(
        self,
        mock_input,
        mock_get_comment,
        mock_add_comment,
        mock_get_issues,
        mock_sprints,
        mock_token,
        mock_config,
        mock_args,
    ):
        """Test main loop selecting an issue and adding a comment."""
        mock_args.return_value = MagicMock(
            config="c.yaml",
            jira_url=None,
            usernames=None,
            board_ids=None,
            set_token=False,
            no_jasper_attribution=False,
        )
        mock_config.return_value = (
            {
                "jira_url": self.fake_jira_url,
                "usernames": ["dblack"],
                "board_ids": self.fake_board_ids,
            },
            "c.yaml",
        )
        mock_get_issues.return_value = self.mock_issue_list

        jasper_main.main()

        mock_add_comment.assert_called()
        # Check that attribution was added to the comment body
        self.assertIn("JASPER", mock_add_comment.call_args[0][3])

    @patch("argparse.ArgumentParser.parse_args")
    @patch(
        "jasper.__main__.load_config", side_effect=FileNotFoundError("Config not found")
    )
    @patch("sys.stderr", new_callable=io.StringIO)
    @patch("sys.exit")
    def test_main_config_load_error(
        self, mock_exit, mock_stderr, mock_config, mock_args
    ):
        """Test main exits gracefully if config file cannot be loaded."""
        mock_args.return_value = MagicMock(config="nonexistent.yaml")

        # Let the mocked sys.exit raise the actual SystemExit exception
        # to correctly halt execution flow inside main().
        mock_exit.side_effect = SystemExit(1)

        with self.assertRaises(SystemExit) as cm:
            jasper_main.main()

        # Check that the exit code is correct
        self.assertEqual(cm.exception.code, 1)

        # Verify that the correct error message was printed to stderr.
        self.assertIn("Error loading configuration", mock_stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
