#!/usr/bin/env python3
"""
JASPER: Jira Active Sprint Personal Reporter

This script interacts with the Jira REST API to help users track and manage their
assigned issues in active sprints. It supports listing issues, adding comments,
changing issue status, and opening issues in a web browser. Configuration is
handled via a YAML file and API tokens are stored securely using the system keyring.

Author: Dustin Black, Red Hat, GmbH
License: Apache License, Version 2.0
"""

# Copyright 2025 Dustin Black, Red Hat, GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import argparse
import getpass
import sys
import os
import webbrowser
import time
import requests
import yaml
import keyring
import keyring.errors
import yaml.parser
import logging

# Initialize logger
logger = logging.getLogger("JASPER")

DEFAULT_ATTRIBUTION = True


# --- Custom Formatter for Color-coded Logs ---
class ColoredFormatter(logging.Formatter):
    """
    Custom formatter to add ANSI color codes to log messages based on severity.
    This works on UNIX-like systems and modern Windows terminals.
    """

    GREY = "\x1b[38;20m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    RED = "\x1b[31m"
    BOLD_RED = "\x1b[31;1m"
    RESET = "\x1b[0m"

    def __init__(self, fmt, datefmt=None):
        super().__init__(fmt, datefmt)
        self.FORMATS = {
            logging.DEBUG: self.GREY + fmt + self.RESET,
            logging.INFO: self.GREEN + fmt + self.RESET,
            logging.WARNING: self.YELLOW + fmt + self.RESET,
            logging.ERROR: self.RED + fmt + self.RESET,
            logging.CRITICAL: self.BOLD_RED + fmt + self.RESET,
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt=self.datefmt)
        return formatter.format(record)


# --- Jira API Functions ---


def get_active_sprints(base_url, api_token, board_ids, max_retries=3, retry_delay=2):
    """
    Fetches active sprints from specified boards.

    Args:
        base_url (str): The base URL of the Jira instance.
        api_token (str): The API token for authentication.
        board_ids (list[int]): List of Jira board IDs to check.
        max_retries (int): Number of retries for transient errors.
        retry_delay (int): Delay in seconds between retries.

    Returns:
        list[int]: A list of active sprint IDs, or an empty list on failure.
    """
    if not board_ids:
        raise ValueError("board_ids is required for get_active_sprints()")
    active_sprint_ids = []
    boards_to_check = []
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
    }

    logger.info(f"Checking specified board IDs: {board_ids}")
    boards_to_check = [{"id": board_id} for board_id in board_ids]

    logger.info(f"Found {len(boards_to_check)} boards. Looking for active sprints...")

    # Iterate through the boards and find sprints with the state "active".
    for board in boards_to_check:
        attempt = 0
        while attempt < max_retries:
            try:
                sprint_url = (
                    f"{base_url}/rest/agile/1.0/board/{board['id']}/sprint?state=active"
                )
                sprint_response = requests.get(sprint_url, headers=headers, timeout=30)
                if sprint_response.status_code == 429:
                    retry_after = int(
                        sprint_response.headers.get("Retry-After", retry_delay)
                    )
                    logger.warning(
                        "Rate limited by Jira API (HTTP 429). "
                        f"Retrying after {retry_after}s..."
                    )
                    time.sleep(retry_after)
                    attempt += 1
                    continue
                sprint_response.raise_for_status()
                sprints = sprint_response.json().get("values", [])
                for sprint in sprints:
                    if sprint.get("id") not in active_sprint_ids:
                        active_sprint_ids.append(sprint["id"])
                break  # Success, exit retry loop
            except requests.exceptions.RequestException as e:
                attempt += 1
                if attempt < max_retries:
                    logger.warning(
                        f"Could not fetch sprints for board ID {board['id']} "
                        f"(attempt {attempt}/{max_retries}). "
                        f"Retrying in {retry_delay}s. "
                        f"Error: {e}"
                    )
                    time.sleep(retry_delay)
                else:
                    logger.error(
                        f"Could not fetch sprints for board ID {board['id']} "
                        f"after {max_retries} attempts. Error: {e}"
                    )
    return active_sprint_ids


def get_user_issues_in_sprints(base_url, api_token, usernames, sprint_ids):
    """
    Searches for issues assigned to one or more users within a list of sprints.

    Args:
        base_url (str): The base URL of the Jira instance.
        api_token (str): The API token for authentication.
        usernames (list[str]): List of Jira Account IDs or usernames.
        sprint_ids (list[int]): A list of sprint IDs to search within.

    Returns:
        list[dict]: A list of issue dictionaries, or an empty list on failure.
    """
    if not sprint_ids or not usernames:
        return []

    search_url = f"{base_url}/rest/api/2/search"
    sprint_id_string = ", ".join(map(str, sprint_ids))
    # Build JQL for multiple users
    if len(usernames) == 1:
        assignee_jql = f'assignee = "{usernames[0]}"'
    else:
        quoted_users = ", ".join(f'"{u}"' for u in usernames)
        assignee_jql = f"assignee in ({quoted_users})"
    jql = f"{assignee_jql} AND sprint in ({sprint_id_string}) " "ORDER BY updated DESC"

    payload = {
        "jql": jql,
        "fields": ["summary", "status", "issuetype", "priority", "labels", "assignee"],
        "maxResults": 100,
    }

    logger.info("Querying for issues with JQL...")
    logger.debug(f"  > {jql}")

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(
            search_url,
            headers=headers,
            data=json.dumps(payload),
            timeout=30,
        )
        response.raise_for_status()
        issues = response.json().get("issues", [])
        # Annotate each issue with the assignee for clarity
        for issue in issues:
            assignee = issue["fields"].get("assignee")
            if assignee:
                issue["_jasper_assignee"] = (
                    assignee.get("name")
                    or assignee.get("displayName")
                    or assignee.get("accountId", "")
                )
            else:
                issue["_jasper_assignee"] = ""
        return issues
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching issues: {e}")
        if hasattr(e, "response") and e.response is not None:
            logger.debug(f"Response Body: {e.response.text}")
        return []


def add_comment_to_issue(base_url, api_token, issue_key, comment_body):
    """
    Adds a plain text comment to a Jira issue (compatible with Jira Data Center).

    Args:
        base_url (str): The base URL of the Jira instance.
        api_token (str): The API token for authentication.
        issue_key (str): The key of the issue to comment on (e.g., "PROJ-123").
        comment_body (str): The text of the comment to add.

    Returns:
        bool: True if the comment was added successfully, False otherwise.
    """
    comment_url = f"{base_url}/rest/api/2/issue/{issue_key}/comment"
    payload = {"body": comment_body}
    logger.info(f"Adding comment to issue {issue_key}...")
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    try:
        response = requests.post(comment_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        if response.status_code == 201:
            logger.info("Comment added successfully.")
            return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Error adding comment: {e}")
        if hasattr(e, "response") and e.response is not None:
            logger.debug(f"Response Body: {e.response.text}")
    return False


def get_issue_transitions(base_url, api_token, issue_key):
    """
    Gets available status transitions for a Jira issue.

    Args:
        base_url (str): The base URL of the Jira instance.
        api_token (str): The API token for authentication.
        issue_key (str): The key of the issue.

    Returns:
        list[dict]: A list of available transition dictionaries.
    """
    transitions_url = f"{base_url}/rest/api/2/issue/{issue_key}/transitions"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
    }
    try:
        response = requests.get(transitions_url, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json().get("transitions", [])
    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting transitions for {issue_key}: {e}")
        return []


def set_issue_transition(base_url, api_token, issue_key, transition_id):
    """
    Changes the status of a Jira issue by posting a transition ID.

    Args:
        base_url (str): The base URL of the Jira instance.
        api_token (str): The API token for authentication.
        issue_key (str): The key of the issue.
        transition_id (str): The ID of the desired status transition.

    Returns:
        bool: True if successful, False otherwise.
    """
    transitions_url = f"{base_url}/rest/api/2/issue/{issue_key}/transitions"
    payload = {"transition": {"id": transition_id}}
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    try:
        response = requests.post(
            transitions_url, headers=headers, json=payload, timeout=30
        )
        response.raise_for_status()
        if response.status_code == 204:
            logger.info(f"Issue {issue_key} status changed successfully.")
            return True
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Error changing status for {issue_key}: {e}")
        if hasattr(e, "response") and e.response is not None:
            logger.debug(f"Response Body: {e.response.text}")
        return False


# --- UI & Interaction Functions ---


def display_issues(issues):
    """
    Prints a numbered list of issues to the console with key details and a direct URL.

    Args:
        issues (list[dict]): List of Jira issue dictionaries.
    """
    print("\n--- Active Sprint Items ---")
    for i, issue in enumerate(issues):
        key = issue["key"]
        fields = issue["fields"]
        summary = fields["summary"]
        status = fields["status"]["name"]
        priority_name = fields.get("priority", {}).get("name", "N/A")
        assignee = issue.get(
            "_jasper_assignee", fields.get("assignee", {}).get("name", "")
        )
        base_url = ""
        if "self" in issue:
            self_url = issue["self"]
            base_url = self_url.split("/rest/api")[0]
        url = f"{base_url}/browse/{key}" if base_url else key
        assignee_str = f" (Assignee: {assignee})" if assignee else ""
        print(
            f"  {i+1}: [{key}] {summary} (Status: {status}, Priority: "
            f"{priority_name}){assignee_str}"
        )
        print(f"      URL: {url}")
    print("---------------------------\n")


def get_multiline_comment():
    """
    Gets multi-line input from the user for a comment.

    Allows users to write detailed comments. The input is terminated by
    an EOF signal (Ctrl+D on Linux/macOS, Ctrl+Z then Enter on Windows).

    Returns:
        str or None: The combined multi-line comment, or None if cancelled.
    """
    print(
        "Enter your comment, ending with a new line. Press Ctrl+D (Linux/macOS) or "
        "Ctrl+Z then Enter (Windows) to save."
    )
    try:
        lines = sys.stdin.readlines()
        return "".join(lines).strip()
    except KeyboardInterrupt:
        print("\nComment cancelled.")
        return None


# --- Configuration & Token Management ---


def load_config(config_path):
    """
    Loads configuration from a YAML file. Searches in this order:
    1. User-provided path from --config (if provided, only this is used)
    2. jasper_config.yaml in the current directory
    3. jasper_config.yaml in $HOME
    Raises if no config file is found or if YAML is invalid.
    """
    search_paths = []
    # 1. User-provided path
    if config_path:
        # If the user provided a config path, only use that
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"No configuration file found at {config_path}")
        search_paths = [config_path]
    else:
        # Fallback search order
        cwd_config = os.path.join(os.getcwd(), "jasper_config.yaml")
        home_config = os.path.join(os.path.expanduser("~"), "jasper_config.yaml")
        search_paths = [cwd_config, home_config]

    found_path = None
    for path in search_paths:
        if os.path.exists(path):
            found_path = path
            break

    # If no config file was found anywhere, raise an exception
    if not found_path:
        error_msg = (
            f"No configuration file found at the specified path: {config_path}"
            if config_path
            else "No configuration file found in ./jasper_config.yaml or "
            "$HOME/jasper_config.yaml"
        )
        raise FileNotFoundError(error_msg)

    # Try to load the one we found. If it fails, it's a fatal error.
    try:
        logger.info(f"Loading configuration from: {found_path}")
        with open(found_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        logger.info("Configuration loaded successfully.")
        return config, found_path
    except (yaml.YAMLError, IOError) as e:
        # Re-raise the exception to be handled by the caller. This makes
        # an invalid config file a fatal error, which is the desired behavior.
        logger.critical(f"Error reading or parsing config file {found_path}: {e}")
        raise


def check_jira_auth(jira_url, api_token):
    """
    Check if the provided Jira credentials are valid using Bearer token.

    Args:
        jira_url (str): The Jira instance URL.
        api_token (str): The API token for authentication.

    Returns:
        bool: True if authentication is successful, False otherwise.
    """
    test_url = f"{jira_url.rstrip('/')}/rest/api/2/myself"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
    }
    try:
        resp = requests.get(test_url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return True
        else:
            logger.warning(f"Authentication failed: {resp.status_code} {resp.reason}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Error connecting to Jira: {e}")
        return False


def get_api_token_with_auth_check(service_name, keyring_user, jira_url):
    """
    Prompt for API token if needed and check authentication before proceeding.

    Args:
        service_name (str): The unique name for the service storing the password.
        keyring_user (str): The key used for storing/retrieving the token.
        jira_url (str): The Jira instance URL, used for generating the token hint.

    Returns:
        str: The retrieved or entered API token.
    """
    from_keyring = False
    first_prompt = True
    while True:
        token = None
        try:
            token = keyring.get_password(service_name, keyring_user)
            if token:
                from_keyring = True
                logger.info("API token found in secure storage.")
        except keyring.errors.NoKeyringError:
            logger.warning(
                "`keyring` backend not found. Falling back to password prompt."
            )
            logger.warning(
                "For secure storage, please install a backend "
                "(e.g., 'pip install keyrings.cryptfile')"
            )
        except Exception as e:
            logger.error(f"An unexpected error occurred with keyring: {e}")

        if not token:
            if first_prompt:
                logger.warning("API token not found in storage.")
                if jira_url:
                    base = jira_url.rstrip("/")
                    tip_url = (
                        f"{base}"
                        "/secure/ViewProfile.jspa"
                        "?selectedTab=com.atlassian.pats.pats-plugin:"
                        "jira-user-personal-access-tokens"
                    )
                    print(
                        "Tip: You can generate a Jira API token for this instance at: "
                        f"{tip_url}"
                    )
                else:
                    print(
                        "Tip: You can generate a Jira API token at: "
                        "https://id.atlassian.com/manage-profile/security/api-tokens"
                    )
                first_prompt = False
            try:
                token = getpass.getpass("Enter your Jira API Token: ")
                from_keyring = False
                # Prompt to store the token in the keyring for future use
                store = (
                    input(
                        "Store this API token in your system keyring for future use? "
                        "(Y/n): "
                    )
                    .strip()
                    .lower()
                )
                if store in ("", "y", "yes"):
                    try:
                        keyring.set_password(service_name, keyring_user, token)
                        logger.info("API token stored securely in keyring.")
                    except Exception as e:
                        logger.error(f"Could not store token in keyring: {e}")
            except Exception as e:
                logger.critical(f"Could not read API token: {e}")
                sys.exit(1)

        # Check authentication
        if check_jira_auth(jira_url, token):
            logger.info("API authentication successful.")
            return token
        else:
            if from_keyring:
                logger.critical("Stored API token is invalid. Please reset your token.")
                sys.exit(1)
            else:
                logger.warning("Invalid API token. Please try again.\n")


def set_api_token(service_name, user):
    """
    Prompts user for an API token and stores it in the system's keyring.

    Args:
        service_name (str): The unique name for the service.
        user (str): The user key to associate with the token.
    """
    print("Please enter the API token to store securely.")
    try:
        token = getpass.getpass("Enter your Jira API Token: ")
        keyring.set_password(service_name, user, token)
        logger.info(
            f"Token stored successfully for user '{user}' in service "
            f"'{service_name}'."
        )
        logger.info("You will not be prompted for it again on this machine.")
        sys.exit(0)  # Exit after successfully setting the token.
    except keyring.errors.NoKeyringError:
        logger.critical(
            "Could not store token because no `keyring` backend is available."
        )
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Could not store token: {e}")
        sys.exit(1)


# --- Main Execution ---


def main():
    """
    Main function to orchestrate the script execution and user interaction.
    Handles argument parsing, configuration, authentication, and the main UI loop.
    """
    parser = argparse.ArgumentParser(
        description="JASPER: Jira Active Sprint Personal Reporter.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    # Define command-line arguments for configuration and actions.
    parser.add_argument(
        "--config",
        default=None,
        help="Path to the YAML config file. If not provided, searches for "
        "jasper_config.yaml in the current directory, then in $HOME.",
    )
    parser.add_argument(
        "--jira-url",
        dest="jira_url",
        default=None,
        help="Your Jira instance URL (e.g., https://your-domain.atlassian.net)",
    )
    parser.add_argument(
        "--usernames",
        dest="usernames",
        nargs="+",
        default=None,
        help="One or more Jira usernames/account IDs to query for assigned issues.",
    )
    parser.add_argument(
        "--board-ids",
        nargs="+",
        type=int,
        help="A space-separated list of Jira board IDs to check. Overrides config.",
    )
    parser.add_argument(
        "--set-token",
        action="store_true",
        help="Store the Jira API token securely in the system's keyring and exit.",
    )
    parser.add_argument(
        "--no-jasper-attribution",
        action="store_true",
        help="Do not add JASPER attribution to comments.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity level. -v for INFO, -vv for DEBUG.",
    )

    args = parser.parse_args()

    # Initial user-facing message to stdout to show the program has started.
    print("JASPER is starting...")

    # Configure logging based on verbosity level
    if args.verbose == 1:
        log_level = logging.INFO
    elif args.verbose >= 2:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARNING

    handler = logging.StreamHandler(sys.stderr)
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    formatter = ColoredFormatter(log_format, datefmt=date_format)
    handler.setFormatter(formatter)

    # Clear existing handlers and add the new one
    if logger.hasHandlers():
        logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(log_level)

    # Suppress noisy logs from underlying libraries
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    try:
        config, config_path_used = load_config(args.config)
    except Exception:
        # The exception is already logged by the load_config function
        sys.exit(1)
    if config is None:
        config = {}

    if config_path_used:
        logger.info(f"Loaded configuration from: {config_path_used}")
    else:
        logger.warning(
            "No configuration file found. Using command-line arguments only."
        )

    # Prioritize command-line args over config file values.
    jira_url = args.jira_url or config.get("jira_url")
    # Read usernames from config if available, otherwise from command line
    usernames = args.usernames or config.get("usernames")
    if usernames is None:
        usernames = []
    elif isinstance(usernames, str):
        usernames = [usernames]
    board_ids = args.board_ids or config.get("board_ids")

    # Ensure all required configuration is present.
    missing = []
    if not jira_url:
        missing.append("'jira_url'")
    if not usernames:
        missing.append("'usernames'")
    if not board_ids:
        missing.append("'board_ids'")
    if missing:
        logger.critical(f"Missing required configuration: {', '.join(missing)}")
        print(
            "\nProvide these as command-line arguments or in your "
            "jasper_config.yaml file.",
            file=sys.stderr,
        )
        parser.print_help()
        sys.exit(1)

    # Create a unique service name for keyring based on the Jira URL.
    service_name = f"jasper_script:{jira_url.rstrip('/')}"

    # Use a fixed key for the token in the keyring
    keyring_user = "jasper"

    # Handle the --set-token action separately.
    if args.set_token:
        set_api_token(service_name, keyring_user)

    # Authenticate with Jira and get the API token.
    api_token = get_api_token_with_auth_check(service_name, keyring_user, jira_url)

    # Determine if JASPER attribution should be added to comments.
    if args.no_jasper_attribution:
        jasper_attribution = False
    elif "jasper_attribution" in config:
        jasper_attribution = bool(config.get("jasper_attribution"))
    else:
        jasper_attribution = DEFAULT_ATTRIBUTION

    # Fetch initial data: active sprints and issues.
    active_sprints = get_active_sprints(jira_url, api_token, board_ids=board_ids)
    if not active_sprints:
        logger.warning("No active sprints found or an error occurred. Exiting.")
        sys.exit(0)
    logger.info(f"Found {len(active_sprints)} active sprints.")

    # Query issues for all specified usernames and combine results
    issues = get_user_issues_in_sprints(jira_url, api_token, usernames, active_sprints)
    if not issues:
        print(f"\nNo active sprint items found for users: {', '.join(usernames)}")
        sys.exit(0)
    display_issues(issues)

    # --- Main Interaction Loop ---
    while True:
        try:
            choice = input("Enter an issue number to select, (r)efresh, or (q)uit: ")
            if choice.lower() in ("q", "quit"):
                logger.info("Exiting.")
                break

            if choice.lower() in ("r", "refresh"):
                logger.info("Refreshing issue list...")
                issues = get_user_issues_in_sprints(
                    jira_url, api_token, usernames, active_sprints
                )
                display_issues(issues)
                continue

            issue_index = int(choice) - 1
            if not 0 <= issue_index < len(issues):
                print("Invalid number. Please try again.")
                continue

            selected_issue = issues[issue_index]
            issue_key = selected_issue["key"]

            # --- Action Sub-Loop for a selected issue ---
            # Allows the user to perform actions on a selected issue.
            while True:
                print(
                    f"\nSelected: [{issue_key}] {selected_issue['fields']['summary']}"
                )
                action = input(
                    "Action: (c)omment, update (s)tatus, (o)pen in browser, (b)ack to "
                    "list, (q)uit: "
                ).lower()

                if action in ("b", "back"):
                    display_issues(issues)
                    break

                elif action in ("o", "open"):
                    issue_url = f"{jira_url.rstrip('/')}/browse/{issue_key}"
                    webbrowser.open_new_tab(issue_url)
                    logger.info(f"Opening {issue_url} in your browser...")

                elif action in ("c", "comment"):
                    comment = get_multiline_comment()
                    if comment:
                        if jasper_attribution:
                            comment += (
                                "\n\nComment added via JASPER: "
                                "https://github.com/redhat-performance/JASPER"
                            )
                        add_comment_to_issue(jira_url, api_token, issue_key, comment)

                elif action in ("s", "status"):
                    transitions = get_issue_transitions(jira_url, api_token, issue_key)
                    if not transitions:
                        logger.warning(
                            "No available status transitions for this issue."
                        )
                        continue

                    print("\nAvailable Statuses:")

                    def closed_last(transitions):
                        closed = [
                            t for t in transitions if t["name"].lower() == "closed"
                        ]
                        not_closed = [
                            t for t in transitions if t["name"].lower() != "closed"
                        ]
                        return not_closed + closed

                    transitions_sorted = closed_last(transitions)
                    for i, t in enumerate(transitions_sorted):
                        print(f"  {i+1}: {t['name']}")

                    while True:
                        trans_choice = input(
                            "\nEnter the number of the status to change to, or (b)ack, "
                            "or (q)uit: "
                        ).lower()
                        if trans_choice in ("b", "back"):
                            break
                        if trans_choice in ("q", "quit"):
                            logger.info("Exiting.")
                            sys.exit(0)
                        if not trans_choice.strip():
                            # Empty input: re-display the list of available statuses
                            for i, t in enumerate(transitions_sorted):
                                print(f"  {i+1}: {t['name']}")
                            continue

                        try:
                            trans_index = int(trans_choice) - 1
                            if 0 <= trans_index < len(transitions_sorted):
                                transition_id = transitions_sorted[trans_index]["id"]
                                if set_issue_transition(
                                    jira_url, api_token, issue_key, transition_id
                                ):
                                    logger.info(
                                        "Status updated. Refresh to see changes."
                                    )
                                    # Stay in the issue action sub-loop
                            else:
                                print("Invalid transition number.")
                                for i, t in enumerate(transitions_sorted):
                                    print(f"  {i+1}: {t['name']}")
                        except ValueError:
                            print("Invalid input.")
                            for i, t in enumerate(transitions_sorted):
                                print(f"  {i+1}: {t['name']}")

                elif action in ("q", "quit"):
                    logger.info("Exiting.")
                    sys.exit(0)
                else:
                    print("Invalid action. Please choose from the options.")
        except ValueError:
            print("Invalid input. Please enter a number, 'r', or 'q'.")
        except (EOFError, KeyboardInterrupt):
            # Gracefully handle Ctrl+C or Ctrl+D to exit the script.
            print("\nExiting.")
            break


# This ensures the main() function is called only when the script is executed directly.
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
