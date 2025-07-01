#!/usr/bin/env python3
"""
JASPER: Jira Active Sprint Personal Reporter

This script interacts with the Jira REST API to help users track and manage their
assigned issues in active sprints. It supports listing issues, adding comments,
changing issue status, and opening issues in a web browser. Configuration is
handled via a YAML file and API tokens are stored securely using the system keyring.

This version includes an optional integration with Google's Gemini AI for real-time
comment suggestions.

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
import logging
import getpass
import sys
import os
import webbrowser
import time
import requests
from typing import Callable, Any, Dict, List, Tuple, Optional
import yaml
import keyring
import keyring.errors
import yaml.parser
import asyncio
import google.generativeai as genai
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggest, Suggestion
from prompt_toolkit.patch_stdout import patch_stdout

# Initialize logger
logger = logging.getLogger("JASPER")

DEFAULT_ATTRIBUTION = True
DEFAULT_GEMINI_MODEL = "gemini-1.5-flash"


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

    def __init__(self, fmt: str, datefmt: Optional[str] = None):
        super().__init__(fmt, datefmt)
        self.FORMATS = {
            logging.DEBUG: self.GREY + fmt + self.RESET,
            logging.INFO: self.GREEN + fmt + self.RESET,
            logging.WARNING: self.YELLOW + fmt + self.RESET,
            logging.ERROR: self.RED + fmt + self.RESET,
            logging.CRITICAL: self.BOLD_RED + fmt + self.RESET,
        }

    def format(self, record: logging.LogRecord) -> str:
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt=self.datefmt)
        return formatter.format(record)


# --- Jira API Functions ---


def jira_query(
    base_url: str,
    api_path: str,
    api_token: str,
    method: Callable = requests.get,
    json_payload: Optional[Dict[str, Any]] = None,
    max_retries: int = 3,
    retry_delay: int = 2,
) -> Optional[requests.Response]:
    """
    Executes a JQL query against the Jira REST API.

    Args:
        base_url: The base URL of the Jira instance.
        api_path: The API path to use for the query.
        api_token: The API token for authentication.
        method: The HTTP requests() method to use.
        json_payload: Optional JSON payload to send with the request.
        max_retries: Number of retries for transient errors.
        retry_delay: Delay in seconds between retries.

    Returns:
        A requests.Response object on success, or None on failure after retries.
    """
    query_url = f"{base_url}{api_path}"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
    }
    if json_payload:
        headers["Content-Type"] = "application/json"

    attempt = 0
    while attempt < max_retries:
        try:
            response = method(
                query_url, headers=headers, data=json.dumps(json_payload), timeout=30
            )
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", retry_delay))
                logger.warning(
                    "Rate limited by Jira API (HTTP 429)."
                    f"Retrying after {retry_after}s..."
                )
                time.sleep(retry_after)
                attempt += 1
                continue
            return response
        except requests.exceptions.RequestException as e:
            attempt += 1
            if attempt < max_retries:
                logger.warning(
                    f"Error executing JQL query (attempt {attempt}/{max_retries}). "
                    f"Retrying in {retry_delay}s. Error: {e}"
                )
                time.sleep(retry_delay)
            else:
                logger.error(f"Failed to query Jira after {max_retries} attempts: {e}")
                raise
    return None


def check_jira_auth(base_url: str, api_token: str) -> bool:
    """
    Check if the provided Jira credentials are valid using Bearer token.

    Args:
        base_url: The Jira instance URL.
        api_token: The API token for authentication.

    Returns:
        True if authentication is successful, False otherwise.
    """
    test_api_path = "/rest/api/2/myself"
    try:
        test_response = jira_query(base_url, test_api_path, api_token)
        if test_response and test_response.status_code == 200:
            return True
        if test_response:
            logger.warning(
                f"Authentication failed: {test_response.status_code} "
                f"{test_response.reason}"
            )
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Error connecting to Jira: {e}")
        return False


def get_active_sprints(base_url: str, api_token: str, board_ids: List[int]) -> List[int]:
    """
    Fetches active sprints from specified boards.

    Args:
        base_url: The base URL of the Jira instance.
        api_token: The API token for authentication.
        board_ids: List of Jira board IDs to check.

    Returns:
        A list of active sprint IDs, or an empty list on failure.
    """
    if not board_ids:
        raise ValueError("board_ids is required for get_active_sprints()")
    active_sprint_ids = []

    logger.info(f"Checking specified board IDs: {board_ids}")
    
    for board_id in board_ids:
        try:
            sprint_api_path = f"/rest/agile/1.0/board/{board_id}/sprint?state=active"
            sprint_response = jira_query(base_url, sprint_api_path, api_token)
            if sprint_response:
                sprint_response.raise_for_status()
                sprints = sprint_response.json().get("values", [])
                for sprint in sprints:
                    if sprint.get("id") not in active_sprint_ids:
                        active_sprint_ids.append(sprint["id"])
                        logger.info(
                            f"Found active sprint: {sprint['name']} (ID: {sprint['id']}) "
                            f"on board ID {board_id}"
                        )
        except requests.exceptions.RequestException as e:
            logger.error(f"Could not fetch sprints for board ID {board_id}: {e}")
    return active_sprint_ids


def get_user_issues_in_sprints(base_url: str, api_token: str, usernames: List[str], sprint_ids: List[int]) -> List[Dict[str, Any]]:
    """
    Searches for issues assigned to one or more users within a list of sprints.

    Args:
        base_url: The base URL of the Jira instance.
        api_token: The API token for authentication.
        usernames: List of Jira Account IDs or usernames.
        sprint_ids: A list of sprint IDs to search within.

    Returns:
        A list of issue dictionaries, or an empty list on failure.
    """
    if not sprint_ids or not usernames:
        return []

    search_api_path = "/rest/api/2/search"
    sprint_id_string = ", ".join(map(str, sprint_ids))
    
    assignee_jql = (
        f'assignee = "{usernames[0]}"'
        if len(usernames) == 1
        else f'assignee in ({", ".join(f'"{u}"' for u in usernames)})'
    )
    jql = f"{assignee_jql} AND sprint in ({sprint_id_string}) ORDER BY updated DESC"

    payload = {
        "jql": jql,
        "fields": ["summary", "status", "issuetype", "priority", "labels", "assignee"],
        "maxResults": 100,
    }

    logger.info("Querying for issues with JQL...")
    logger.debug(f"  > {jql}")

    try:
        search_response = jira_query(
            base_url,
            search_api_path,
            api_token,
            method=requests.post,
            json_payload=payload,
        )
        if not search_response:
            return []
            
        search_response.raise_for_status()
        issues = search_response.json().get("issues", [])
        # Annotate each issue with the assignee for clarity
        for issue in issues:
            assignee = issue["fields"].get("assignee")
            issue["_jasper_assignee"] = (
                assignee.get("name") or assignee.get("displayName") or assignee.get("accountId", "")
            ) if assignee else ""
        return issues
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching issues: {e}")
        if hasattr(e, "response") and e.response is not None:
            logger.debug(f"Response Body: {e.response.text}")
        return []


def get_issue_details_and_comments(base_url: str, api_token: str, issue_key: str) -> Tuple[Optional[Dict[str, Any]], Optional[List[Dict[str, Any]]]]:
    """
    Fetches full details and all comments for a single Jira issue.

    Args:
        base_url: The base URL of the Jira instance.
        api_token: The API token for authentication.
        issue_key: The key of the issue.

    Returns:
        A tuple containing the issue details dictionary and a list of comment
        dictionaries. Returns (None, None) on error.
    """
    details_api_path = f"/rest/api/2/issue/{issue_key}?fields=summary,description"
    comments_api_path = f"/rest/api/2/issue/{issue_key}/comment"

    try:
        details_response = jira_query(base_url, details_api_path, api_token)
        if not details_response: return None, None
        details_response.raise_for_status()
        issue_details = details_response.json()

        comments_response = jira_query(base_url, comments_api_path, api_token)
        if not comments_response: return issue_details, None
        comments_response.raise_for_status()
        comments = comments_response.json().get("comments", [])

        return issue_details, comments
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching issue details for {issue_key}: {e}")
        return None, None


def add_comment_to_issue(base_url: str, api_token: str, issue_key: str, comment_body: str) -> bool:
    """
    Adds a plain text comment to a Jira issue.

    Args:
        base_url: The base URL of the Jira instance.
        api_token: The API token for authentication.
        issue_key: The key of the issue to comment on.
        comment_body: The text of the comment to add.

    Returns:
        True if the comment was added successfully, False otherwise.
    """
    comment_api_path = f"/rest/api/2/issue/{issue_key}/comment"
    payload = {"body": comment_body}
    logger.info(f"Adding comment to issue {issue_key}...")

    try:
        comment_response = jira_query(
            base_url,
            comment_api_path,
            api_token,
            method=requests.post,
            json_payload=payload,
        )
        if comment_response:
            comment_response.raise_for_status()
            if comment_response.status_code == 201:
                logger.info("Comment added successfully.")
                return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Error adding comment: {e}")
        if hasattr(e, "response") and e.response is not None:
            logger.debug(f"Response Body: {e.response.text}")
    return False


def get_issue_transitions(base_url: str, api_token: str, issue_key: str) -> List[Dict[str, Any]]:
    """
    Gets available status transitions for a Jira issue.

    Args:
        base_url: The base URL of the Jira instance.
        api_token: The API token for authentication.
        issue_key: The key of the issue.

    Returns:
        A list of available transition dictionaries.
    """
    transitions_api_path = f"/rest/api/2/issue/{issue_key}/transitions"
    try:
        transitions_response = jira_query(base_url, transitions_api_path, api_token)
        if transitions_response:
            transitions_response.raise_for_status()
            return transitions_response.json().get("transitions", [])
    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting transitions for {issue_key}: {e}")
    return []


def set_issue_transition(base_url: str, api_token: str, issue_key: str, transition_id: str) -> bool:
    """
    Changes the status of a Jira issue by posting a transition ID.

    Args:
        base_url: The base URL of the Jira instance.
        api_token: The API token for authentication.
        issue_key: The key of the issue.
        transition_id: The ID of the desired status transition.

    Returns:
        True if successful, False otherwise.
    """
    transitions_api_path = f"/rest/api/2/issue/{issue_key}/transitions"
    payload = {"transition": {"id": transition_id}}

    try:
        transitions_response = jira_query(
            base_url,
            transitions_api_path,
            api_token,
            method=requests.post,
            json_payload=payload,
        )
        if transitions_response:
            transitions_response.raise_for_status()
            if transitions_response.status_code == 204:
                logger.info(f"Issue {issue_key} status changed successfully.")
                return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Error changing status for {issue_key}: {e}")
        if hasattr(e, "response") and e.response is not None:
            logger.debug(f"Response Body: {e.response.text}")
    return False


# --- Gemini AI Functions ---

def check_gemini_auth(api_key: str, model_name: str) -> bool:
    """
    Checks if the provided Gemini API key is valid by making a small,
    authenticated API call.

    Args:
        api_key: The Gemini API key.
        model_name: The Gemini model to use for validation.

    Returns:
        True if the key is valid, False otherwise.
    """
    if not api_key:
        return False
    try:
        logger.debug(f"Attempting to validate Gemini API key with model '{model_name}'...")
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)
        model.generate_content("test", generation_config={"max_output_tokens": 1})
        logger.info("Gemini API key is valid.")
        return True
    except Exception as e:
        logger.warning(
            "Gemini API key validation failed. AI features will be disabled."
        )
        logger.debug(f"Gemini validation error: {e}")
        return False


def get_gemini_suggestion(api_key: str, model_name: str, issue_details: Dict[str, Any], comments: List[Dict[str, Any]], partial_comment: str) -> Optional[str]:
    """
    Gets a comment suggestion from the Gemini API.

    Args:
        api_key: The Gemini API key.
        model_name: The Gemini model to use.
        issue_details: The details of the Jira issue.
        comments: A list of existing comments on the issue.
        partial_comment: The user's partially typed comment.

    Returns:
        The suggested comment text, or None on error.
    """
    if not partial_comment.strip():
        return None  # Don't suggest for empty input

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)

        prompt = (
            "You are a helpful assistant for writing Jira comments. "
            "Based on the following Jira issue, please complete the user's comment. "
            "Keep the suggestion concise and relevant.\n\n"
            f"Issue Key: {issue_details['key']}\n"
            f"Summary: {issue_details['fields']['summary']}\n"
        )
        if issue_details["fields"].get("description"):
            prompt += f"Description: {issue_details['fields']['description']}\n\n"

        if comments:
            prompt += "--- Existing Comments ---\n"
            for comment in comments:
                author = comment.get("author", {}).get("displayName", "Unknown")
                body = comment.get("body", "")
                prompt += f"Author: {author}\nComment: {body}\n---\n"

        prompt += "\n--- New Comment ---\n"
        prompt += f"User's partial comment: '{partial_comment}'\n\n"
        prompt += "Your suggested completion:"

        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        logger.error(f"Error getting suggestion from Gemini: {e}")
        return None


# --- UI & Interaction Functions ---


def display_issues(issues: List[Dict[str, Any]]):
    """
    Prints a numbered list of issues to the console with key details and a direct URL.

    Args:
        issues: List of Jira issue dictionaries.
    """
    print("\n--- Active Sprint Items ---")
    for i, issue in enumerate(issues):
        key = issue["key"]
        fields = issue["fields"]
        summary = fields.get("summary", "No summary")
        status = fields.get("status", {}).get("name", "N/A")
        priority_name = fields.get("priority", {}).get("name", "N/A")
        assignee = issue.get("_jasper_assignee", "Unassigned")
        
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


class GeminiSuggester(AutoSuggest):
    """
    An auto-suggester that fetches suggestions from the Gemini API asynchronously.
    """

    def __init__(self, base_url: str, api_token: str, issue_key: str, gemini_config: Dict[str, Any]):
        self.base_url = base_url
        self.api_token = api_token
        self.issue_key = issue_key
        self.gemini_config = gemini_config
        self.issue_details: Optional[Dict[str, Any]] = None
        self.comments: Optional[List[Dict[str, Any]]] = None

    async def get_suggestion_async(self, session: PromptSession, buffer: Any) -> Optional[Suggestion]:
        await asyncio.sleep(0.5)  # Debounce

        if buffer.text != session.default_buffer.text:
            return None

        if not self.issue_details:
            logger.info("Fetching issue context for Gemini...")
            self.issue_details, self.comments = await asyncio.to_thread(
                get_issue_details_and_comments, self.base_url, self.api_token, self.issue_key
            )

        if not self.issue_details or self.comments is None:
            return None

        logger.info("Getting Gemini suggestion...")
        suggestion_text = await asyncio.to_thread(
            get_gemini_suggestion,
            self.gemini_config["api_key"],
            self.gemini_config["model_name"],
            self.issue_details,
            self.comments,
            buffer.text,
        )

        if suggestion_text and suggestion_text.lower().strip() != buffer.text.lower().strip():
            if suggestion_text.lower().startswith(buffer.text.lower()):
                return Suggestion(suggestion_text[len(buffer.text):])
        return None

    def get_suggestion(self, buffer: Any, document: Any) -> Optional[Suggestion]:
        return None


async def get_multiline_comment_async(base_url: str, api_token: str, issue_key: str, gemini_config: Dict[str, Any]) -> Optional[str]:
    """
    Gets multi-line input using prompt_toolkit with live Gemini suggestions if enabled and valid.
    """
    use_gemini = gemini_config.get("enabled") and gemini_config.get("is_valid")

    if use_gemini:
        print(
            "Enter your comment. A suggestion will appear as you type.\n"
            "Press Tab to accept. To submit, press Esc and then Enter."
        )
        suggester: Optional[GeminiSuggester] = GeminiSuggester(base_url, api_token, issue_key, gemini_config)
    else:
        print("Enter your comment. To submit, press Esc and then Enter.")
        suggester = None
        
    session = PromptSession(
        "Comment: ",
        multiline=True,
        auto_suggest=suggester,
        history=InMemoryHistory(),
    )

    with patch_stdout():
        try:
            return await session.prompt_async()
        except (EOFError, KeyboardInterrupt):
            print("\nComment cancelled.")
            return None


# --- Configuration & Token Management ---


def load_config(config_path: Optional[str]) -> Tuple[Dict[str, Any], str]:
    """
    Loads configuration from a YAML file.

    Args:
        config_path: Optional path to a specific config file.

    Returns:
        A tuple containing the configuration dictionary and the path of the loaded file.
    
    Raises:
        FileNotFoundError: If no configuration file can be found.
        yaml.YAMLError: If the configuration file is invalid.
    """
    if config_path:
        search_paths = [config_path]
    else:
        search_paths = [
            os.path.join(os.getcwd(), "jasper_config.yaml"),
            os.path.join(os.path.expanduser("~"), "jasper_config.yaml"),
        ]

    found_path = next((path for path in search_paths if os.path.exists(path)), None)

    if not found_path:
        raise FileNotFoundError(
            f"No configuration file found at the specified path: {config_path}"
            if config_path
            else "No configuration file found in ./ or ~/"
        )

    try:
        logger.info(f"Loading configuration from: {found_path}")
        with open(found_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
        logger.info("Configuration loaded successfully.")
        return config, found_path
    except (yaml.YAMLError, IOError) as e:
        logger.critical(f"Error reading or parsing config file {found_path}: {e}")
        raise


def get_api_token(
    service_name: str,
    user: str,
    friendly_name: str,
    validation_func: Callable[[str], bool],
) -> str:
    """
    Generic function to get an API token from keyring or prompt the user.

    Args:
        service_name: The unique name for the service storing the password.
        user: The key used for storing/retrieving the token.
        friendly_name: A user-friendly name for the token type.
        validation_func: A function to validate the token.

    Returns:
        The retrieved or entered API token.
    
    Raises:
        Exception: If a stored token is invalid or if a token cannot be obtained.
    """
    from_keyring = False
    keyring_available = True
    while True:
        token = None
        try:
            token = keyring.get_password(service_name, user)
            if token:
                from_keyring = True
                logger.info(f"{friendly_name} found in secure storage.")
        except keyring.errors.NoKeyringError:
            logger.warning(
                f"Keyring backend not found for '{service_name}'. For secure storage, "
                "please install a backend (e.g., 'pip install keyrings.cryptfile')"
            )
            keyring_available = False
        except Exception as e:
            logger.error(f"An unexpected error occurred with keyring for '{service_name}': {e}")
            keyring_available = False

        if not token:
            logger.warning(f"{friendly_name} not found in storage.")
            try:
                token = set_api_token(service_name, user, friendly_name, keyring_available)
            except (EOFError, KeyboardInterrupt):
                raise Exception(f"Could not read {friendly_name}.")

        if validation_func(token):
            return token
        
        if from_keyring:
            raise Exception(
                f"Stored {friendly_name} is invalid. Please reset it using the "
                f"appropriate --set-...-token flag or manually in your keyring."
            )
        logger.warning(f"Invalid {friendly_name}. Please try again.\n")


def set_api_token(service_name: str, user: str, friendly_name: str, keyring_available: bool, interactive: bool = True) -> str:
    """
    Prompts user for an API token and optionally stores it in the system's keyring.

    Args:
        service_name: The unique name for the service.
        user: The user key to associate with the token.
        friendly_name: A user-friendly name for the token type.
        keyring_available: Whether a keyring backend is available for storage.
        interactive: Whether to prompt for storing the token.
    
    Returns:
        The entered token.
    """
    print(f"Please enter your {friendly_name}.")
    try:
        token = getpass.getpass(f"Enter {friendly_name}: ")
        if not keyring_available:
            logger.info("Token will not be stored as no keyring backend is available.")
            return token

        if interactive:
            store = input("Store this token in your system keyring? (Y/n): ").strip().lower()
        else:
            store = "y"

        if store in ("", "y", "yes"):
            keyring.set_password(service_name, user, token)
            logger.info(f"Token stored successfully for '{user}' in service '{service_name}'.")
        else:
            logger.info("Token will not be stored.")
        return token
    except (EOFError, KeyboardInterrupt) as e:
        print("\nToken entry cancelled.")
        raise e


# --- Main Application Logic ---

def setup_logging(verbosity: int):
    """Configures logging based on the verbosity level."""
    if verbosity == 1:
        log_level = logging.INFO
    elif verbosity >= 2:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARNING

    handler = logging.StreamHandler(sys.stderr)
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    formatter = ColoredFormatter(log_format, datefmt=date_format)
    handler.setFormatter(formatter)

    if logger.hasHandlers():
        logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(log_level)

    # Suppress noisy logs from underlying libraries
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("prompt_toolkit").setLevel(logging.WARNING)


def handle_token_actions(args: argparse.Namespace, jira_service_name: str, gemini_service_name: str):
    """Handles --set-token and --set-gemini-token actions and exits."""
    if args.set_token:
        if not args.jira_url:
            logger.critical("Cannot --set-token without a --jira-url or jira_url in config.")
            sys.exit(1)
        try:
            set_api_token(jira_service_name, "jasper", "Jira API Token", True, False)
            print("Jira API token stored successfully.")
            sys.exit(0)
        except (EOFError, KeyboardInterrupt):
            sys.exit(1)
        except Exception as e:
            logger.critical(f"Failed to set Jira API token: {e}")
            sys.exit(1)

    if args.set_gemini_token:
        try:
            set_api_token(gemini_service_name, "gemini_api_key", "Gemini API Key", True, False)
            print("Gemini API key stored successfully.")
            sys.exit(0)
        except (EOFError, KeyboardInterrupt):
            sys.exit(1)
        except Exception as e:
            logger.critical(f"Failed to set Gemini API key: {e}")
            sys.exit(1)


def process_issue_actions(issue: Dict[str, Any], jira_url: str, api_token: str, gemini_config: Dict[str, Any], jasper_attribution: bool):
    """
    Handles the user interaction loop for a single selected issue.
    """
    issue_key = issue["key"]
    while True:
        print(f"\nSelected: [{issue_key}] {issue['fields']['summary']}")
        action = input(
            "Action: (c)omment, update (s)tatus, (o)pen in browser, (b)ack to list, (q)uit: "
        ).lower()

        if action in ("q", "quit"):
            logger.info("Exiting.")
            sys.exit(0)
        elif action in ("b", "back"):
            return
        elif action in ("o", "open"):
            issue_url = f"{jira_url.rstrip('/')}/browse/{issue_key}"
            webbrowser.open_new_tab(issue_url)
            logger.info(f"Opening {issue_url} in your browser...")
        elif action in ("c", "comment"):
            try:
                comment = asyncio.run(
                    get_multiline_comment_async(jira_url, api_token, issue_key, gemini_config)
                )
                if comment:
                    if gemini_config.get("is_valid"):
                        model_name = gemini_config.get("model_name", DEFAULT_GEMINI_MODEL)
                        comment += f"\n\n_Comment assisted by Gemini ({model_name})._"
                    if jasper_attribution:
                        comment += "\n\nComment added via JASPER: https://github.com/redhat-performance/JASPER"
                    add_comment_to_issue(jira_url, api_token, issue_key, comment)
            except Exception as e:
                logger.error(f"Failed to get comment: {e}")
        elif action in ("s", "status"):
            process_status_update(issue_key, jira_url, api_token)
        else:
            print("Invalid action. Please choose from the options.")


def process_status_update(issue_key: str, jira_url: str, api_token: str):
    """Handles the logic for updating an issue's status."""
    print("Getting available statuses...")
    transitions = get_issue_transitions(jira_url, api_token, issue_key)
    if not transitions:
        logger.warning("No available status transitions for this issue.")
        return

    # Sort transitions to put "Closed" last
    transitions.sort(key=lambda t: t["name"].lower() == "closed")

    while True:
        print("\nAvailable Statuses:")
        for i, t in enumerate(transitions):
            print(f"  {i+1}: {t['name']}")
        
        trans_choice = input("\nEnter the number of the status to change to, or (b)ack: ").lower()
        if trans_choice in ("b", "back"):
            break
        
        try:
            trans_index = int(trans_choice) - 1
            if 0 <= trans_index < len(transitions):
                transition_id = transitions[trans_index]["id"]
                if set_issue_transition(jira_url, api_token, issue_key, transition_id):
                    print("Status updated. Refresh to see changes.\n")
                    break
            else:
                print("Invalid transition number.")
        except ValueError:
            print("Invalid input. Please enter a number.")


def main():
    """
    Main function to orchestrate the script execution and user interaction.
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
        "--set-gemini-token",
        action="store_true",
        help="Store the Gemini API key securely in the system's keyring and exit.",
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
    print("JASPER is starting...")
    setup_logging(args.verbose)

    try:
        config, _ = load_config(args.config)
    except Exception as e:
        logger.critical(f"Failed to initialize: {e}")
        sys.exit(1)

    jira_url = args.jira_url or config.get("jira_url")
    if not jira_url:
        logger.critical("Missing required configuration: 'jira_url'")
        sys.exit(1)

    jira_service_name = f"jasper_script:{jira_url.rstrip('/')}"
    gemini_service_name = "jasper_gemini"

    handle_token_actions(args, jira_service_name, gemini_service_name)

    usernames = args.usernames or config.get("usernames", [])
    board_ids = args.board_ids or config.get("board_ids", [])
    
    if not usernames or not board_ids:
        logger.critical("Missing required configuration: 'usernames' and/or 'board_ids'")
        sys.exit(1)

    try:
        api_token = get_api_token(
            jira_service_name, "jasper", "Jira API Token",
            lambda token: check_jira_auth(base_url=jira_url, api_token=token)
        )
    except Exception as e:
        logger.critical(f"Failed to authenticate with Jira: {e}")
        sys.exit(1)

    gemini_enabled = config.get("enable_gemini", False)
    gemini_config = {"enabled": gemini_enabled, "is_valid": False}
    if gemini_enabled:
        logger.info("Gemini AI is enabled in config. Checking for API key...")
        model_name = config.get("gemini", {}).get("model_name", DEFAULT_GEMINI_MODEL)
        gemini_config["model_name"] = model_name
        try:
            gemini_api_key = get_api_token(
                gemini_service_name, "gemini_api_key", "Gemini API Key",
                lambda token: check_gemini_auth(api_key=token, model_name=model_name)
            )
            gemini_config["api_key"] = gemini_api_key
            gemini_config["is_valid"] = True
        except Exception as e:
            logger.warning(f"Could not get a valid Gemini API key. Disabling AI features. Error: {e}")
            gemini_config["enabled"] = False
    else:
        logger.info("Gemini AI is disabled in config.")

    jasper_attribution = not args.no_jasper_attribution and config.get("jasper_attribution", DEFAULT_ATTRIBUTION)

    active_sprints = get_active_sprints(jira_url, api_token, board_ids)
    if not active_sprints:
        logger.error("No active sprints found or an error occurred. Exiting.")
        sys.exit(2)
    logger.info(f"Found {len(active_sprints)} active sprints.")

    issues = get_user_issues_in_sprints(jira_url, api_token, usernames, active_sprints)
    if not issues:
        print(f"\nNo active sprint items found for users: {', '.join(usernames)}. Exiting.")
        sys.exit(2)
    
    # --- Main Interaction Loop ---
    while True:
        display_issues(issues)
        try:
            choice = input("Enter an issue number to select, (r)efresh, or (q)uit: ")
            if choice.lower() in ("q", "quit"):
                break
            if choice.lower() in ("r", "refresh"):
                logger.info("Refreshing issue list...")
                issues = get_user_issues_in_sprints(jira_url, api_token, usernames, active_sprints)
                if not issues:
                    print(f"\nNo active sprint items found for users: {', '.join(usernames)}. Exiting.")
                    sys.exit(2)
                continue

            issue_index = int(choice) - 1
            if not 0 <= issue_index < len(issues):
                print("Invalid number. Please try again.")
                continue

            process_issue_actions(issues[issue_index], jira_url, api_token, gemini_config, jasper_attribution)

        except ValueError:
            print("Invalid input. Please enter a number, 'r', or 'q'.")
        except (EOFError, KeyboardInterrupt):
            break

    print("\nExiting.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
