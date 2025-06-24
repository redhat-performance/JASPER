# JASPER: Jira Active Sprint Personal Reporter

JASPER is a command-line tool to help you track and manage your assigned Jira issues in
active sprints. It supports listing issues, adding comments, changing issue status, and
opening issues in a web browser. Configuration is handled via a YAML file, and API
tokens are stored securely using the system keyring.

---

## Python Requirements

JASPER requires Python 3.7 or newer.

To install JASPER as a module, run the following commands from the project root:

```sh
python3 -m ensurepip
pip install .
```

Once installed, you can run JASPER from anywhere using the Python module syntax:

```sh
python3 -m jasper
```

Or simply as:

```sh
jasper
```

---

## Configuration

Create a `jasper_config.yaml` file in your current directory or in your user home
directory (or you can specify a file location with `--config`). Example:

```yaml
# Your full Jira instance URL
jira_url: "https://your-company.atlassian.net"

# One or more Jira usernames/account IDs to query for assigned issues
usernames:
  - "user1"
  - "user2"

# A list of board IDs to search within.
# To find board IDs: In Jira, open your board in the browser. The board ID is the
# number in the URL after "rapidView=" (e.g., ...RapidBoard.jspa?rapidView=42).
board_ids:
  - 10
  - 25
  - 42

# Set to false to disable JASPER attribution in comments
jasper_attribution: true
```

---

## Command-Line Arguments

- `--config`: Path to the YAML config file (default: `jasper_config.yaml`)
- `--jira-url`: Your Jira instance URL (overrides config)
- `--usernames`: One or more Jira usernames/account IDs to query for assigned issues
  (overrides config)
- `--board-ids`: Space-separated list of Jira board IDs to check (overrides config)
- `--set-token`: Store the Jira API token securely in the system's keyring and exit
- `--no-jasper-attribution`: Do not add JASPER attribution to comments (overrides config)
- `--help`: Show all options

---

## Usage

By default, JASPER will look for a `jasper_config.yaml` file in your current directory.
If not found, it will look in your home directory. You can also specify a config file
explicitly:

```sh
jasper --config /path/to/jasper_config.yaml
```

Or, to specify options on the command line (these will override config file options):

```sh
jasper --jira-url "https://your-company.atlassian.net" \
  --usernames user1 user2 \
  --board-ids 10 25 42
```

After starting JASPER, you will see a numbered list of your active sprint issues.

You can interact with the tool using the following options:

- **Select an issue:**  
  Enter the number of an issue to select it for further actions.

- **(r)efresh the issue list:**  
  Enter `r` or `refresh` to reload the list of issues.

- **(q)uit:**  
  Enter `q` or `quit` to exit the program.

```console
API token found in secure storage.
API authentication successful.
Checking specified board IDs: [12345]
Found 1 boards. Looking for active sprints...

Found 1 active sprints.

Querying for issues with JQL:
  > assignee in ("foo@example.com", "bar@example.com") AND sprint in (7890) ORDER BY updated DESC

--- Active Sprint Items ---
  1: [PROJECT-7760] Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed accumsan porta sem. (Status: In Progress, Priority: Normal) (Assignee: bar@example.com)
      URL: https://your-company.atlassian.net/browse/PROJECT-7760
  2: [PROJECT-29981] Phasellus malesuada aliquet lacus a pharetra. Aliquam erat volutpat. (Status: In Progress, Priority: Critical) (Assignee: foo@example.com)
      URL: https://your-company.atlassian.net/browse/PROJECT-29981
  3: [PROJECT-27400] Etiam turpis lacus, vestibulum ac mauris et, pellentesque bibendum ante. (Status: New, Priority: Major) (Assignee: foo@example.com)
      URL: https://your-company.atlassian.net/browse/PROJECT-27400
  4: [PROJECT-30477] Suspendisse egestas risus id ligula facilisis pharetra. (Status: In Progress, Priority: Undefined) (Assignee: bar@example.com)
      URL: https://your-company.atlassian.net/browse/PROJECT-30477
---------------------------

Enter an issue number to select, (r)efresh, or (q)uit: 
```

When you select an issue, you will be prompted with additional actions:

- **(c)omment:**  
  Add a comment to the selected issue. You can enter a multi-line comment, ending with
  a new line and Ctrl+D (Linux/macOS) or Ctrl+Z then Enter (Windows).

- **Update (s)tatus:**  
  Change the status of the selected issue. You will be shown available transitions and
  can select one by number.

- **(o)pen in browser:**  
  Open the selected issue in your default web browser.

- **(b)ack to list:**  
  Return to the main issue list.

- **(q)uit:**  
  Exit the program from the issue action menu.

```console
Selected: [PROJECT-7760] Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed accumsan porta sem.
Action: (c)omment, update (s)tatus, (o)pen in browser, (b)ack to list, (q)uit: 
```

> [!NOTE]
> Jira Data Center comments do **not** support Markdown or HTML formatting via the REST
> API. Links and formatting will appear as plain text.

---

## JASPER Attribution in Comments

By default, JASPER will append the following plain text attribution to each comment it
adds:

```
Comment added via JASPER: https://github.com/redhat-performance/JASPER
```

You can disable this globally by setting `jasper_attribution: false` in your
`config.yaml` or by passing the `--no-jasper-attribution` flag on the command line.

---

## Authentication & API Token Storage

JASPER uses a Jira API token for authentication. The token is stored securely using
your system keyring. The keyring entry is scoped to your Jira instance and a fixed key
("jasper"), so only one token per Jira instance is stored.

- If no token is found in the keyring, you will be prompted to enter one.
- You will be asked if you want to store the token in your keyring for future use.

> [!NOTE]
> To create a Jira API token, go to your Jira Data Center profile and look for
> "Personal Access Tokens" under your profile or account settings.  
> For example, visit:  
> `https://your-jira.example.com/secure/ViewProfile.jspa?selectedTab=com.atlassian.pats.pats-plugin:jira-user-personal-access-tokens`  
> If you do not see this option, contact your Jira administrator.

---

## Finding Your Jira Information

- **Jira Username or Account ID (`usernames`)**:
    - For Jira Data Center, this is typically your Jira login username (not necessarily 
      your email).
    - You can find your username by clicking your profile/avatar in the top right and
      selecting "Profile" or "Profile and Visibility."
    - Your username is often shown in the URL or in your profile details.
    - If unsure, ask your Jira administrator or check the "Assigned to" field on an
      issue you are assigned to.

- **Jira Board ID (`board_ids`)**:
    - Navigate to the Jira board you are interested in.
    - The URL will be similar to
      `https://your-jira.example.com/secure/RapidBoard.jspa?rapidView={BOARD_ID}`.
    - The `BOARD_ID` is the number after `rapidView=` in the URL.
    - If unsure, ask your Jira administrator or check the board settings in Jira.

---

## AI Notes

This project was developed with the assistance of Gemini 2.5 Pro and Copilot/GPT-4.1.

---

## License

Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.

---

For more information, see
[https://github.com/redhat-performance/JASPER](https://github.com/redhat-performance/JASPER)
