# JASPER: Jira Active Sprint Personal Reporter

JASPER is a command-line tool to help you track and manage your assigned Jira issues in
active sprints. It supports listing issues, adding comments, changing issue status, and
opening issues in a web browser. Configuration is handled via a YAML file, and API
tokens are stored securely using the system keyring.

---

## Configuration

Create a `config.yaml` file in the same directory as `jasper.py` (or specify with
`--config`). Example:

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

- `--config`: Path to the YAML config file (default: `config.yaml`)
- `--jira-url`: Your Jira instance URL (overrides config)
- `--usernames`: One or more Jira usernames/account IDs to query for assigned issues
  (overrides config)
- `--board-ids`: Space-separated list of Jira board IDs to check (overrides config)
- `--set-token`: Store the Jira API token securely in the system's keyring and exit
- `--no-jasper-attribution`: Do not add JASPER attribution to comments (overrides config)
- `--help`: Show all options

---

## JASPER Attribution in Comments

By default, JASPER will append the following plain text attribution to each comment it
adds:

```
Comment added via JASPER: https://github.com/redhat-performance/JASPER
```

You can disable this globally by setting `jasper_attribution: false` in your
`config.yaml` or by passing the `--no-jasper-attribution` flag on the command line.

**Note:**  
Jira Data Center comments do **not** support Markdown or HTML formatting via the REST
API. Links and formatting will appear as plain text.

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

## License

Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.

---

For more information, see
[https://github.com/redhat-performance/JASPER](https://github.com/redhat-performance/JASPER)
