
# JASPER: Jira Active Sprint PErsonal Reporter

JASPER is a command-line tool to help you track and manage your assigned Jira issues in
active sprints. It supports listing issues, adding comments, changing issue status, and
opening issues in a web browser. Configuration is handled via a YAML file, and API
tokens are stored securely using the system keyring.

<p align="center">
  <img src="jasper-demo.gif" alt="JASPER demo" width="700"><br>
  <i>Demo created with <a href="https://asciinema.org/a/727294">asciinema</a></i>
</p>

---

## Installation

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

Or, if your python scripts directory is in your default execution path, simply as:

```sh
jasper
```

> [!TIP]
> On a Linux system, you may need `${HOME}/.local/bin` in your `$PATH` in order to
> execute the module directly without the `python -m` command.
> ```sh
> export PATH="$HOME/.local/bin:$PATH"
> ```

---

## Configuration

Create a `jasper_config.yaml` file in your current directory or in your user home
directory (or you can specify a file location with `--config`). Example:

```yaml
# Your full Jira Cloud instance URL
jira_url: "https://your-company.atlassian.net"

# Your Atlassian account email (used for API authentication)
auth_email: "your.email@example.com"

# One or more Jira email addresses or account IDs to query for assigned issues
usernames:
  - "your.email@example.com"

# A list of board IDs to search within.
# To find board IDs: In Jira, open your board in the browser. The board ID is the
# number in the URL (e.g., ...rapidView=42 or .../board/42).
board_ids:
  - 10
  - 25
  - 42

# Set to false to disable JASPER attribution in comments
jasper_attribution: true

# Comment Entry Method (optional)
# If set to 'editor', JASPER will launch your $EDITOR (e.g., vim, nano) for comment entry, similar to git commit. If set to 'stdin' or omitted, you will enter comments directly in the terminal (the old way).
comment_entry: stdin   # or 'editor' to use your $EDITOR for comment entry
```

---

### Finding Your Jira Information

- **Atlassian Account Email (`auth_email`)**:
    - This is the email address associated with your Atlassian account.
    - It is used together with your API token for authentication.

- **Jira User Identity (`usernames`)**:
    - For Jira Cloud, use your email address or Atlassian account ID.
    - To find your account ID, go to your Atlassian profile page — the account ID
      appears in the URL (e.g., `https://your-company.atlassian.net/jira/people/{accountId}`).
    - You can also use your email address if your Jira instance allows it.

- **Jira Board ID (`board_ids`)**:
    - Navigate to the Jira board you are interested in.
    - The URL will contain the board ID (e.g., `.../board/{BOARD_ID}`
      or `...?rapidView={BOARD_ID}`).
    - If unsure, ask your Jira administrator or check the board settings in Jira.

---

## Command-Line Arguments

- `--config`: Path to the YAML config file (default: `jasper_config.yaml`)
- `--jira-url`: Your Jira instance URL (overrides config)
- `--auth-email`: Your Atlassian account email for API authentication (overrides config)
- `--usernames`: One or more Jira email addresses or account IDs to query for assigned
  issues (overrides config)
- `--board-ids`: Space-separated list of Jira board IDs to check (overrides config)
- `--set-token`: Store the Jira API token securely in the system's keyring and exit
- `--no-jasper-attribution`: Do not add JASPER attribution to comments (overrides config)
- `--help`: Show all options
- `-v/-vv`: Show INFO/DEBUG log messages
- `--comment-entry`: How to enter comments: `stdin` (default, type in terminal) or `editor` (launch $EDITOR for multi-line comment entry, like git commit)

---

## Authentication & API Token Storage

JASPER uses a Jira Cloud API token for authentication via Basic Auth (email + API
token). The token is stored securely using your system keyring. The keyring entry is
scoped to your Jira instance and a fixed key ("jasper"), so only one token per Jira
instance is stored.

You must also provide your Atlassian account email via the `auth_email` config field
or the `--auth-email` CLI argument.

You can add your Jira API token to the keyring securely once, and it will be available
for all future runs of JASPER.

```sh
jasper --set-token
```

- If, when running JASPER, no token is found in the keyring, you will be prompted to
  enter one.
- You will also be asked if you want to store the token in your keyring for future use.

> [!NOTE]
> To create a Jira Cloud API token, visit:
> `https://id.atlassian.com/manage-profile/security/api-tokens`
> Log in with your Atlassian account and create a new API token.

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

> [!TIP]
> If you have installed JASPER as a module, have placed your configuration file in your
> home directory, and have set up your Jira key in the keyring, you can simply run
> `jasper` at the command line with no flags at any time to get the latest open sprint
> issues for the configured users and boards.

After starting JASPER, you will see a numbered list of your active sprint issues.

You can interact with the tool using the following options:

- **Select an issue:**  
  Enter the number of an issue to select it for further actions.

- **(r)efresh the issue list:**  
  Enter `r` or `refresh` to reload the list of issues.

- **(q)uit:**  
  Enter `q` or `quit` to exit the program.

```console
JASPER is starting...

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

- **change (s)tatus:**  
  Change the status of the selected issue. You will be shown available transitions and
  can select one by number.

- **show (l)ast comment:**  
  Display the most recent comment from the selected issue.

- **(o)pen in browser:**  
  Open the selected issue in your default web browser.

- **(b)ack:**  
  Return to the main issue list.

- **(q)uit:**  
  Exit the program.

```console
Selected: [PROJECT-7760] Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed accumsan porta sem.
Action: (c)omment, change (s)tatus, show (l)ast comment, (o)pen in browser, (b)ack, (q)uit: 
```

When you choose to **(c)omment** on an issue, you will be presented with a `Comment:`
entry prompt. To end your comment entry, simply press `Esc` followed by `Enter`, or to
cancel your comment simply use `Ctrl+C` or `Ctrl+D`.

```console
Enter your comment. To submit, press Esc and then Enter. To cancel, press Ctrl+C or Ctrl+D.

Comment: Lorem ipsum dolor sit amet, consectetur adipiscing elit.
         Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.

Comment added successfully.
```

> [!NOTE]
> Comments are submitted as plain text via the REST API v2. Markdown or HTML formatting
> will appear as plain text.

Selecting **change (s)tatus** will present a list of available statuses to choose from
and will highlight the current status with an `*`.

```console
Getting available statuses...

Available Statuses:
  1: New *
  2: In Progress
  3: Verified
  4: Review
  5: Closed

Enter the number of the status to change to, or (b)ack, or (q)uit: 
```

Selecting **show (l)ast comment** will fetch and display the most recent comment.

```console
Fetching last comment...
--------------------------------------------------
Author: Example User (2025-07-11)
--------------------------------------------------
Lorem ipsum dolor sit amet, consectetur adipiscing elit.
Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.

Comment added via JASPER: https://github.com/redhat-performance/JASPER
--------------------------------------------------
```

---

### JASPER Attribution in Comments

By default, JASPER will append the following plain text attribution to each comment it
adds:

```
Comment added via JASPER: https://github.com/redhat-performance/JASPER
```

You can disable this globally by setting `jasper_attribution: false` in your
`config.yaml` or by passing the `--no-jasper-attribution` flag on the command line.

---

## AI Notes

This project was developed with the assistance of Gemini 2.5 Pro and Copilot/GPT-4.1.

---

## License

Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.

---

For more information, see
[https://github.com/redhat-performance/JASPER](https://github.com/redhat-performance/JASPER)
