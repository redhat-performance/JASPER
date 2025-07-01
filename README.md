# JASPER: Jira Active Sprint Personal Reporter

JASPER is a command-line tool to help you track and manage your assigned Jira issues in
active sprints. It supports listing issues, adding comments, changing issue status, and
opening issues in a web browser. Configuration is handled via a YAML file, and API
tokens are stored securely using the system keyring.

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
# Your full Jira instance URL
jira_url: "[https://your-company.atlassian.net](https://your-company.atlassian.net)"

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

# --- Gemini AI Integration (Optional) ---
gemini:
  # Set to true to enable Gemini comment assistance.
  # You will be prompted to securely store your Gemini API key on first run.
  enabled: false
```

---

### Finding Your Jira Information

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

## Command-Line Arguments

- `--config`: Path to the YAML config file (default: `jasper_config.yaml`)
- `--jira-url`: Your Jira instance URL (overrides config)
- `--usernames`: One or more Jira usernames/account IDs to query for assigned issues
  (overrides config)
- `--board-ids`: Space-separated list of Jira board IDs to check (overrides config)
- `--set-token`: Store the Jira API token securely in the system's keyring and exit
- `--set-gemini-token`: Store the Gemini API key securely in the system's keyring and exit
- `--no-jasper-attribution`: Do not add JASPER attribution to comments (overrides config)
- `--help`: Show all options
- `-v/-vv`: Show INFO/DEBUG log messages

---

## Authentication & API Token Storage

JASPER uses API tokens for authentication with both Jira and Gemini. The tokens are
stored securely using your system's keyring.

### Jira API Token
You can add your Jira API token to the keyring securely once, and it will be available
for all future runs of JASPER.

```sh
jasper --set-token
```

### Gemini API Token
To use the AI-powered comment assistance, you must first store your Gemini API key.

```sh
jasper --set-gemini-token
```

> [!NOTE]
> - To create a **Jira API token**, go to your Jira profile and look for "Personal
>   Access Tokens".
> - To create a **Gemini API key**, visit
>   [Google AI Studio](https://aistudio.google.com/).

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
jasper --jira-url "[https://your-company.atlassian.net](https://your-company.atlassian.net)" \
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

- **Select an issue:** Enter the number of an issue to select it for further actions.

- **(r)efresh the issue list:** Enter `r` or `refresh` to reload the list of issues.

- **(q)uit:** Enter `q` or `quit` to exit the program.

```console
JASPER is starting...

--- Active Sprint Items ---
  1: [PROJECT-7760] Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed accumsan porta sem. (Status: In Progress, Priority: Normal) (Assignee: bar@example.com)
      URL: [https://your-company.atlassian.net/browse/PROJECT-7760](https://your-company.atlassian.net/browse/PROJECT-7760)
  2: [PROJECT-29981] Phasellus malesuada aliquet lacus a pharetra. Aliquam erat volutpat. (Status: In Progress, Priority: Critical) (Assignee: foo@example.com)
      URL: [https://your-company.atlassian.net/browse/PROJECT-29981](https://your-company.atlassian.net/browse/PROJECT-29981)
  3: [PROJECT-27400] Etiam turpis lacus, vestibulum ac mauris et, pellentesque bibendum ante. (Status: New, Priority: Major) (Assignee: foo@example.com)
      URL: [https://your-company.atlassian.net/browse/PROJECT-27400](https://your-company.atlassian.net/browse/PROJECT-27400)
  4: [PROJECT-30477] Suspendisse egestas risus id ligula facilisis pharetra. (Status: In Progress, Priority: Undefined) (Assignee: bar@example.com)
      URL: [https://your-company.atlassian.net/browse/PROJECT-30477](https://your-company.atlassian.net/browse/PROJECT-30477)
---------------------------

Enter an issue number to select, (r)efresh, or (q)uit: 
```

When you select an issue, you will be prompted with additional actions:

- **(c)omment:** Add a comment to the selected issue. To submit the comment, press the `Esc` key followed by the `Enter` key. If Gemini is enabled, you will get real-time "ghost text" suggestions as you type. Press `Tab` to accept a suggestion.

- **Update (s)tatus:** Change the status of the selected issue. You will be shown available transitions and
  can select one by number.

- **(o)pen in browser:** Open the selected issue in your default web browser.

- **(b)ack to list:** Return to the main issue list.

- **(q)uit:** Exit the program from the issue action menu.

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
Comment added via JASPER: [https://github.com/redhat-performance/JASPER](https://github.com/redhat-performance/JASPER)
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
