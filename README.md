# FastMCP Email Server (IMAP/SMTP)

A comprehensive Model Context Protocol (MCP) server for email operations using FastMCP. This server provides full email functionality including sending (SMTP), receiving (IMAP), and management capabilities - all without requiring environment variables. All credentials are passed dynamically to each tool.

## 🎯 Key Features

- **Send emails via SMTP** with HTML support
- **Read and manage emails via IMAP**
- **Reply and forward** maintaining email threads
- **Batch operations** for efficient management
- **Thread tracking** for conversations
- **Dynamic credentials** - no environment variables needed

## 📧 Available Tools (17 total)

### SMTP Tools (Email Sending)
- **get_smtp_config**: Get SMTP server configuration for any email provider
- **send_email**: Send emails with HTML/plain text, CC/BCC support
- **reply_to_email**: Reply maintaining thread/conversation
- **forward_email**: Forward emails to others

### IMAP Tools (Email Reading)
- **check_connection**: Test IMAP server connectivity
- **list_folders**: Get all email folders/mailboxes
- **list_emails**: List emails with pagination and filtering
- **read_email**: Get full email content (headers, body, attachments info)
- **search_emails**: Advanced search with multiple criteria
- **search_by_date_range**: Find emails between specific dates
- **get_email_count**: Get folder statistics

### Email Management
- **mark_email**: Mark as read/unread or flagged/unflagged
- **batch_mark_emails**: Mark multiple emails at once
- **move_email**: Move emails between folders
- **delete_email**: Delete emails (trash or permanent)
- **get_email_thread**: Get all emails in a conversation

### Folder Operations
- **create_folder**: Create new email folders

## Installation

### Prerequisites
- Python 3.8+
- pip

### Install Dependencies
```bash
pip install -r requirements.txt
```

## Usage

### Local Development
```bash
# Run in development mode
fastmcp dev server.py

# Test the server
python server.py
```

### Deploy to FastMCP Cloud

1. Push this repository to GitHub
2. Visit [FastMCP Cloud](https://fastmcp.cloud)
3. Connect your GitHub repository
4. Deploy with one click (no environment variables needed)

## Tool Examples

### SMTP: Send Email
```python
await send_email(
    smtp_server="smtp.gmail.com",
    smtp_username="user@gmail.com",
    smtp_password="app_specific_password",
    to_email="recipient@example.com",
    subject="Hello from MCP",
    body="This is a test email",
    html_body="<h1>Hello</h1><p>This is a <b>test</b> email</p>",
    smtp_port=587,
    use_tls=True
)
```

### SMTP: Reply to Email
```python
await reply_to_email(
    # IMAP credentials to fetch original
    server="imap.gmail.com",
    username="user@gmail.com",
    password="password",
    email_id=123,
    # SMTP credentials to send reply
    smtp_server="smtp.gmail.com",
    smtp_username="user@gmail.com",
    smtp_password="password",
    reply_body="Thanks for your email!",
    quote_original=True,
    reply_all=False
)
```

### SMTP: Get Configuration
```python
await get_smtp_config(
    email_address="user@gmail.com"
)
# Returns: {server: "smtp.gmail.com", port: 587, use_tls: true}
```

### IMAP: Test Connection
```python
await check_connection(
    server="imap.gmail.com",
    username="user@gmail.com",
    password="app_specific_password",
    port=993,
    use_ssl=True
)
```

### IMAP: Search by Date Range
```python
await search_by_date_range(
    server="imap.gmail.com",
    username="user@gmail.com",
    password="password",
    start_date="2024-01-01",
    end_date="2024-01-31",
    folder="INBOX"
)
```

### Batch Operations
```python
await batch_mark_emails(
    server="imap.gmail.com",
    username="user@gmail.com",
    password="password",
    email_ids=[123, 124, 125, 126],
    action="read",  # or "unread", "flag", "unflag"
    folder="INBOX"
)
```

### Thread Management
```python
await get_email_thread(
    server="imap.gmail.com",
    username="user@gmail.com",
    password="password",
    email_id=123,
    folder="INBOX"
)
```

## Supported Email Servers

### SMTP Servers
- **Gmail**: smtp.gmail.com:587 (TLS)
- **Outlook**: smtp-mail.outlook.com:587 (TLS)
- **Yahoo**: smtp.mail.yahoo.com:587 (TLS)
- **iCloud**: smtp.mail.me.com:587 (TLS)

### IMAP Servers

### Gmail
- Server: `imap.gmail.com`
- Port: `993` (SSL)
- Requires: App-specific password or OAuth2

### Outlook/Office 365
- Server: `outlook.office365.com`
- Port: `993` (SSL)
- May require: App passwords

### Yahoo Mail
- Server: `imap.mail.yahoo.com`
- Port: `993` (SSL)
- Requires: App password

### Custom IMAP Servers
- Supports any IMAP-compatible server
- Configurable ports and SSL/TLS settings

## Security Considerations

- **No stored credentials**: All authentication details are passed as parameters
- **SSL/TLS by default**: Secure connections are enforced
- **No logging of passwords**: Sensitive data is never logged
- **Error message sanitization**: Authentication errors don't expose credentials

## Key Design Decisions

### Dynamic Credentials
Unlike traditional MCP servers that use environment variables, this server accepts credentials as parameters to each tool. This allows:
- Multiple email accounts in a single session
- No credential storage on the server
- Better security isolation
- Easier testing and development

### Connection Management
- Connections are created per-request (no persistent connections)
- Automatic timeout handling
- Graceful error recovery

### Email Parsing
- Full support for multipart messages
- HTML to text conversion
- Attachment detection and metadata
- Proper encoding handling for international emails

## Error Handling

The server provides detailed error messages for common issues:
- Authentication failures
- Connection timeouts
- Invalid folder names
- Missing emails
- Server capability limitations

## Development

### Project Structure
```
fastmcp-imap/
├── server.py          # Main FastMCP server implementation
├── requirements.txt   # Python dependencies
├── README.md         # This file
├── SCRATCHPAD.md     # Development notes
└── .gitignore        # Git ignore rules
```

### Testing

Test with various IMAP providers:
```python
# Test connection
fastmcp dev server.py

# In another terminal, use the MCP client to test
# Or integrate with Claude, Cline, or other MCP clients
```

## FastMCP Cloud Deployment

This server is optimized for [FastMCP Cloud](https://fastmcp.cloud):

1. **Module-level server object**: The `mcp` object is at module level
2. **PyPI dependencies only**: All dependencies available on PyPI
3. **No environment variables**: Dynamic credential handling
4. **Public repository**: Ready for GitHub integration

## Contributing

Feel free to submit issues and enhancement requests!

## License

MIT License - See LICENSE file for details

## Acknowledgments

Built with [FastMCP](https://github.com/jlowin/fastmcp) - The fast, Pythonic way to build MCP servers.