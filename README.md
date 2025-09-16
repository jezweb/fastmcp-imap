# FastMCP IMAP Server

A Model Context Protocol (MCP) server for IMAP email operations using FastMCP. This server provides comprehensive email management capabilities without requiring environment variables - all credentials are passed dynamically to each tool.

## Features

### Connection & Authentication
- **check_connection**: Test IMAP server connectivity with provided credentials
- **list_folders**: Get all available email folders/mailboxes

### Email Reading
- **list_emails**: List emails with pagination and filtering
- **read_email**: Get full email content including headers, body, and attachment info
- **search_emails**: Advanced search with multiple criteria
- **get_email_count**: Get statistics for a specific folder

### Email Management
- **mark_email**: Mark emails as read/unread or flagged/unflagged
- **move_email**: Move emails between folders
- **delete_email**: Delete emails (trash or permanent)

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

### Test Connection
```python
await check_connection(
    server="imap.gmail.com",
    username="user@gmail.com",
    password="app_specific_password",
    port=993,
    use_ssl=True
)
```

### List Emails
```python
await list_emails(
    server="imap.gmail.com",
    username="user@gmail.com",
    password="password",
    folder="INBOX",
    limit=20,
    offset=0
)
```

### Search Emails
```python
await search_emails(
    server="imap.gmail.com",
    username="user@gmail.com",
    password="password",
    subject="important",
    from_address="boss@company.com",
    unread_only=True
)
```

### Read Email
```python
await read_email(
    server="imap.gmail.com",
    username="user@gmail.com",
    password="password",
    email_id=123,
    folder="INBOX",
    mark_as_read=True
)
```

## Supported IMAP Servers

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