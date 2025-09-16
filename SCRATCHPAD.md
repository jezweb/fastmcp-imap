# FastMCP IMAP Server - Development Scratchpad

## Project Overview
Creating an MCP server using FastMCP for IMAP email operations that:
- Accepts credentials dynamically (not from env vars)
- Provides comprehensive email management
- Deploys to FastMCP Cloud

## Key Design Decisions

### 1. Authentication Approach
- Pass credentials as parameters to each tool
- No environment variables for IMAP credentials
- Support multiple email accounts in single session

### 2. Core Libraries
- `imapclient` - Better than imaplib, more pythonic
- `email` - Python standard library for parsing
- `html2text` - Convert HTML emails to readable text

### 3. Connection Management
- Optional connection caching with TTL
- Connection pooling for performance
- Graceful disconnection handling

## IMAP Server Compatibility Notes

### Gmail
- Server: imap.gmail.com
- Port: 993 (SSL)
- Requires app-specific password or OAuth2

### Outlook/Office365
- Server: outlook.office365.com
- Port: 993 (SSL)
- May require app passwords

### Generic IMAP
- Support custom ports
- SSL/TLS options
- STARTTLS support

## Tool Categories

### Essential (MVP)
1. check_connection - Test connectivity
2. list_folders - Get mailbox structure
3. list_emails - Basic email listing
4. read_email - Get email content
5. search_emails - Find specific emails

### Management
6. mark_as_read/unread
7. move_email
8. delete_email
9. flag_email

### Advanced
10. create_draft
11. send_email (via SMTP)
12. get_attachments
13. folder operations

## Code Snippets

### Connection Helper
```python
from imapclient import IMAPClient
import ssl

def create_imap_connection(server, username, password, port=993, use_ssl=True):
    context = ssl.create_default_context()
    client = IMAPClient(server, port=port, ssl=use_ssl, ssl_context=context)
    client.login(username, password)
    return client
```

### Email Parser
```python
import email
from email.header import decode_header

def parse_email_message(raw_message):
    msg = email.message_from_bytes(raw_message)
    subject = decode_header(msg['Subject'])[0][0]
    from_addr = msg['From']
    to_addr = msg['To']
    date = msg['Date']

    # Extract body
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode()
                break
    else:
        body = msg.get_payload(decode=True).decode()

    return {
        "subject": subject,
        "from": from_addr,
        "to": to_addr,
        "date": date,
        "body": body
    }
```

## Error Handling Patterns

```python
class IMAPError(Exception):
    """Base exception for IMAP operations"""
    pass

class AuthenticationError(IMAPError):
    """Failed to authenticate with IMAP server"""
    pass

class ConnectionError(IMAPError):
    """Failed to connect to IMAP server"""
    pass

class FolderNotFoundError(IMAPError):
    """Specified folder doesn't exist"""
    pass
```

## Testing Checklist
- [ ] Test with Gmail
- [ ] Test with Outlook
- [ ] Test with custom IMAP server
- [ ] Test error handling (wrong credentials)
- [ ] Test timeout handling
- [ ] Test large mailboxes
- [ ] Test special characters in emails
- [ ] Test attachments

## FastMCP Cloud Requirements
1. Module-level mcp object ✓
2. PyPI dependencies only ✓
3. Public GitHub repo ✓
4. No local file dependencies ✓

## Performance Considerations
- Implement pagination for large mailboxes
- Cache folder structure
- Batch operations where possible
- Connection pooling with timeout

## Security Notes
- Never log passwords
- Use SSL/TLS by default
- Sanitize error messages
- Handle OAuth2 tokens securely (future)