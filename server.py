"""
FastMCP IMAP Server
===================
An MCP server for IMAP email operations with dynamic credential handling.
No environment variables required - all credentials passed as parameters.
"""

import ssl
import email
import logging
import smtplib
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime, formataddr
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import html2text
from imapclient import IMAPClient
from imapclient.exceptions import IMAPClientError
from fastmcp import FastMCP
from email_validator import validate_email, EmailNotValidError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# Server Creation - MUST be at module level for FastMCP Cloud
# ============================================================================

mcp = FastMCP(
    name="Email Server (IMAP/SMTP)",
    instructions="""
    Email Server for MCP - IMAP and SMTP Operations

    This server provides comprehensive email operations without requiring
    environment variables. All credentials are passed dynamically to each tool.

    Key Features:
    - Send emails via SMTP
    - Read and manage emails via IMAP
    - Reply and forward emails
    - Batch operations
    - Email thread management
    - Folder operations
    - SMTP configuration helper

    All tools require credentials as parameters - no environment variables needed.
    Supports Gmail, Outlook, Yahoo, and any IMAP/SMTP compatible servers.
    """
)

# ============================================================================
# Error Classes
# ============================================================================

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

# ============================================================================
# Helper Functions
# ============================================================================

def create_imap_connection(
    server: str,
    username: str,
    password: str,
    port: int = 993,
    use_ssl: bool = True,
    timeout: int = 30
) -> IMAPClient:
    """
    Create and authenticate IMAP connection.

    Args:
        server: IMAP server hostname
        username: Email username
        password: Email password
        port: IMAP port (default 993 for SSL)
        use_ssl: Use SSL/TLS connection
        timeout: Connection timeout in seconds

    Returns:
        Authenticated IMAPClient instance

    Raises:
        ConnectionError: Failed to connect
        AuthenticationError: Failed to authenticate
    """
    try:
        if use_ssl:
            context = ssl.create_default_context()
            client = IMAPClient(
                server,
                port=port,
                ssl=True,
                ssl_context=context,
                timeout=timeout
            )
        else:
            client = IMAPClient(
                server,
                port=port,
                ssl=False,
                timeout=timeout
            )

        logger.info(f"Connected to {server}:{port}")

        try:
            client.login(username, password)
            logger.info(f"Authenticated as {username}")
            return client
        except IMAPClientError as e:
            raise AuthenticationError(f"Authentication failed: {str(e)}")

    except Exception as e:
        if "authentication" in str(e).lower() or "login" in str(e).lower():
            raise AuthenticationError(f"Authentication failed: {str(e)}")
        else:
            raise ConnectionError(f"Connection failed: {str(e)}")

def decode_header_value(value: str) -> str:
    """Decode email header value handling various encodings."""
    if not value:
        return ""

    try:
        decoded_parts = decode_header(value)
        result = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                try:
                    result.append(part.decode(encoding or 'utf-8', errors='replace'))
                except:
                    result.append(part.decode('utf-8', errors='replace'))
            else:
                result.append(str(part))
        return ' '.join(result)
    except:
        return str(value)

def parse_email_message(raw_message: bytes) -> Dict[str, Any]:
    """
    Parse raw email message into structured format.

    Args:
        raw_message: Raw email bytes

    Returns:
        Dictionary with parsed email data
    """
    msg = email.message_from_bytes(raw_message)

    # Decode headers
    subject = decode_header_value(msg.get('Subject', ''))
    from_addr = decode_header_value(msg.get('From', ''))
    to_addr = decode_header_value(msg.get('To', ''))
    cc_addr = decode_header_value(msg.get('Cc', ''))
    date_str = msg.get('Date', '')

    # Parse date
    try:
        date_parsed = parsedate_to_datetime(date_str) if date_str else None
        date_iso = date_parsed.isoformat() if date_parsed else date_str
    except:
        date_iso = date_str

    # Extract body
    text_body = ""
    html_body = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    attachments.append({
                        "filename": decode_header_value(filename),
                        "content_type": content_type,
                        "size": len(part.get_payload())
                    })
            elif content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    text_body = payload.decode('utf-8', errors='replace')
            elif content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    html_body = payload.decode('utf-8', errors='replace')
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            content_type = msg.get_content_type()
            decoded_payload = payload.decode('utf-8', errors='replace')
            if content_type == "text/html":
                html_body = decoded_payload
            else:
                text_body = decoded_payload

    # Convert HTML to text if no text body
    if not text_body and html_body:
        h = html2text.HTML2Text()
        h.ignore_links = False
        h.ignore_images = False
        text_body = h.handle(html_body)

    return {
        "subject": subject,
        "from": from_addr,
        "to": to_addr,
        "cc": cc_addr,
        "date": date_iso,
        "text_body": text_body.strip(),
        "html_body": html_body,
        "attachments": attachments,
        "has_attachments": len(attachments) > 0
    }

# ============================================================================
# SMTP Configuration and Helpers
# ============================================================================

# Common SMTP server configurations
SMTP_CONFIGS = {
    "gmail.com": {"server": "smtp.gmail.com", "port": 587, "use_tls": True},
    "outlook.com": {"server": "smtp-mail.outlook.com", "port": 587, "use_tls": True},
    "hotmail.com": {"server": "smtp-mail.outlook.com", "port": 587, "use_tls": True},
    "live.com": {"server": "smtp-mail.outlook.com", "port": 587, "use_tls": True},
    "yahoo.com": {"server": "smtp.mail.yahoo.com", "port": 587, "use_tls": True},
    "icloud.com": {"server": "smtp.mail.me.com", "port": 587, "use_tls": True},
    "aol.com": {"server": "smtp.aol.com", "port": 587, "use_tls": True},
}

def guess_smtp_config(email_address: str) -> Dict[str, Any]:
    """
    Guess SMTP configuration based on email domain.

    Args:
        email_address: Email address to analyze

    Returns:
        SMTP configuration dict or None
    """
    try:
        domain = email_address.split('@')[1].lower()
        return SMTP_CONFIGS.get(domain, None)
    except:
        return None

def create_smtp_connection(
    server: str,
    username: str,
    password: str,
    port: int = 587,
    use_tls: bool = True,
    timeout: int = 30
) -> smtplib.SMTP:
    """
    Create and authenticate SMTP connection.

    Args:
        server: SMTP server hostname
        username: Email username
        password: Email password
        port: SMTP port (default 587 for TLS)
        use_tls: Use STARTTLS
        timeout: Connection timeout in seconds

    Returns:
        Authenticated SMTP instance

    Raises:
        ConnectionError: Failed to connect
        AuthenticationError: Failed to authenticate
    """
    try:
        if port == 465:
            # SMTP_SSL for port 465
            smtp = smtplib.SMTP_SSL(server, port, timeout=timeout)
        else:
            # Regular SMTP with optional STARTTLS
            smtp = smtplib.SMTP(server, port, timeout=timeout)
            if use_tls:
                smtp.starttls()

        logger.info(f"Connected to SMTP server {server}:{port}")

        try:
            smtp.login(username, password)
            logger.info(f"Authenticated to SMTP as {username}")
            return smtp
        except smtplib.SMTPAuthenticationError as e:
            raise AuthenticationError(f"SMTP authentication failed: {str(e)}")

    except Exception as e:
        if "authentication" in str(e).lower() or "login" in str(e).lower():
            raise AuthenticationError(f"SMTP authentication failed: {str(e)}")
        else:
            raise ConnectionError(f"SMTP connection failed: {str(e)}")

# ============================================================================
# Connection and Authentication Tools
# ============================================================================

@mcp.tool()
async def check_connection(
    server: str,
    username: str,
    password: str,
    port: int = 993,
    use_ssl: bool = True
) -> Dict[str, Any]:
    """
    Test IMAP server connection and authentication.

    Args:
        server: IMAP server hostname (e.g., 'imap.gmail.com')
        username: Email username
        password: Email password
        port: IMAP port (default 993 for SSL, 143 for non-SSL)
        use_ssl: Use SSL/TLS connection (default True)

    Returns:
        Connection status and server capabilities
    """
    try:
        client = create_imap_connection(server, username, password, port, use_ssl)

        # Get server capabilities
        capabilities = list(client.capabilities())

        # Get folder count
        folders = client.list_folders()
        folder_count = len(folders)

        # Check for INBOX
        has_inbox = any('INBOX' in folder[2].upper() for folder in folders)

        client.logout()

        return {
            "success": True,
            "server": server,
            "port": port,
            "username": username,
            "ssl": use_ssl,
            "capabilities": capabilities,
            "folder_count": folder_count,
            "has_inbox": has_inbox,
            "message": f"Successfully connected to {server}"
        }

    except AuthenticationError as e:
        return {
            "success": False,
            "error": "authentication_failed",
            "message": str(e)
        }
    except ConnectionError as e:
        return {
            "success": False,
            "error": "connection_failed",
            "message": str(e)
        }
    except Exception as e:
        return {
            "success": False,
            "error": "unknown_error",
            "message": str(e)
        }

@mcp.tool()
async def list_folders(
    server: str,
    username: str,
    password: str,
    port: int = 993,
    use_ssl: bool = True
) -> Dict[str, Any]:
    """
    List all available email folders/mailboxes.

    Args:
        server: IMAP server hostname
        username: Email username
        password: Email password
        port: IMAP port
        use_ssl: Use SSL/TLS connection

    Returns:
        List of folders with details
    """
    try:
        client = create_imap_connection(server, username, password, port, use_ssl)

        folders = []
        raw_folders = client.list_folders()

        for flags, delimiter, name in raw_folders:
            # Get folder status if possible
            try:
                client.select_folder(name, readonly=True)
                status = client.folder_status(name, ['MESSAGES', 'UNSEEN', 'RECENT'])
                message_count = status.get(b'MESSAGES', 0)
                unseen_count = status.get(b'UNSEEN', 0)
            except:
                message_count = None
                unseen_count = None

            folders.append({
                "name": name,
                "flags": [flag.decode() if isinstance(flag, bytes) else flag for flag in flags],
                "delimiter": delimiter,
                "message_count": message_count,
                "unseen_count": unseen_count,
                "is_selectable": b'\\Noselect' not in flags
            })

        client.logout()

        return {
            "success": True,
            "folders": folders,
            "total_folders": len(folders)
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

# ============================================================================
# Email Reading Tools
# ============================================================================

@mcp.tool()
async def list_emails(
    server: str,
    username: str,
    password: str,
    folder: str = "INBOX",
    limit: int = 20,
    offset: int = 0,
    port: int = 993,
    use_ssl: bool = True,
    include_seen: bool = True,
    sort_desc: bool = True
) -> Dict[str, Any]:
    """
    List emails from a specific folder.

    Args:
        server: IMAP server hostname
        username: Email username
        password: Email password
        folder: Folder to list emails from (default INBOX)
        limit: Maximum number of emails to return (default 20)
        offset: Number of emails to skip (for pagination)
        port: IMAP port
        use_ssl: Use SSL/TLS connection
        include_seen: Include read emails (default True)
        sort_desc: Sort by date descending/newest first (default True)

    Returns:
        List of email summaries
    """
    try:
        client = create_imap_connection(server, username, password, port, use_ssl)

        # Select folder
        client.select_folder(folder, readonly=True)

        # Search for messages
        if include_seen:
            messages = client.search(['ALL'])
        else:
            messages = client.search(['UNSEEN'])

        if not messages:
            client.logout()
            return {
                "success": True,
                "emails": [],
                "total": 0,
                "folder": folder
            }

        # Sort messages
        messages = list(messages)
        if sort_desc:
            messages.reverse()

        # Apply pagination
        total = len(messages)
        start = offset
        end = min(start + limit, total)
        page_messages = messages[start:end] if start < total else []

        if not page_messages:
            client.logout()
            return {
                "success": True,
                "emails": [],
                "total": total,
                "folder": folder,
                "offset": offset,
                "limit": limit
            }

        # Fetch message data
        email_list = []
        fetch_data = client.fetch(
            page_messages,
            ['ENVELOPE', 'FLAGS', 'RFC822.SIZE', 'INTERNALDATE', 'UID']
        )

        for msg_id, data in fetch_data.items():
            envelope = data[b'ENVELOPE']
            flags = data.get(b'FLAGS', [])
            size = data.get(b'RFC822.SIZE', 0)
            date = data.get(b'INTERNALDATE')
            uid = data.get(b'UID', msg_id)

            # Parse envelope
            subject = decode_header_value(envelope.subject.decode() if envelope.subject else "")
            from_addr = ""
            if envelope.from_:
                addr = envelope.from_[0]
                from_addr = f"{addr.name.decode() if addr.name else ''} <{addr.mailbox.decode()}@{addr.host.decode()}>".strip()

            to_addrs = []
            if envelope.to:
                for addr in envelope.to:
                    to_addr = f"{addr.name.decode() if addr.name else ''} <{addr.mailbox.decode()}@{addr.host.decode()}>".strip()
                    to_addrs.append(to_addr)

            email_list.append({
                "id": msg_id,
                "uid": uid,
                "subject": subject,
                "from": from_addr,
                "to": ", ".join(to_addrs),
                "date": date.isoformat() if date else None,
                "size": size,
                "flags": [flag.decode() if isinstance(flag, bytes) else flag for flag in flags],
                "is_seen": b'\\Seen' in flags,
                "is_flagged": b'\\Flagged' in flags,
                "is_answered": b'\\Answered' in flags
            })

        client.logout()

        return {
            "success": True,
            "emails": email_list,
            "total": total,
            "folder": folder,
            "offset": offset,
            "limit": limit,
            "has_more": end < total
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
async def read_email(
    server: str,
    username: str,
    password: str,
    email_id: int,
    folder: str = "INBOX",
    port: int = 993,
    use_ssl: bool = True,
    mark_as_read: bool = False
) -> Dict[str, Any]:
    """
    Read full email content by ID.

    Args:
        server: IMAP server hostname
        username: Email username
        password: Email password
        email_id: Email message ID
        folder: Folder containing the email (default INBOX)
        port: IMAP port
        use_ssl: Use SSL/TLS connection
        mark_as_read: Mark email as read after fetching (default False)

    Returns:
        Full email content including headers, body, and attachments
    """
    try:
        client = create_imap_connection(server, username, password, port, use_ssl)

        # Select folder
        client.select_folder(folder, readonly=not mark_as_read)

        # Fetch the message
        fetch_data = client.fetch([email_id], ['RFC822', 'FLAGS', 'UID'])

        if email_id not in fetch_data:
            client.logout()
            return {
                "success": False,
                "error": f"Email with ID {email_id} not found in {folder}"
            }

        data = fetch_data[email_id]
        raw_message = data[b'RFC822']
        flags = data.get(b'FLAGS', [])
        uid = data.get(b'UID', email_id)

        # Parse the email
        parsed = parse_email_message(raw_message)

        # Add metadata
        parsed["id"] = email_id
        parsed["uid"] = uid
        parsed["folder"] = folder
        parsed["flags"] = [flag.decode() if isinstance(flag, bytes) else flag for flag in flags]
        parsed["is_seen"] = b'\\Seen' in flags
        parsed["is_flagged"] = b'\\Flagged' in flags
        parsed["is_answered"] = b'\\Answered' in flags

        # Mark as read if requested
        if mark_as_read and not parsed["is_seen"]:
            client.add_flags([email_id], [b'\\Seen'])
            parsed["is_seen"] = True
            parsed["marked_as_read"] = True

        client.logout()

        return {
            "success": True,
            "email": parsed
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
async def search_emails(
    server: str,
    username: str,
    password: str,
    folder: str = "INBOX",
    subject: Optional[str] = None,
    from_address: Optional[str] = None,
    to_address: Optional[str] = None,
    body_text: Optional[str] = None,
    limit: int = 50,
    port: int = 993,
    use_ssl: bool = True,
    unread_only: bool = False
) -> Dict[str, Any]:
    """
    Search for emails matching specific criteria.

    Args:
        server: IMAP server hostname
        username: Email username
        password: Email password
        folder: Folder to search in (default INBOX)
        subject: Search for text in subject
        from_address: Search for sender email/name
        to_address: Search for recipient email/name
        body_text: Search for text in body
        limit: Maximum results to return
        port: IMAP port
        use_ssl: Use SSL/TLS connection
        unread_only: Only search unread emails

    Returns:
        List of matching emails
    """
    try:
        client = create_imap_connection(server, username, password, port, use_ssl)

        # Select folder
        client.select_folder(folder, readonly=True)

        # Build search criteria
        criteria = []

        if unread_only:
            criteria.append('UNSEEN')

        if subject:
            criteria.append(['SUBJECT', subject])

        if from_address:
            criteria.append(['FROM', from_address])

        if to_address:
            criteria.append(['TO', to_address])

        if body_text:
            criteria.append(['BODY', body_text])

        # Default to ALL if no criteria
        if not criteria:
            criteria = ['ALL']

        # Search
        messages = client.search(criteria)

        if not messages:
            client.logout()
            return {
                "success": True,
                "emails": [],
                "total": 0,
                "search_criteria": {
                    "folder": folder,
                    "subject": subject,
                    "from": from_address,
                    "to": to_address,
                    "body": body_text,
                    "unread_only": unread_only
                }
            }

        # Limit results
        messages = list(messages)
        messages.reverse()  # Newest first
        total = len(messages)
        messages = messages[:limit]

        # Fetch message data
        email_list = []
        fetch_data = client.fetch(
            messages,
            ['ENVELOPE', 'FLAGS', 'RFC822.SIZE', 'INTERNALDATE', 'UID']
        )

        for msg_id, data in fetch_data.items():
            envelope = data[b'ENVELOPE']
            flags = data.get(b'FLAGS', [])
            size = data.get(b'RFC822.SIZE', 0)
            date = data.get(b'INTERNALDATE')
            uid = data.get(b'UID', msg_id)

            # Parse envelope
            subject_str = decode_header_value(envelope.subject.decode() if envelope.subject else "")
            from_str = ""
            if envelope.from_:
                addr = envelope.from_[0]
                from_str = f"{addr.name.decode() if addr.name else ''} <{addr.mailbox.decode()}@{addr.host.decode()}>".strip()

            email_list.append({
                "id": msg_id,
                "uid": uid,
                "subject": subject_str,
                "from": from_str,
                "date": date.isoformat() if date else None,
                "size": size,
                "flags": [flag.decode() if isinstance(flag, bytes) else flag for flag in flags],
                "is_seen": b'\\Seen' in flags,
                "is_flagged": b'\\Flagged' in flags
            })

        client.logout()

        return {
            "success": True,
            "emails": email_list,
            "total": total,
            "returned": len(email_list),
            "search_criteria": {
                "folder": folder,
                "subject": subject,
                "from": from_address,
                "to": to_address,
                "body": body_text,
                "unread_only": unread_only
            }
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

# ============================================================================
# Email Management Tools
# ============================================================================

@mcp.tool()
async def mark_email(
    server: str,
    username: str,
    password: str,
    email_id: int,
    folder: str = "INBOX",
    action: str = "read",
    port: int = 993,
    use_ssl: bool = True
) -> Dict[str, Any]:
    """
    Mark email with specific flags (read/unread, flagged/unflagged).

    Args:
        server: IMAP server hostname
        username: Email username
        password: Email password
        email_id: Email message ID
        folder: Folder containing the email
        action: Action to perform ('read', 'unread', 'flag', 'unflag')
        port: IMAP port
        use_ssl: Use SSL/TLS connection

    Returns:
        Success status and updated flags
    """
    try:
        client = create_imap_connection(server, username, password, port, use_ssl)

        # Select folder
        client.select_folder(folder, readonly=False)

        # Apply action
        if action == "read":
            client.add_flags([email_id], [b'\\Seen'])
            operation = "marked as read"
        elif action == "unread":
            client.remove_flags([email_id], [b'\\Seen'])
            operation = "marked as unread"
        elif action == "flag":
            client.add_flags([email_id], [b'\\Flagged'])
            operation = "flagged"
        elif action == "unflag":
            client.remove_flags([email_id], [b'\\Flagged'])
            operation = "unflagged"
        else:
            client.logout()
            return {
                "success": False,
                "error": f"Invalid action: {action}. Use 'read', 'unread', 'flag', or 'unflag'"
            }

        # Get updated flags
        fetch_data = client.fetch([email_id], ['FLAGS'])
        flags = fetch_data[email_id].get(b'FLAGS', []) if email_id in fetch_data else []

        client.logout()

        return {
            "success": True,
            "message": f"Email {email_id} {operation}",
            "email_id": email_id,
            "folder": folder,
            "action": action,
            "flags": [flag.decode() if isinstance(flag, bytes) else flag for flag in flags]
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
async def move_email(
    server: str,
    username: str,
    password: str,
    email_id: int,
    from_folder: str = "INBOX",
    to_folder: str = "Archive",
    port: int = 993,
    use_ssl: bool = True
) -> Dict[str, Any]:
    """
    Move email from one folder to another.

    Args:
        server: IMAP server hostname
        username: Email username
        password: Email password
        email_id: Email message ID
        from_folder: Source folder
        to_folder: Destination folder
        port: IMAP port
        use_ssl: Use SSL/TLS connection

    Returns:
        Success status and new location
    """
    try:
        client = create_imap_connection(server, username, password, port, use_ssl)

        # Select source folder
        client.select_folder(from_folder, readonly=False)

        # Check if destination folder exists
        folders = [f[2] for f in client.list_folders()]
        if to_folder not in folders:
            client.logout()
            return {
                "success": False,
                "error": f"Destination folder '{to_folder}' does not exist"
            }

        # Move the message
        client.move([email_id], to_folder)

        client.logout()

        return {
            "success": True,
            "message": f"Email {email_id} moved from {from_folder} to {to_folder}",
            "email_id": email_id,
            "from_folder": from_folder,
            "to_folder": to_folder
        }

    except Exception as e:
        # Fallback to copy+delete if MOVE not supported
        if "MOVE" in str(e):
            try:
                client = create_imap_connection(server, username, password, port, use_ssl)
                client.select_folder(from_folder, readonly=False)

                # Copy then delete
                client.copy([email_id], to_folder)
                client.add_flags([email_id], [b'\\Deleted'])
                client.expunge()

                client.logout()

                return {
                    "success": True,
                    "message": f"Email {email_id} moved from {from_folder} to {to_folder} (via copy+delete)",
                    "email_id": email_id,
                    "from_folder": from_folder,
                    "to_folder": to_folder
                }
            except Exception as e2:
                return {
                    "success": False,
                    "error": f"Move failed: {str(e2)}"
                }

        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
async def delete_email(
    server: str,
    username: str,
    password: str,
    email_id: int,
    folder: str = "INBOX",
    permanent: bool = False,
    port: int = 993,
    use_ssl: bool = True
) -> Dict[str, Any]:
    """
    Delete an email (move to trash or permanent deletion).

    Args:
        server: IMAP server hostname
        username: Email username
        password: Email password
        email_id: Email message ID
        folder: Folder containing the email
        permanent: Permanently delete (True) or move to Trash (False)
        port: IMAP port
        use_ssl: Use SSL/TLS connection

    Returns:
        Success status
    """
    try:
        client = create_imap_connection(server, username, password, port, use_ssl)

        if not permanent:
            # Try to move to Trash/Deleted folder
            folders = [f[2] for f in client.list_folders()]
            trash_folder = None

            # Look for common trash folder names
            for trash_name in ['Trash', 'Deleted', 'Deleted Items', '[Gmail]/Trash']:
                if trash_name in folders:
                    trash_folder = trash_name
                    break

            if trash_folder and folder != trash_folder:
                # Move to trash
                client.select_folder(folder, readonly=False)
                try:
                    client.move([email_id], trash_folder)
                except:
                    # Fallback to copy+delete
                    client.copy([email_id], trash_folder)
                    client.add_flags([email_id], [b'\\Deleted'])
                    client.expunge()

                client.logout()

                return {
                    "success": True,
                    "message": f"Email {email_id} moved to {trash_folder}",
                    "email_id": email_id,
                    "permanent": False,
                    "trash_folder": trash_folder
                }

        # Permanent deletion
        client.select_folder(folder, readonly=False)
        client.add_flags([email_id], [b'\\Deleted'])
        client.expunge()

        client.logout()

        return {
            "success": True,
            "message": f"Email {email_id} permanently deleted from {folder}",
            "email_id": email_id,
            "permanent": True
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

# ============================================================================
# Folder Management Tools
# ============================================================================

@mcp.tool()
async def create_folder(
    server: str,
    username: str,
    password: str,
    folder_name: str,
    port: int = 993,
    use_ssl: bool = True
) -> Dict[str, Any]:
    """
    Create a new email folder.

    Args:
        server: IMAP server hostname
        username: Email username
        password: Email password
        folder_name: Name of the folder to create
        port: IMAP port
        use_ssl: Use SSL/TLS connection

    Returns:
        Success status
    """
    try:
        client = create_imap_connection(server, username, password, port, use_ssl)

        # Check if folder already exists
        folders = [f[2] for f in client.list_folders()]
        if folder_name in folders:
            client.logout()
            return {
                "success": False,
                "error": f"Folder '{folder_name}' already exists"
            }

        # Create folder
        client.create_folder(folder_name)

        client.logout()

        return {
            "success": True,
            "message": f"Folder '{folder_name}' created successfully",
            "folder_name": folder_name
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
async def get_email_count(
    server: str,
    username: str,
    password: str,
    folder: str = "INBOX",
    port: int = 993,
    use_ssl: bool = True
) -> Dict[str, Any]:
    """
    Get email count and statistics for a folder.

    Args:
        server: IMAP server hostname
        username: Email username
        password: Email password
        folder: Folder to get statistics for
        port: IMAP port
        use_ssl: Use SSL/TLS connection

    Returns:
        Email counts and statistics
    """
    try:
        client = create_imap_connection(server, username, password, port, use_ssl)

        # Get folder status
        status = client.folder_status(folder, ['MESSAGES', 'UNSEEN', 'RECENT'])

        # Select folder for more details
        client.select_folder(folder, readonly=True)

        # Count flagged messages
        flagged = len(client.search(['FLAGGED']))

        client.logout()

        return {
            "success": True,
            "folder": folder,
            "total_messages": status.get(b'MESSAGES', 0),
            "unread_count": status.get(b'UNSEEN', 0),
            "recent_count": status.get(b'RECENT', 0),
            "flagged_count": flagged,
            "read_count": status.get(b'MESSAGES', 0) - status.get(b'UNSEEN', 0)
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

# ============================================================================
# SMTP Email Sending Tools
# ============================================================================

@mcp.tool()
async def get_smtp_config(
    email_address: str
) -> Dict[str, Any]:
    """
    Get suggested SMTP configuration for an email address.

    Args:
        email_address: Email address to analyze

    Returns:
        SMTP configuration suggestion
    """
    try:
        config = guess_smtp_config(email_address)

        if config:
            return {
                "success": True,
                "email": email_address,
                "domain": email_address.split('@')[1],
                "smtp_server": config["server"],
                "smtp_port": config["port"],
                "use_tls": config["use_tls"],
                "note": "Use app-specific password if 2FA is enabled"
            }
        else:
            domain = email_address.split('@')[1]
            return {
                "success": True,
                "email": email_address,
                "domain": domain,
                "smtp_server": f"smtp.{domain}",
                "smtp_port": 587,
                "use_tls": True,
                "note": "Generic configuration - adjust server if needed"
            }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
async def send_email(
    smtp_server: str,
    smtp_username: str,
    smtp_password: str,
    to_email: str,
    subject: str,
    body: str,
    from_email: Optional[str] = None,
    cc: Optional[str] = None,
    bcc: Optional[str] = None,
    html_body: Optional[str] = None,
    reply_to: Optional[str] = None,
    smtp_port: int = 587,
    use_tls: bool = True
) -> Dict[str, Any]:
    """
    Send an email via SMTP.

    Args:
        smtp_server: SMTP server hostname
        smtp_username: SMTP username (usually email address)
        smtp_password: SMTP password
        to_email: Recipient email address(es) - comma separated
        subject: Email subject
        body: Plain text body
        from_email: From address (default: smtp_username)
        cc: CC recipients - comma separated
        bcc: BCC recipients - comma separated
        html_body: HTML body (optional)
        reply_to: Reply-to address
        smtp_port: SMTP port (587 for TLS, 465 for SSL)
        use_tls: Use TLS/STARTTLS

    Returns:
        Send status and message ID
    """
    try:
        # Use smtp_username as from_email if not specified
        if not from_email:
            from_email = smtp_username

        # Create message
        if html_body:
            msg = MIMEMultipart('alternative')
            msg.attach(MIMEText(body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
        else:
            msg = MIMEText(body, 'plain')

        # Set headers
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg['Date'] = email.utils.formatdate(localtime=True)
        msg['Message-ID'] = email.utils.make_msgid()

        if cc:
            msg['Cc'] = cc

        if reply_to:
            msg['Reply-To'] = reply_to

        # Combine all recipients
        recipients = [addr.strip() for addr in to_email.split(',')]
        if cc:
            recipients.extend([addr.strip() for addr in cc.split(',')])
        if bcc:
            recipients.extend([addr.strip() for addr in bcc.split(',')])

        # Send email
        smtp = create_smtp_connection(
            smtp_server,
            smtp_username,
            smtp_password,
            smtp_port,
            use_tls
        )

        try:
            smtp.send_message(msg, from_email, recipients)
            message_id = msg['Message-ID']
            smtp.quit()

            return {
                "success": True,
                "message": "Email sent successfully",
                "message_id": message_id,
                "from": from_email,
                "to": to_email,
                "subject": subject
            }

        except Exception as e:
            smtp.quit()
            raise e

    except AuthenticationError as e:
        return {
            "success": False,
            "error": "authentication_failed",
            "message": str(e)
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
async def reply_to_email(
    server: str,
    username: str,
    password: str,
    email_id: int,
    smtp_server: str,
    smtp_username: str,
    smtp_password: str,
    reply_body: str,
    folder: str = "INBOX",
    quote_original: bool = True,
    reply_all: bool = False,
    smtp_port: int = 587,
    use_tls: bool = True,
    port: int = 993,
    use_ssl: bool = True
) -> Dict[str, Any]:
    """
    Reply to an email maintaining thread.

    Args:
        server: IMAP server hostname
        username: IMAP username
        password: IMAP password
        email_id: Email message ID to reply to
        smtp_server: SMTP server hostname
        smtp_username: SMTP username
        smtp_password: SMTP password
        reply_body: Reply message body
        folder: Folder containing the email
        quote_original: Include quoted original message
        reply_all: Reply to all recipients
        smtp_port: SMTP port
        use_tls: Use TLS for SMTP
        port: IMAP port
        use_ssl: Use SSL for IMAP

    Returns:
        Reply status
    """
    try:
        # Fetch original email
        client = create_imap_connection(server, username, password, port, use_ssl)
        client.select_folder(folder, readonly=True)

        fetch_data = client.fetch([email_id], ['RFC822', 'FLAGS'])
        if email_id not in fetch_data:
            client.logout()
            return {
                "success": False,
                "error": f"Email {email_id} not found"
            }

        raw_message = fetch_data[email_id][b'RFC822']
        original = email.message_from_bytes(raw_message)

        # Extract original details
        original_from = original.get('From', '')
        original_to = original.get('To', '')
        original_cc = original.get('Cc', '')
        original_subject = original.get('Subject', '')
        original_message_id = original.get('Message-ID', '')
        original_references = original.get('References', '')

        client.logout()

        # Parse original body for quoting
        original_body = ""
        if quote_original:
            parsed = parse_email_message(raw_message)
            original_body = parsed.get('text_body', '')

        # Prepare reply
        if not original_subject.lower().startswith('re:'):
            reply_subject = f"Re: {original_subject}"
        else:
            reply_subject = original_subject

        # Determine recipients
        reply_to_addr = original.get('Reply-To', original_from)

        if reply_all:
            # Reply to all: sender + all recipients except us
            all_addrs = f"{reply_to_addr},{original_to}"
            if original_cc:
                all_addrs += f",{original_cc}"

            # Filter out our own address
            addrs = [addr.strip() for addr in all_addrs.split(',')]
            addrs = [addr for addr in addrs if smtp_username not in addr]
            to_addresses = ','.join(addrs)
        else:
            to_addresses = reply_to_addr

        # Build reply body
        if quote_original and original_body:
            quoted = '\n'.join(f"> {line}" for line in original_body.split('\n'))
            full_body = f"{reply_body}\n\n--- Original Message ---\n{quoted}"
        else:
            full_body = reply_body

        # Create reply message
        msg = MIMEText(full_body, 'plain')
        msg['From'] = smtp_username
        msg['To'] = to_addresses
        msg['Subject'] = reply_subject
        msg['In-Reply-To'] = original_message_id

        # Maintain thread
        if original_references:
            msg['References'] = f"{original_references} {original_message_id}"
        else:
            msg['References'] = original_message_id

        msg['Date'] = email.utils.formatdate(localtime=True)
        msg['Message-ID'] = email.utils.make_msgid()

        # Send reply
        smtp = create_smtp_connection(
            smtp_server,
            smtp_username,
            smtp_password,
            smtp_port,
            use_tls
        )

        try:
            smtp.send_message(msg)
            message_id = msg['Message-ID']
            smtp.quit()

            return {
                "success": True,
                "message": "Reply sent successfully",
                "message_id": message_id,
                "in_reply_to": original_message_id,
                "to": to_addresses,
                "subject": reply_subject
            }

        except Exception as e:
            smtp.quit()
            raise e

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
async def forward_email(
    server: str,
    username: str,
    password: str,
    email_id: int,
    smtp_server: str,
    smtp_username: str,
    smtp_password: str,
    to_email: str,
    forward_message: str = "",
    folder: str = "INBOX",
    smtp_port: int = 587,
    use_tls: bool = True,
    port: int = 993,
    use_ssl: bool = True
) -> Dict[str, Any]:
    """
    Forward an email to another recipient.

    Args:
        server: IMAP server hostname
        username: IMAP username
        password: IMAP password
        email_id: Email message ID to forward
        smtp_server: SMTP server hostname
        smtp_username: SMTP username
        smtp_password: SMTP password
        to_email: Forward to email address(es)
        forward_message: Additional message to include
        folder: Folder containing the email
        smtp_port: SMTP port
        use_tls: Use TLS for SMTP
        port: IMAP port
        use_ssl: Use SSL for IMAP

    Returns:
        Forward status
    """
    try:
        # Fetch original email
        client = create_imap_connection(server, username, password, port, use_ssl)
        client.select_folder(folder, readonly=True)

        fetch_data = client.fetch([email_id], ['RFC822'])
        if email_id not in fetch_data:
            client.logout()
            return {
                "success": False,
                "error": f"Email {email_id} not found"
            }

        raw_message = fetch_data[email_id][b'RFC822']
        original = email.message_from_bytes(raw_message)

        client.logout()

        # Parse original
        parsed = parse_email_message(raw_message)

        # Create forward subject
        original_subject = parsed.get('subject', 'No Subject')
        if not original_subject.lower().startswith('fwd:'):
            forward_subject = f"Fwd: {original_subject}"
        else:
            forward_subject = original_subject

        # Build forward body
        forward_body = ""
        if forward_message:
            forward_body = f"{forward_message}\n\n"

        forward_body += f"""---------- Forwarded message ----------
From: {parsed.get('from', '')}
Date: {parsed.get('date', '')}
Subject: {original_subject}
To: {parsed.get('to', '')}

{parsed.get('text_body', '')}"""

        # Note about attachments if present
        if parsed.get('has_attachments'):
            attachments = parsed.get('attachments', [])
            forward_body += f"\n\n[Note: Original email had {len(attachments)} attachment(s): "
            forward_body += ", ".join([att['filename'] for att in attachments])
            forward_body += "]"

        # Send forward
        return await send_email(
            smtp_server=smtp_server,
            smtp_username=smtp_username,
            smtp_password=smtp_password,
            to_email=to_email,
            subject=forward_subject,
            body=forward_body,
            smtp_port=smtp_port,
            use_tls=use_tls
        )

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

# ============================================================================
# Enhanced Email Operations
# ============================================================================

@mcp.tool()
async def batch_mark_emails(
    server: str,
    username: str,
    password: str,
    email_ids: List[int],
    action: str = "read",
    folder: str = "INBOX",
    port: int = 993,
    use_ssl: bool = True
) -> Dict[str, Any]:
    """
    Mark multiple emails at once.

    Args:
        server: IMAP server hostname
        username: Email username
        password: Email password
        email_ids: List of email message IDs
        action: Action to perform ('read', 'unread', 'flag', 'unflag')
        folder: Folder containing the emails
        port: IMAP port
        use_ssl: Use SSL/TLS connection

    Returns:
        Batch operation status
    """
    try:
        client = create_imap_connection(server, username, password, port, use_ssl)
        client.select_folder(folder, readonly=False)

        # Apply action to all emails
        if action == "read":
            client.add_flags(email_ids, [b'\\Seen'])
            operation = "marked as read"
        elif action == "unread":
            client.remove_flags(email_ids, [b'\\Seen'])
            operation = "marked as unread"
        elif action == "flag":
            client.add_flags(email_ids, [b'\\Flagged'])
            operation = "flagged"
        elif action == "unflag":
            client.remove_flags(email_ids, [b'\\Flagged'])
            operation = "unflagged"
        else:
            client.logout()
            return {
                "success": False,
                "error": f"Invalid action: {action}"
            }

        client.logout()

        return {
            "success": True,
            "message": f"{len(email_ids)} emails {operation}",
            "email_ids": email_ids,
            "folder": folder,
            "action": action,
            "count": len(email_ids)
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
async def get_email_thread(
    server: str,
    username: str,
    password: str,
    email_id: int,
    folder: str = "INBOX",
    port: int = 993,
    use_ssl: bool = True
) -> Dict[str, Any]:
    """
    Get all emails in a conversation thread.

    Args:
        server: IMAP server hostname
        username: Email username
        password: Email password
        email_id: Email message ID to find thread for
        folder: Folder to search in
        port: IMAP port
        use_ssl: Use SSL/TLS connection

    Returns:
        List of related emails in the thread
    """
    try:
        client = create_imap_connection(server, username, password, port, use_ssl)
        client.select_folder(folder, readonly=True)

        # Get the original email
        fetch_data = client.fetch([email_id], ['ENVELOPE', 'RFC822.HEADER'])

        if email_id not in fetch_data:
            client.logout()
            return {
                "success": False,
                "error": f"Email {email_id} not found"
            }

        # Parse headers to get thread info
        envelope = fetch_data[email_id][b'ENVELOPE']
        headers = email.message_from_bytes(fetch_data[email_id][b'RFC822.HEADER'])

        subject = decode_header_value(envelope.subject.decode() if envelope.subject else "")
        # Remove Re: and Fwd: prefixes for thread matching
        clean_subject = subject
        for prefix in ['Re:', 'RE:', 'Fwd:', 'FWD:', 'Fw:', 'FW:']:
            clean_subject = clean_subject.replace(prefix, '').strip()

        message_id = headers.get('Message-ID', '')
        references = headers.get('References', '').split()
        in_reply_to = headers.get('In-Reply-To', '')

        # Search for related messages
        thread_emails = []

        # Search by subject (crude but effective)
        if clean_subject:
            # Search for emails with similar subject
            subject_results = client.search(['SUBJECT', clean_subject])

            for msg_id in subject_results:
                msg_data = client.fetch([msg_id], ['ENVELOPE', 'FLAGS', 'INTERNALDATE'])
                if msg_id in msg_data:
                    env = msg_data[msg_id][b'ENVELOPE']
                    flags = msg_data[msg_id].get(b'FLAGS', [])
                    date = msg_data[msg_id].get(b'INTERNALDATE')

                    from_str = ""
                    if env.from_:
                        addr = env.from_[0]
                        from_str = f"{addr.name.decode() if addr.name else ''} <{addr.mailbox.decode()}@{addr.host.decode()}>".strip()

                    thread_emails.append({
                        "id": msg_id,
                        "subject": decode_header_value(env.subject.decode() if env.subject else ""),
                        "from": from_str,
                        "date": date.isoformat() if date else None,
                        "is_seen": b'\\Seen' in flags,
                        "is_current": msg_id == email_id
                    })

        # Sort by date
        thread_emails.sort(key=lambda x: x['date'] or '')

        client.logout()

        return {
            "success": True,
            "thread_count": len(thread_emails),
            "current_email_id": email_id,
            "emails": thread_emails,
            "subject": subject
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool()
async def search_by_date_range(
    server: str,
    username: str,
    password: str,
    start_date: str,
    end_date: str,
    folder: str = "INBOX",
    port: int = 993,
    use_ssl: bool = True,
    limit: int = 100
) -> Dict[str, Any]:
    """
    Search emails within a date range.

    Args:
        server: IMAP server hostname
        username: Email username
        password: Email password
        start_date: Start date (YYYY-MM-DD)
        end_date: End date (YYYY-MM-DD)
        folder: Folder to search in
        port: IMAP port
        use_ssl: Use SSL/TLS connection
        limit: Maximum results

    Returns:
        List of emails in date range
    """
    try:
        client = create_imap_connection(server, username, password, port, use_ssl)
        client.select_folder(folder, readonly=True)

        # Convert dates to IMAP format (DD-MMM-YYYY)
        from datetime import datetime
        start_dt = datetime.strptime(start_date, "%Y-%m-%d")
        end_dt = datetime.strptime(end_date, "%Y-%m-%d")

        start_imap = start_dt.strftime("%d-%b-%Y")
        end_imap = end_dt.strftime("%d-%b-%Y")

        # Search within date range
        criteria = ['SINCE', start_imap, 'BEFORE', end_imap]
        messages = client.search(criteria)

        if not messages:
            client.logout()
            return {
                "success": True,
                "emails": [],
                "total": 0,
                "date_range": f"{start_date} to {end_date}"
            }

        # Limit results
        messages = list(messages)
        messages.reverse()  # Newest first
        total = len(messages)
        messages = messages[:limit]

        # Fetch email data
        email_list = []
        fetch_data = client.fetch(
            messages,
            ['ENVELOPE', 'FLAGS', 'INTERNALDATE', 'UID']
        )

        for msg_id, data in fetch_data.items():
            envelope = data[b'ENVELOPE']
            flags = data.get(b'FLAGS', [])
            date = data.get(b'INTERNALDATE')

            subject = decode_header_value(envelope.subject.decode() if envelope.subject else "")
            from_str = ""
            if envelope.from_:
                addr = envelope.from_[0]
                from_str = f"{addr.name.decode() if addr.name else ''} <{addr.mailbox.decode()}@{addr.host.decode()}>".strip()

            email_list.append({
                "id": msg_id,
                "subject": subject,
                "from": from_str,
                "date": date.isoformat() if date else None,
                "is_seen": b'\\Seen' in flags,
                "is_flagged": b'\\Flagged' in flags
            })

        client.logout()

        return {
            "success": True,
            "emails": email_list,
            "total": total,
            "returned": len(email_list),
            "date_range": f"{start_date} to {end_date}",
            "folder": folder
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

# ============================================================================
# Main execution for local testing
# ============================================================================

if __name__ == "__main__":
    import asyncio

    async def test_server():
        """Test the MCP server locally."""
        print("FastMCP Email Server (IMAP/SMTP)")
        print("=" * 50)
        print("Server is ready for MCP connections.")
        print("\nFeatures:")
        print("  - Send emails via SMTP")
        print("  - Read and manage emails via IMAP")
        print("  - Reply and forward emails")
        print("  - Batch operations")
        print("  - Email thread management")
        print("\nUse 'fastmcp dev server.py' to run in development mode.")

    asyncio.run(test_server())