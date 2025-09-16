"""
FastMCP IMAP Server
===================
An MCP server for IMAP email operations with dynamic credential handling.
No environment variables required - all credentials passed as parameters.
"""

import ssl
import email
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
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
    name="IMAP Email Server",
    instructions="""
    IMAP Email Server for MCP

    This server provides comprehensive IMAP email operations without requiring
    environment variables. All credentials are passed dynamically to each tool.

    Key Features:
    - Test IMAP connections
    - List and search emails
    - Read email content
    - Manage emails (move, delete, flag)
    - Folder operations

    All tools require IMAP server credentials as parameters.
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
# Main execution for local testing
# ============================================================================

if __name__ == "__main__":
    import asyncio

    async def test_server():
        """Test the MCP server locally."""
        print("FastMCP IMAP Server")
        print("=" * 50)
        print("Server is ready for MCP connections.")
        print("\nAvailable tools:")
        for tool in mcp.list_tools():
            print(f"  - {tool.name}")
        print("\nUse 'fastmcp dev server.py' to run in development mode.")

    asyncio.run(test_server())