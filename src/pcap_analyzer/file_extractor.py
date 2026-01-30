"""File extraction utilities for extracting files from network streams.

This module provides functionality to extract files from reassembled
TCP streams, particularly focusing on HTTP responses that may contain
flags or other interesting data.
"""

import mimetypes
import os
import re
from typing import Any, Dict, List, TypedDict


class ExtractedFileInfo(TypedDict):
    """Type definition for extracted file metadata.

    Attributes:
        filename: Name of the extracted file.
        path: Full filesystem path where file was saved.
        size: Size of the extracted file in bytes.
        stream_id: Identifier of the source stream.
    """

    filename: str
    path: str
    size: int
    stream_id: str


class FileExtractor:
    """Extracts files from reassembled TCP stream payloads.

    This class analyzes reassembled TCP stream data, identifies HTTP
    responses, and extracts file bodies to disk. It attempts to
    determine appropriate filenames from Content-Disposition headers
    or Content-Type MIME types.

    Attributes:
        output_dir: Directory where extracted files are saved.

    Example:
        >>> extractor = FileExtractor(output_dir="./extracted")
        >>> files = extractor.extract_from_stream("stream_1", payload_bytes)
        >>> for f in files:
        ...     print(f"Extracted: {f['filename']}")
    """

    def __init__(self, output_dir: str = "extracted_files") -> None:
        """Initialize the file extractor.

        Args:
            output_dir: Directory path where extracted files will be saved.
                Created if it does not exist.
        """
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def extract_from_stream(
        self,
        stream_id: str,
        payload_bytes: bytes
    ) -> List[ExtractedFileInfo]:
        """Extract files from a reassembled stream payload.

        Attempts to identify HTTP responses within the payload and
        extract the response body as a file. Filename is determined
        from Content-Disposition header if present, otherwise from
        Content-Type MIME type.

        Args:
            stream_id: Unique identifier for the stream (used in fallback
                filename generation).
            payload_bytes: Raw bytes of the reassembled TCP stream payload.

        Returns:
            List of ExtractedFileInfo dictionaries, one per extracted file.
            Empty list if no files could be extracted.

        Note:
            Currently focuses on HTTP/1.x responses with standard header
            formatting. Chunked transfer encoding is not yet supported.
        """
        files_found: List[ExtractedFileInfo] = []

        try:
            # Look for HTTP/1.x responses
            # Header end sequence is \r\n\r\n
            header_end_idx = payload_bytes.find(b'\r\n\r\n')
            if header_end_idx == -1:
                return []

            headers_raw = payload_bytes[:header_end_idx]
            body = payload_bytes[header_end_idx + 4:]

            # Check if likely HTTP
            if not headers_raw.startswith(b'HTTP/'):
                return []

            # Parse headers for filename or extension
            headers_str = headers_raw.decode('utf-8', errors='ignore')

            filename: str | None = None
            extension = ".bin"

            # 1. Content-Disposition: attachment; filename="flag.png"
            match_disp = re.search(
                r'Content-Disposition:.*filename="?([^";\r\n]+)"?',
                headers_str,
                re.IGNORECASE
            )
            if match_disp:
                filename = match_disp.group(1)

            # 2. Content-Type: image/png
            if not filename:
                match_type = re.search(
                    r'Content-Type: ([^;\r\n]+)',
                    headers_str,
                    re.IGNORECASE
                )
                if match_type:
                    ctype = match_type.group(1).strip()
                    ext = mimetypes.guess_extension(ctype)
                    if ext:
                        extension = ext

            if not filename:
                # Sanitize stream_id for filename
                safe_id = re.sub(r'[^a-zA-Z0-9]', '_', stream_id)
                filename = f"stream_{safe_id}{extension}"

            filepath = os.path.join(self.output_dir, filename)

            # Save file
            with open(filepath, 'wb') as f:
                f.write(body)

            files_found.append({
                'filename': filename,
                'path': filepath,
                'size': len(body),
                'stream_id': stream_id
            })

        except Exception:
            pass

        return files_found
