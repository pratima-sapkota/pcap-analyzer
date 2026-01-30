import re
import os
import mimetypes

class FileExtractor:
    def __init__(self, output_dir="extracted_files"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def extract_from_stream(self, stream_id, payload_bytes):
        """
        Attempt to extract files from a reassembled stream payload (bytes).
        Currently focuses on HTTP responses.
        """
        files_found = []
        
        # Look for HTTP/1.x responses with 200 OK
        # Header end sequence is \r\n\r\n
        try:
            # We treat the payload as bytes, but regex on bytes is cleaner for binary separation
            # Pattern: HTTP/1.1 200 OK ... \r\n\r\n (Body)
            
            # Simple heuristic: Split by double newline to separate headers and body
            # We look for the start of an HTTP response
            
            # Note: This is a simplified extractor. It assumes the stream STARTS with the response
            # or we find a clear boundary.
            
            header_end_idx = payload_bytes.find(b'\r\n\r\n')
            if header_end_idx == -1:
                return []
            
            headers_raw = payload_bytes[:header_end_idx]
            body = payload_bytes[header_end_idx+4:]
            
            # Check if likely HTTP
            if not headers_raw.startswith(b'HTTP/'):
                return []
            
            # Parse headers for filename or extension
            headers_str = headers_raw.decode('utf-8', errors='ignore')
            
            filename = None
            extension = ".bin"
            
            # 1. Content-Disposition: attachment; filename="flag.png"
            match_disp = re.search(r'Content-Disposition:.*filename="?([^";\r\n]+)"?', headers_str, re.IGNORECASE)
            if match_disp:
                filename = match_disp.group(1)
            
            # 2. Content-Type: image/png
            if not filename:
                match_type = re.search(r'Content-Type: ([^;\r\n]+)', headers_str, re.IGNORECASE)
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
