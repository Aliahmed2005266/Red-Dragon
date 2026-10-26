"""
Encoding Handler Module - Provides advanced encoding/decoding for payload testing
"""

import base64
import urllib.parse
import json
import re

class EncodingHandler:
    """Handles various encoding schemes for payload obfuscation and bypass testing"""
    
    @staticmethod
    def url_encode(payload):
        """Standard URL encoding"""
        return urllib.parse.quote(payload, safe='')
    
    @staticmethod
    def url_double_encode(payload):
        """Double URL encoding for WAF bypass"""
        first_encode = urllib.parse.quote(payload, safe='')
        return urllib.parse.quote(first_encode, safe='')
    
    @staticmethod
    def base64_encode(payload):
        """Base64 encoding"""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def base64_decode(payload):
        """Base64 decoding"""
        try:
            return base64.b64decode(payload).decode()
        except:
            return payload
    
    @staticmethod
    def hex_encode(payload):
        """Hexadecimal encoding"""
        return payload.encode().hex()
    
    @staticmethod
    def hex_decode(payload):
        """Hexadecimal decoding"""
        try:
            return bytes.fromhex(payload).decode()
        except:
            return payload
    
    @staticmethod
    def unicode_encode(payload):
        """Unicode encoding for bypass"""
        encoded = ''
        for char in payload:
            encoded += f'\\u{ord(char):04x}'
        return encoded
    
    @staticmethod
    def html_encode(payload):
        """HTML entity encoding"""
        encoded = ''
        for char in payload:
            encoded += f'&#{ord(char)};'
        return encoded
    
    @staticmethod
    def mixed_case_encode(payload):
        """Mixed case encoding for signature bypass"""
        result = ''
        for i, char in enumerate(payload):
            if i % 2 == 0:
                result += char.lower()
            else:
                result += char.upper()
        return result
    
    @staticmethod
    def null_byte_encode(payload):
        """Null byte injection"""
        return payload + '%00'
    
    @staticmethod
    def unicode_normalize(payload):
        """Unicode normalization bypass"""
        replacements = {
            '<': '\u2039',
            '>': '\u203A',
            "'": '\u2018',
            '"': '\u201C',
            '=': '\u207C',
            '(': '\u207D',
            ')': '\u207E',
        }
        result = payload
        for char, replacement in replacements.items():
            result = result.replace(char, replacement)
        return result
    
    @staticmethod
    def tab_whitespace_encode(payload):
        """Tab/newline whitespace bypass for SQLi"""
        return payload.replace(' ', '\t')
    
    @staticmethod
    def comment_insertion(payload):
        """Comment insertion for SQLi bypass"""
        result = ''
        for char in payload:
            if char in ["'", '"', '=', '(', ')', ';']:
                result += f'/**/{char}/**/'
            else:
                result += char
        return result
    
    @staticmethod
    @staticmethod
    def url_decode(payload):
        """Standard URL decoding"""
        try:
            return urllib.parse.unquote(payload)
        except:
            return payload
    
    @staticmethod
    def url_double_decode(payload):
        """Double URL decoding for WAF bypass testing"""
        try:
            first = urllib.parse.unquote(payload)
            return urllib.parse.unquote(first)
        except:
            return payload
    
    @staticmethod
    def base64_decode(payload):
        """Base64 decoding with padding fix"""
        try:
            padding = 4 - (len(payload) % 4)
            if padding != 4:
                payload += '=' * padding
            return base64.b64decode(payload).decode()
        except:
            return payload
    
    @staticmethod
    def hex_decode(payload):
        """Hexadecimal decoding (supports 0x and \\x prefixes)"""
        try:
            clean = payload.replace('0x', '').replace('\\x', '').replace(' ', '')
            return bytes.fromhex(clean).decode()
        except:
            return payload
    
    @staticmethod
    def unicode_decode(payload):
        """Unicode escape decoding (\\uXXXX)"""
        try:
            def replace_match(match):
                return chr(int(match.group(1), 16))
            return re.sub(r'\\u([0-9a-fA-F]{4})', replace_match, payload)
        except:
            return payload
    
    @staticmethod
    def html_decode(payload):
        """HTML entity decoding (&#NN; and named entities)"""
        import html
        try:
            return html.unescape(payload)
        except:
            return payload
    
    @staticmethod
    def mixed_case_decode(payload):
        """Normalize mixed case encoding"""
        return payload.lower()
    
    @staticmethod
    def null_byte_decode(payload):
        """Remove null byte injections"""
        return payload.replace('%00', '').replace('\x00', '')
    
    @staticmethod
    def tab_whitespace_decode(payload):
        """Reverse tab/whitespace bypass"""
        return payload.replace('\t', ' ').replace('\n', ' ')
    
    @staticmethod
    def comment_removal(payload):
        """Remove SQL comment insertions"""
        return re.sub(r'/\*\*/', '', payload)
    
    @staticmethod
    def unicode_normalize_revert(payload):
        """Revert unicode normalization bypass"""
        reverse_map = {
            '\u2039': '<', '\u203A': '>', '\u2018': "'", '\u2019': "'",
            '\u201C': '"', '\u201D': '"', '\u207C': '=', '\u207D': '(', '\u207E': ')',
        }
        result = payload
        for uni, char in reverse_map.items():
            result = result.replace(uni, char)
        return result
    
    @staticmethod
    def decode_all(payload):
        """Apply all decodings and return a dict of results"""
        return {
            'url_decoded': EncodingHandler.url_decode(payload),
            'double_url_decoded': EncodingHandler.url_double_decode(payload),
            'base64_decoded': EncodingHandler.base64_decode(payload),
            'hex_decoded': EncodingHandler.hex_decode(payload),
            'unicode_decoded': EncodingHandler.unicode_decode(payload),
            'html_decoded': EncodingHandler.html_decode(payload),
            'mixed_case_decoded': EncodingHandler.mixed_case_decode(payload),
            'null_byte_cleaned': EncodingHandler.null_byte_decode(payload),
            'whitespace_normalized': EncodingHandler.tab_whitespace_decode(payload),
            'comments_removed': EncodingHandler.comment_removal(payload),
            'unicode_normalized': EncodingHandler.unicode_normalize_revert(payload),
        }
    
    @staticmethod
    def detect_and_decode(payload):
        """Auto-detect encoding type and decode"""
        # Try base64 first (most distinctive)
        b64_result = EncodingHandler.base64_decode(payload)
        if b64_result != payload and len(b64_result) > 0:
            printable = sum(1 for c in b64_result if c.isprintable() or c in '\n\r\t')
            if printable / max(len(b64_result), 1) > 0.8:
                return ('base64', b64_result)
        
        # Try URL decode
        url_result = EncodingHandler.url_decode(payload)
        if url_result != payload:
            return ('url', url_result)
        
        # Try hex
        hex_result = EncodingHandler.hex_decode(payload)
        if hex_result != payload and len(hex_result) > 0:
            printable = sum(1 for c in hex_result if c.isprintable() or c in '\n\r\t')
            if printable / max(len(hex_result), 1) > 0.8:
                return ('hex', hex_result)
        
        # Try HTML
        html_result = EncodingHandler.html_decode(payload)
        if html_result != payload:
            return ('html', html_result)
        
        # Try unicode
        unicode_result = EncodingHandler.unicode_decode(payload)
        if unicode_result != payload:
            return ('unicode', unicode_result)
        
        return ('none', payload)
    
        """Generate multiple encoding variants of a payload"""
        if encoding_types is None:
            encoding_types = [
                'url', 'double_url', 'base64', 'hex', 'unicode', 
                'html', 'mixed_case', 'null_byte', 'tab_whitespace',
                'comment_insertion', 'unicode_normalize'
            ]
        
        variants = {
            'original': payload,
            'url_encoded': None,
            'double_url_encoded': None,
            'base64_encoded': None,
            'hex_encoded': None,
            'unicode_encoded': None,
            'html_encoded': None,
            'mixed_case': None,
            'null_byte': None,
            'tab_whitespace': None,
            'comment_insertion': None,
            'unicode_normalized': None,
        }
        
        encoding_map = {
            'url': ('url_encoded', EncodingHandler.url_encode),
            'double_url': ('double_url_encoded', EncodingHandler.url_double_encode),
            'base64': ('base64_encoded', EncodingHandler.base64_encode),
            'hex': ('hex_encoded', EncodingHandler.hex_encode),
            'unicode': ('unicode_encoded', EncodingHandler.unicode_encode),
            'html': ('html_encoded', EncodingHandler.html_encode),
            'mixed_case': ('mixed_case', EncodingHandler.mixed_case_encode),
            'null_byte': ('null_byte', EncodingHandler.null_byte_encode),
            'tab_whitespace': ('tab_whitespace', EncodingHandler.tab_whitespace_encode),
            'comment_insertion': ('comment_insertion', EncodingHandler.comment_insertion),
            'unicode_normalize': ('unicode_normalized', EncodingHandler.unicode_normalize),
        }
        
        for enc_type in encoding_types:
            if enc_type in encoding_map:
                key, func = encoding_map[enc_type]
                try:
                    variants[key] = func(payload)
                except:
                    continue
        
        return variants

    @staticmethod
    def get_sqli_encoded_payloads():
        """Generate SQL injection payloads with various encodings"""
        base_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "' AND 1=1--",
            "' SLEEP(5)--",
        ]
        
        encoded_payloads = []
        for payload in base_payloads:
            variants = EncodingHandler.generate_payload_variants(payload)
            encoded_payloads.extend([v for v in variants.values() if v is not None])
        
        return encoded_payloads

    @staticmethod
    def get_xss_encoded_payloads():
        """Generate XSS payloads with various encodings"""
        base_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
        ]
        
        encoded_payloads = []
        for payload in base_payloads:
            variants = EncodingHandler.generate_payload_variants(payload)
            encoded_payloads.extend([v for v in variants.values() if v is not None])
        
        return encoded_payloads

class AdvancedEncoder:
    """Advanced encoding with multiple layers for sophisticated bypass testing"""
    
    @staticmethod
    def multi_layer_encode(payload, layers=3):
        """Apply multiple encoding layers"""
        result = payload
        for i in range(layers):
            # Alternate between encoding types
            if i % 3 == 0:
                result = EncodingHandler.url_encode(result)
            elif i % 3 == 1:
                result = EncodingHandler.base64_encode(result)
            else:
                result = EncodingHandler.hex_encode(result)
        return result
    
    @staticmethod
    def generate_bypass_chain(payload):
        """Generate a chain of bypass techniques"""
        chain = []
        chain.append(payload)
        chain.append(EncodingHandler.url_encode(payload))
        chain.append(EncodingHandler.url_double_encode(payload))
        chain.append(EncodingHandler.mixed_case_encode(payload))
        chain.append(EncodingHandler.null_byte_encode(payload))
        chain.append(EncodingHandler.comment_insertion(payload))
        chain.append(EncodingHandler.tab_whitespace_encode(payload))
        
        # Multi-layer
        for i in range(1, 4):
            chain.append(AdvancedEncoder.multi_layer_encode(payload, i))
        
        return chain


class Decoder:
    """Advanced decoder with chaining and auto-detection capabilities"""
    
    @staticmethod
    def decode_chain(payload, encodings):
        """Decode a payload through a chain of encoding types in order"""
        result = payload
        for enc in encodings:
            result = decode_payload(result, enc)
        return result
    
    @staticmethod
    def smart_decode(payload, max_iterations=10):
        """Iteratively decode until no more changes detected"""
        result = payload
        for _ in range(max_iterations):
            detected, decoded = EncodingHandler.detect_and_decode(result)
            if detected == 'none' or decoded == result:
                break
            result = decoded
        return result
    
    @staticmethod
    def brute_force_decode(payload):
        """Try all decoding methods and return all successful results"""
        results = {}
        decoders = {
            'url': EncodingHandler.url_decode,
            'double_url': EncodingHandler.url_double_decode,
            'base64': EncodingHandler.base64_decode,
            'hex': EncodingHandler.hex_decode,
            'unicode': EncodingHandler.unicode_decode,
            'html': EncodingHandler.html_decode,
            'mixed_case': EncodingHandler.mixed_case_decode,
            'null_byte': EncodingHandler.null_byte_decode,
            'whitespace': EncodingHandler.tab_whitespace_decode,
            'comments': EncodingHandler.comment_removal,
            'unicode_normalize': EncodingHandler.unicode_normalize_revert,
        }
        for name, func in decoders.items():
            try:
                decoded = func(payload)
                if decoded != payload:
                    results[name] = decoded
            except:
                continue
        return results


# Module-level dispatcher functions for easy API use
def encode_payload(payload, encoding_type):
    """Encode a payload using the specified encoding type"""
    encoders = {
        'url': EncodingHandler.url_encode,
        'double_url': EncodingHandler.url_double_encode,
        'base64': EncodingHandler.base64_encode,
        'hex': EncodingHandler.hex_encode,
        'unicode': EncodingHandler.unicode_encode,
        'html': EncodingHandler.html_encode,
        'mixed_case': EncodingHandler.mixed_case_encode,
        'null_byte': EncodingHandler.null_byte_encode,
        'unicode_normalize': EncodingHandler.unicode_normalize,
        'tab_whitespace': EncodingHandler.tab_whitespace_encode,
        'comment_insertion': EncodingHandler.comment_insertion,
    }
    encoder = encoders.get(encoding_type)
    if encoder:
        return encoder(payload)
    raise ValueError(f"Unknown encoding type: {encoding_type}. Available: {', '.join(encoders.keys())}")


def decode_payload(payload, encoding_type):
    """Decode a payload using the specified encoding type"""
    decoders = {
        'url': EncodingHandler.url_decode,
        'double_url': EncodingHandler.url_double_decode,
        'base64': EncodingHandler.base64_decode,
        'hex': EncodingHandler.hex_decode,
        'unicode': EncodingHandler.unicode_decode,
        'html': EncodingHandler.html_decode,
        'mixed_case': EncodingHandler.mixed_case_decode,
        'null_byte': EncodingHandler.null_byte_decode,
        'whitespace': EncodingHandler.tab_whitespace_decode,
        'comments': EncodingHandler.comment_removal,
        'unicode_normalize': EncodingHandler.unicode_normalize_revert,
    }
    decoder = decoders.get(encoding_type)
    if decoder:
        return decoder(payload)
    raise ValueError(f"Unknown decoding type: {encoding_type}. Available: {', '.join(decoders.keys())}")


def get_available_encodings():
    """Return dict of available encoding and decoding types"""
    return {
        'encodings': [
            'url', 'double_url', 'base64', 'hex', 'unicode', 'html',
            'mixed_case', 'null_byte', 'unicode_normalize', 'tab_whitespace', 'comment_insertion'
        ],
        'decodings': [
            'url', 'double_url', 'base64', 'hex', 'unicode', 'html',
            'mixed_case', 'null_byte', 'whitespace', 'comments', 'unicode_normalize'
        ]
    }