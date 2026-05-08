#!/usr/bin/env python3
"""
Convert JSON backup data to HTML table format.
Supports both local JSON files and API endpoints.
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Any
import requests

# ANSI color codes for terminal output
GREEN = '\033[92m'
BLUE = '\033[94m'
RESET = '\033[0m'


def json_to_html_table(data: Any, title: str = "Data") -> str:
    """Convert JSON data to HTML table format."""
    
    html_parts = []
    
    def process_value(value: Any) -> str:
        """Convert a value to HTML representation."""
        if isinstance(value, bool):
            return f'<span style="color: #0066cc; font-weight: bold;">{str(value)}</span>'
        elif isinstance(value, (int, float)):
            return f'<span style="color: #cc0000;">{value}</span>'
        elif value is None:
            return '<span style="color: #999999;">null</span>'
        elif isinstance(value, list):
            if len(value) == 0:
                return '[]'
            elif all(isinstance(x, (str, int, float, bool, type(None))) for x in value):
                return ', '.join(process_value(v) for v in value)
            else:
                return f'<details><summary>Array ({len(value)} items)</summary>{process_value(value)}</details>'
        elif isinstance(value, dict):
            return '<details><summary>Object</summary>' + dict_to_table(value) + '</details>'
        else:
            return str(value)
    
    def dict_to_table(d: dict) -> str:
        """Convert a dictionary to an HTML table."""
        if not d:
            return '<p><em>Empty object</em></p>'
        
        table_html = '<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; margin: 10px 0; width: 100%;">'
        table_html += '<thead><tr style="background-color: #f0f0f0;"><th style="text-align: left;">Key</th><th style="text-align: left;">Value</th></tr></thead>'
        table_html += '<tbody>'
        
        for key, value in d.items():
            value_html = process_value(value)
            # Escape HTML special characters in keys
            safe_key = str(key).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            table_html += f'<tr><td style="font-weight: bold; vertical-align: top;">{safe_key}</td><td>{value_html}</td></tr>'
        
        table_html += '</tbody></table>'
        return table_html
    
    def list_to_table(lst: list) -> str:
        """Convert a list of items to HTML tables."""
        if not lst:
            return '<p><em>Empty array</em></p>'
        
        # If list of dictionaries with same keys, create a nice table
        if all(isinstance(item, dict) for item in lst):
            # Get all unique keys
            all_keys = set()
            for item in lst:
                all_keys.update(item.keys())
            all_keys = sorted(list(all_keys))
            
            if all_keys:
                table_html = '<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; margin: 10px 0; width: 100%;">'
                table_html += '<thead><tr style="background-color: #4CAF50; color: white;">'
                
                for key in all_keys:
                    safe_key = str(key).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    table_html += f'<th style="text-align: left; padding: 12px;">{safe_key}</th>'
                
                table_html += '</tr></thead><tbody>'
                
                # Alternate row colors
                for idx, item in enumerate(lst):
                    bg_color = '#f9f9f9' if idx % 2 == 0 else '#ffffff'
                    table_html += f'<tr style="background-color: {bg_color};">'
                    
                    for key in all_keys:
                        value = item.get(key, '')
                        value_html = process_value(value)
                        table_html += f'<td style="padding: 10px; vertical-align: top;">{value_html}</td>'
                    
                    table_html += '</tr>'
                
                table_html += '</tbody></table>'
                return table_html
        
        # Fallback: list of individual items
        html = '<ol>'
        for item in lst:
            if isinstance(item, dict):
                html += '<li>' + dict_to_table(item) + '</li>'
            else:
                html += f'<li>{process_value(item)}</li>'
        html += '</ol>'
        return html
    
    if isinstance(data, dict):
        html_parts.append(dict_to_table(data))
    elif isinstance(data, list):
        html_parts.append(list_to_table(data))
    else:
        html_parts.append(f'<p>{process_value(data)}</p>')
    
    return '\n'.join(html_parts)


def create_html_document(content: str, title: str = "JSON to HTML Converter") -> str:
    """Wrap content in a complete HTML document."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        
        h1 {{
            color: #333;
            margin-bottom: 10px;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .metadata {{
            font-size: 12px;
            color: #666;
            margin-bottom: 20px;
            background: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
        }}
        
        table {{
            font-size: 14px;
            line-height: 1.5;
        }}
        
        table thead th {{
            background-color: #667eea;
            color: white;
            font-weight: bold;
            text-align: left;
        }}
        
        table tbody tr:hover {{
            background-color: #f0f0f0 !important;
        }}
        
        details {{
            margin: 5px 0;
            padding: 8px;
            background: #f9f9f9;
            border-left: 3px solid #667eea;
            border-radius: 3px;
        }}
        
        details summary {{
            cursor: pointer;
            font-weight: bold;
            color: #667eea;
            user-select: none;
        }}
        
        details summary:hover {{
            color: #764ba2;
        }}
        
        details[open] summary {{
            margin-bottom: 10px;
        }}
        
        .timestamp {{
            font-size: 11px;
            color: #999;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📊 {title}</h1>
        <div class="metadata">
            <p>Generated: <span class="timestamp">{timestamp}</span></p>
        </div>
        <div class="content">
            {content}
        </div>
    </div>
</body>
</html>"""
    
    return html


def convert_json_file(json_path: str, output_path: str = None) -> str:
    """Convert a JSON file to HTML table format."""
    json_file = Path(json_path)
    
    if not json_file.exists():
        print(f"{'\033[91m'}Error: File not found: {json_path}{RESET}")
        sys.exit(1)
    
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"{'\033[91m'}Error: Invalid JSON in file: {e}{RESET}")
        sys.exit(1)
    
    # Generate HTML
    title = json_file.stem.replace('_', ' ').title()
    html_content = json_to_html_table(data, title)
    html_document = create_html_document(html_content, title)
    
    # Determine output path
    if output_path is None:
        output_path = json_file.with_suffix('.html')
    
    # Write HTML file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_document)
    
    print(f"{GREEN}✓ Converted: {json_file}{RESET}")
    print(f"{GREEN}✓ Output: {output_path}{RESET}")
    
    return str(output_path)


def fetch_backup_from_api(api_url: str, token: str = None, output_path: str = None) -> str:
    """Fetch backup from API endpoint and convert to HTML."""
    try:
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = f'Bearer {token}'
        
        print(f"{BLUE}Fetching backup from: {api_url}{RESET}")
        response = requests.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        # Generate HTML
        title = "System Backup"
        html_content = json_to_html_table(data, title)
        html_document = create_html_document(html_content, title)
        
        # Determine output path
        if output_path is None:
            output_path = "backup.html"
        
        # Write HTML file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_document)
        
        print(f"{GREEN}✓ Backup fetched and converted{RESET}")
        print(f"{GREEN}✓ Output: {output_path}{RESET}")
        
        return str(output_path)
    
    except requests.RequestException as e:
        print(f"{'\033[91m'}Error fetching backup: {e}{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{BLUE}JSON to HTML Table Converter{RESET}")
        print("\nUsage:")
        print("  Convert JSON file:")
        print("    python json_to_html_converter.py <input.json> [output.html]")
        print("\n  Fetch from API endpoint:")
        print("    python json_to_html_converter.py --api <url> [--token <jwt>] [--output file.html]")
        print("\nExample:")
        print("  python json_to_html_converter.py backup.json backup.html")
        print("  python json_to_html_converter.py --api http://localhost:8000/api/v1/admin/backup/snapshot --output backup.html")
        sys.exit(0)
    
    if sys.argv[1] == "--api":
        # API mode
        if len(sys.argv) < 3:
            print(f"{'\033[91m'}Error: API URL required{RESET}")
            sys.exit(1)
        
        api_url = sys.argv[2]
        token = None
        output_path = None
        
        # Parse optional arguments
        i = 3
        while i < len(sys.argv):
            if sys.argv[i] == "--token":
                token = sys.argv[i + 1]
                i += 2
            elif sys.argv[i] == "--output":
                output_path = sys.argv[i + 1]
                i += 2
            else:
                i += 1
        
        fetch_backup_from_api(api_url, token, output_path)
    else:
        # File mode
        json_path = sys.argv[1]
        output_path = sys.argv[2] if len(sys.argv) > 2 else None
        convert_json_file(json_path, output_path)
