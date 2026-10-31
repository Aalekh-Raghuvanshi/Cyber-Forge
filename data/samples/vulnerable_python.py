# Sample Vulnerable Python Code
# Use this file to test the LLM Code Analyzer

import os
import pickle
import yaml
import sqlite3
import subprocess

# Hardcoded credentials - BAD PRACTICE
API_KEY = "sk-1234567890abcdefghijklmnop"
DATABASE_PASSWORD = "admin123!@#"
SECRET_TOKEN = "super_secret_token_12345"

def get_user_by_id(user_id):
    """SQL Injection vulnerability - string concatenation in query"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: Direct string concatenation
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchone()

def search_users(name):
    """SQL Injection vulnerability - format string"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: String formatting
    query = "SELECT * FROM users WHERE name LIKE '%{}%'".format(name)
    cursor.execute(query)
    return cursor.fetchall()

def run_system_command(user_command):
    """Command injection vulnerability"""
    # VULNERABLE: Direct command execution with user input
    os.system("echo " + user_command)

def execute_with_subprocess(filename):
    """Command injection via subprocess"""
    # VULNERABLE: Shell=True with user input
    subprocess.call("cat " + filename, shell=True)

def process_user_data(data):
    """Insecure deserialization"""
    # VULNERABLE: Pickle can execute arbitrary code
    return pickle.loads(data)

def load_config(yaml_content):
    """Insecure YAML loading"""
    # VULNERABLE: yaml.load without SafeLoader
    return yaml.load(yaml_content)

def calculate(expression):
    """Arbitrary code execution via eval"""
    # VULNERABLE: eval with user input
    return eval(expression)

def execute_code(code_string):
    """Arbitrary code execution via exec"""
    # VULNERABLE: exec with user input
    exec(code_string)

def read_file(filename):
    """Path traversal vulnerability"""
    # VULNERABLE: No path validation
    with open("/var/data/" + filename, 'r') as f:
        return f.read()

def hash_password(password):
    """Weak cryptography"""
    import hashlib
    # VULNERABLE: MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

def debug_mode():
    """Debug mode in production"""
    # VULNERABLE: Debug should be disabled in production
    debug = True
    return debug

def validate_input(user_input):
    """Using assert for validation"""
    # VULNERABLE: Assert statements removed with -O flag
    assert len(user_input) < 100, "Input too long"
    return user_input
