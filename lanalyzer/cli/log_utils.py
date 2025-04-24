"""
Log Utilities Module - Provides logging and output redirection functionalities.
"""

import datetime


class LogTee:
    """Send output to two file objects simultaneously"""

    def __init__(self, file1, file2):
        self.file1 = file1
        self.file2 = file2

    def write(self, data):
        self.file1.write(data)
        self.file2.write(data)
        self.file1.flush()  # Ensure real-time output
        self.file2.flush()

    def flush(self):
        self.file1.flush()
        self.file2.flush()


def get_timestamp():
    """Return the current formatted timestamp"""
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') 