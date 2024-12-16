import hashlib
import os
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
import time

class FileActivityHandler(FileSystemEventHandler):
    def __init__(self):
        self.file_renames = 0
        self.file_modifications = 0
        self.file_deletions = 0
        self.file_creations = 0
        self.hashed_files = {}

    def on_modified(self, event):
        if event.is_directory:
            return
        self.file_modifications += 1
        self.detect_encryption(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.file_creations += 1

    def on_deleted(self, event):
        if not event.is_directory:
            self.file_deletions += 1

    def on_moved(self, event):
        self.file_renames += 1

    def detect_encryption(self, file_path):
        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
                if file_path in self.hashed_files:
                    if self.hashed_files[file_path] != file_hash:
                        print(f"Encryption detected: {file_path}")
                self.hashed_files[file_path] = file_hash
        except Exception:
            pass

def start_file_observer(path):
    handler = FileActivityHandler()
    observer = Observer()
    observer.schedule(handler, path, recursive=True)
    observer.start()
    return handler, observer
