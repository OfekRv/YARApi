import os

def search_file(root, file_name):
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            if name == file_name:
                return os.path.join(dirpath, name)
    return None