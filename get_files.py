import os
import json

def get_all_files(directory):
    file_list = []
    ignore_dirs = {'.git', 'node_modules', 'venv', '__pycache__', '.venv', 'env'}
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for file in files:
            if file.endswith(('.py', '.js', '.html', '.css', '.json', '.yml', '.yaml', '.sh', '.md')):
                file_list.append(os.path.join(root, file))
    return file_list

if __name__ == '__main__':
    directory = 'c:\\Users\\gusta\\Desktop\\scannerfinal\\scanner-fixed-v51\\scanner-fixed'
    files = get_all_files(directory)
    with open(os.path.join(directory, 'files_list_output.json'), 'w') as f:
        json.dump(files, f, indent=2)
