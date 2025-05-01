import os
import glob

def cleanup_old_files(directory, max_files=5, file_extension="*"):
    """
    Remove arquivos antigos em um diretório, mantendo apenas os 'max_files' mais recentes.
    "Removes old files from a directory, keeping only the most recent 'max_files' files."
    
    Args:
        directory (str): Directory Path (ex.: 'data/bronze/').
        max_files (int): Max retention parameter.
        file_extension (str): Specifies the file extension to look for when scanning the directory. (ex.: '*.json').
    """
    files = glob.glob(os.path.join(directory, file_extension))
    
    files.sort(key=os.path.getmtime, reverse=True)

    if len(files) > max_files:
        for old_file in files[max_files:]:
            try:
                os.remove(old_file)
                print(f"Removed old file: {old_file}")
            except OSError as e:
                print(f"Error removing file {old_file}: {e}")