import zipfile
import os

def extract_zip(zip_filename, extract_to_directory):
    os.makedirs(extract_to_directory, exist_ok=True)
    
    try:
        with zipfile.ZipFile(zip_filename, 'r') as zip_ref:
            zip_ref.testzip()  # Check for any errors in the archive
            zip_ref.extractall(extract_to_directory)
        print(f"Extraction complete. Files extracted to: {extract_to_directory}")
    except zipfile.BadZipFile:
        print(f"Error: {zip_filename} is not a valid zip file.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example usage
extract_zip('suspicious_data.zip', 'extracted_files')
