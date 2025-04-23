import os
import re
import subprocess
import shutil
import json
import stat  # For handling file permissions
import time  # For adding delays between retries
import hashlib
from colorama import init, Fore, Style
init(autoreset=True)  # Initialize colorama for Windows compatibility

class AppUpdater:
    def __init__(self, config_path=os.path.join(os.path.dirname(__file__), "config.json"), target_dir="."):
        self.config = self.load_config(config_path)
        self.target_dir = target_dir  # Directory where files will be updated
        self.backup_dir = os.path.join(self.target_dir, "__backup")  # Backup directory

    @staticmethod
    def handle_remove_readonly(func, path, exc_info):
        """
        Handle the removal of read-only files during shutil.rmtree.
        """
        # Change the file's permissions to writable and retry the operation
        os.chmod(path, stat.S_IWRITE)
        func(path)

    def load_config(self, config_path):
        """Load and validate the configuration file."""
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file '{config_path}' not found.")
        with open(config_path, "r") as f:
            try:
                config = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in configuration file: {e}")
        # Validate required keys
        if "update_source" not in config:
            raise ValueError("Configuration file must specify 'update_source'.")
        if config["update_source"] == "pypi" and "pypi" not in config:
            raise ValueError("Configuration file must include 'pypi' section for PyPI updates.")
        if config["update_source"] == "github" and "github" not in config:
            raise ValueError("Configuration file must include 'github' section for GitHub updates.")
        return config

    def retry_operation(self, operation, *args, retries=3, delay=2, **kwargs):
        """Retry a given operation up to a specified number of times."""
        for attempt in range(1, retries + 1):
            try:
                return operation(*args, **kwargs)
            except Exception as e:
                print(f"Attempt {attempt} failed: {e}")
                if attempt < retries:
                    print(f"Retrying in {delay} seconds...")
                    time.sleep(delay)
                else:
                    print("All attempts failed.")
                    raise

    def create_backup(self):
        """Create a backup of the target directory."""
        if os.path.exists(self.backup_dir):
            shutil.rmtree(self.backup_dir, onerror=self.handle_remove_readonly)
        print(f"Creating backup of {self.target_dir} in {self.backup_dir}...")
        shutil.copytree(self.target_dir, self.backup_dir, dirs_exist_ok=True)

    def restore_backup(self):
        """Restore the backup to the target directory."""
        if os.path.exists(self.backup_dir):
            print(f"Restoring backup from {self.backup_dir} to {self.target_dir}...")
            for root, dirs, files in os.walk(self.backup_dir):
                rel_path = os.path.relpath(root, self.backup_dir)
                target_subdir = os.path.join(self.target_dir, rel_path)
                os.makedirs(target_subdir, exist_ok=True)

                for file in files:
                    source_file = os.path.join(root, file)
                    target_file = os.path.join(target_subdir, file)
                    try:
                        print(f"Restoring {source_file} to {target_file}")
                        shutil.copy2(source_file, target_file)
                    except PermissionError:
                        print(f"Permission denied: Skipping {source_file}")

            shutil.rmtree(self.backup_dir, onerror=self.handle_remove_readonly)
        else:
            print("No backup found to restore.")

    def validate_files(self, source_dir, target_dir):
        """Validate that files were copied correctly."""
        for root, _, files in os.walk(source_dir):
            for file in files:
                source_file = os.path.join(root, file)
                rel_path = os.path.relpath(source_file, source_dir)
                target_file = os.path.join(target_dir, rel_path)

                if not os.path.exists(target_file):
                    print(f"Validation failed: {target_file} is missing.")
                    return False

                if os.path.getsize(source_file) != os.path.getsize(target_file):
                    print(f"Validation failed: {target_file} size mismatch.")
                    return False

        print("Validation successful: All files are intact.")
        return True

    def clone_repo(self, repo_url, branch, temp_dir):
        """Clone a GitHub repository into a temporary directory."""
        print(f"Cloning repository: {repo_url} into {temp_dir}")
        self.retry_operation(
            subprocess.run,
            ["git", "clone", "--branch", branch, "--depth", "1", repo_url, temp_dir],
            check=True
        )

    def copy_files(self, source_dir, target_dir, exclude):
        """Copy files from the source directory to the target directory, excluding specified files/directories."""
        for root, dirs, files in os.walk(source_dir):
            # Calculate relative path from the source directory
            rel_path = os.path.relpath(root, source_dir)

            # Skip excluded directories
            if any(rel_path.startswith(excluded.rstrip("/")) for excluded in exclude if excluded.endswith("/")):
                print(f"Skipping directory: {rel_path}")
                dirs[:] = []  # Prevent descending into this directory
                continue

            # Ensure the corresponding directory exists in the target
            target_subdir = os.path.join(target_dir, rel_path)
            os.makedirs(target_subdir, exist_ok=True)

            # Copy files, skipping excluded ones
            for file in files:
                file_rel_path = os.path.join(rel_path, file)
                if file_rel_path in exclude:
                    print(f"Skipping file: {file_rel_path}")
                    continue

                source_file = os.path.join(root, file)
                target_file = os.path.join(target_subdir, file)
                try:
                    print(f"Copying {source_file} to {target_file}")
                    shutil.copy2(source_file, target_file)
                except PermissionError:
                    print(f"Permission denied: Skipping {source_file}")

    def update_from_github(self):
        """Update the application from GitHub."""
        github_config = self.config.get("github", {})
        repo_url = github_config.get("repo_url")
        branch = github_config.get("branch", "main")
        exclude = github_config.get("exclude", [])

        if not repo_url:
            raise ValueError("GitHub repository URL is not specified in the configuration.")

        # Create a temporary directory for cloning
        temp_dir = os.path.join(self.target_dir, "__temp_repo")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, onerror=self.handle_remove_readonly)

        # Create a backup before updating
        self.create_backup()

        # Hash excluded files and directories before the update
        excluded_file_hashes = {}
        for excluded_path in exclude:
            excluded_full_path = os.path.join(self.target_dir, excluded_path)
            if os.path.isfile(excluded_full_path):
                # Hash individual excluded files
                file_hash = self.calculate_file_hash(excluded_full_path)
                if file_hash is not None:
                    excluded_file_hashes[excluded_path] = file_hash
                else:
                    print(f"Skipping missing excluded file: {excluded_path}")
            elif os.path.isdir(excluded_full_path):
                # Hash all files in excluded directories
                for root, _, files in os.walk(excluded_full_path):
                    for file in files:
                        file_rel_path = os.path.relpath(os.path.join(root, file), self.target_dir)
                        file_hash = self.calculate_file_hash(os.path.join(root, file))
                        if file_hash is not None:
                            excluded_file_hashes[file_rel_path] = file_hash
                        else:
                            print(f"Skipping missing excluded file: {file_rel_path}")

        try:
            # Clone the repository
            self.clone_repo(repo_url, branch, temp_dir)

            # Copy files to the target directory, excluding specified files/directories
            self.copy_files(temp_dir, self.target_dir, exclude)

            # Validate the update
            if not self.validate_files(temp_dir, self.target_dir):
                raise ValueError("Validation failed: Restoring backup...")

            # Hash excluded files and directories after the update and compare
            for excluded_file, original_hash in excluded_file_hashes.items():
                excluded_file_path = os.path.join(self.target_dir, excluded_file)
                new_hash = self.calculate_file_hash(excluded_file_path)
                if new_hash is None:
                    print(f"Missing excluded file after update: {excluded_file}. Restoring from backup...")
                    backup_file_path = os.path.join(self.backup_dir, excluded_file)
                    shutil.copy2(backup_file_path, excluded_file_path)
                elif original_hash != new_hash:
                    print(f"Hash mismatch for excluded file after update: {excluded_file}. Restoring from backup...")
                    backup_file_path = os.path.join(self.backup_dir, excluded_file)
                    shutil.copy2(backup_file_path, excluded_file_path)

            # If everything is successful, delete the backup
            if os.path.exists(self.backup_dir):
                print(f"Deleting backup directory: {self.backup_dir}")
                shutil.rmtree(self.backup_dir, onerror=self.handle_remove_readonly)

        except Exception as e:
            print(f"Update failed: {e}")
            self.restore_backup()
        finally:
            # Clean up the temporary directory
            time.sleep(2)  # Optional delay before cleanup (Stops errors)
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, onerror=self.handle_remove_readonly)

        print("GitHub update completed.")

    def update_from_pypi(self):
        """Update the application from PyPI."""
        pypi_config = self.config.get("pypi", {})
        package_names = pypi_config.get("package_name", [])
        preferred_method = pypi_config.get("preferred_method", 2)  # Default to method 2

        if not package_names or not isinstance(package_names, list):
            raise ValueError("PyPI package names must be specified as a list in the configuration.")

        for package_name in package_names:
            try:
                print(f"Updating package '{package_name}' from PyPI...")
                if preferred_method == 1:
                    # Try Method 1 first
                    self.retry_operation(
                        subprocess.run,
                        ["pip", "install", "--upgrade", package_name],
                        check=True,
                        retries=2
                    )
                else:
                    # Try Method 2 first
                    self.retry_operation(
                        subprocess.run,
                        ["python", "-m", "pip", "install", "--upgrade", package_name],
                        check=True,
                        retries=2
                    )
            except Exception as e:
                print(f"Preferred method failed for {package_name}. Trying the fallback method...")
                try:
                    if preferred_method == 1:
                        # Fallback to Method 2
                        self.retry_operation(
                            subprocess.run,
                            ["python", "-m", "pip", "install", "--upgrade", package_name],
                            check=True,
                            retries=2
                        )
                    else:
                        # Fallback to Method 1
                        self.retry_operation(
                            subprocess.run,
                            ["pip", "install", "--upgrade", package_name],
                            check=True,
                            retries=2
                        )
                except Exception as fallback_error:
                    print(f"Both methods failed for {package_name}: {fallback_error}")

        print("PyPI update completed.")

    def run(self):
        """Run the updater based on the configuration."""
        update_source = self.config.get("update_source")

        if update_source == "github":
            self.update_from_github()
        elif update_source == "pypi":
            self.update_from_pypi()
        else:
            raise ValueError("Invalid update source specified in the configuration.")

    @staticmethod
    def calculate_file_hash(file_path, prev_hash=""):
        """Calculate the SHA-256 hash of a file."""
        hash_sha256 = hashlib.sha256()
        try:
            # Ensure the path is a file
            if not os.path.isfile(file_path):
                return None  # Skip directories or invalid paths
            file_path_display = file_path.replace("\\", "/")
            print(f"Calculating hash for {file_path_display}...")
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            if prev_hash:
                if hash_sha256.hexdigest() != prev_hash:
                    print(f"Hash mismatch for {file_path_display}: {hash_sha256.hexdigest()} vs {prev_hash}")
                else:
                    print(f"Hash matches for {file_path_display}: {hash_sha256.hexdigest()}")
            print(f"Hash for {file_path_display}: {hash_sha256.hexdigest()}")
        except FileNotFoundError:
            return None  # File doesn't exist
        except PermissionError:
            print(f"Permission denied: {file_path}")
            return None  # Skip files with permission issues
        return hash_sha256.hexdigest()

if __name__ == "__main__":
    clear = lambda: os.system('cls' if os.name == 'nt' else 'clear')
    clear()
    updater = AppUpdater()
    if input(Fore.YELLOW + "This module is normally meant to be ran by other scripts, but does have a standalone mode.\nDo you want to run the updater standalone mode? (y/n): ").strip().lower() == 'y':
        choice = input("What do you want to do? (1: Clear Backup and Temp, 2: Update): ").strip()
        if choice == "1":
            if updater.config.get("update_source") == "github":
                print("Clearing backup and temp directories.")
                if os.path.exists(updater.backup_dir):
                    shutil.rmtree(updater.backup_dir, onerror=updater.handle_remove_readonly)
                if os.path.exists(os.path.join(updater.target_dir, "__temp_repo")):
                    shutil.rmtree(os.path.join(updater.target_dir, "__temp_repo"), onerror=updater.handle_remove_readonly)
                print("Backup and temp directories cleared.")
            else:
                print(Fore.RED + "This option is only available for GitHub updates, as the PyPi updater functions via pip.")
                print(Fore.RED + "GitHub updates are done via a temporary directory, while PyPi updates are done via pip.")
                print(Fore.GREEN + "This is a good thing, as it means you will not run into permission errors.")
        elif choice == "2":
            print("Running in standalone mode.")
            updater.run()
        else:
            print("Invalid choice. Exiting.")