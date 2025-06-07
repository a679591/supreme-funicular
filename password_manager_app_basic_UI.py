import customtkinter as ctk # Use ctk as the alias for customtkinter
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog # Added filedialog
import string
import random
import json
import os
from datetime import datetime, timedelta
import hashlib # Keep for derive_key, not for dir name

# --- Encryption/Decryption ---
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

# --- Constants ---
# Filenames within the vault directory
SALT_FILENAME = "salt.key"
PASSWORD_FILENAME = "passwords.enc"

# Character sets for password generation
CHAR_SETS = {
    "low": string.ascii_lowercase + string.digits,
    "medium": string.ascii_lowercase + string.ascii_uppercase + string.digits,
    "high": string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?",
    "extreme": string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
}

# --- Encryption Helper Functions (remain the same) ---
def generate_salt():
    return os.urandom(16)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_data(data: str, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    f = Fernet(key)
    try:
        return f.decrypt(encrypted_data).decode()
    except Exception as e:
        # Do not show messagebox here, let the caller handle it
        # print(f"Decryption error: {e}") # For debugging
        return None

# --- Main Application Class ---
class PasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.withdraw() # Hide main window until setup is complete

        self.title("Complex Password Creator & Vault")
        # Geometry and resizable will be set after successful setup

        self.master_password_key = None
        self.salt = None
        self.passwords_data = []

        self.current_vault_directory = None
        self.password_file_path = None
        self.salt_file_path = None

        # --- Step 1: Choose or Create Vault Directory ---
        if not self._select_or_create_vault_directory():
            messagebox.showinfo("Setup Cancelled", "Vault selection/creation was cancelled. Application will close.")
            self.destroy()
            return

        # --- Step 2: Setup Master Password for the selected/created directory ---
        if not self._setup_master_password_for_vault():
            messagebox.showinfo("Setup Failed", "Master password setup failed or was cancelled. Application will close.")
            self.destroy()
            return

        # --- If setup is successful, show the main application window ---
        self.deiconify() # Show the main window
        self.geometry("550x500")
        self.resizable(False, False)
        self.title(f"Password Vault - {os.path.basename(self.current_vault_directory)}") # Update title
        self._create_widgets()
        self._load_passwords()

    def _select_or_create_vault_directory(self) -> bool:
        """
        Prompts user to select an existing vault directory or create a new one.
        Sets self.current_vault_directory.
        Returns True if a directory is set, False on cancellation.
        """
        # Use a temporary hidden Toplevel for modal dialogs if main window is hidden
        temp_parent = tk.Toplevel(self)
        temp_parent.withdraw()
        temp_parent.grab_set() # Make dialogs modal to this temp window

        choice = messagebox.askquestion("Vault Setup",
                                        "Do you want to OPEN an existing vault directory?\n\n"
                                        "(Choose 'No' to CREATE a new vault directory)",
                                        parent=temp_parent, type=messagebox.YESNOCANCEL)

        if choice == 'yes': # Open existing
            chosen_dir = filedialog.askdirectory(title="Select Existing Vault Directory",
                                                 mustexist=True, parent=temp_parent)
            if chosen_dir:
                self.current_vault_directory = chosen_dir
                temp_parent.destroy()
                return True
            else: # User cancelled dialog
                temp_parent.destroy()
                return False
        elif choice == 'no': # Create new
            parent_dir_for_new_vault = filedialog.askdirectory(title="Select Location for New Vault Directory",
                                                               parent=temp_parent)
            if not parent_dir_for_new_vault:
                temp_parent.destroy()
                return False # User cancelled parent directory selection

            new_vault_name = simpledialog.askstring("New Vault Name",
                                                  "Enter a name for your new vault directory:",
                                                  parent=temp_parent)
            if new_vault_name and new_vault_name.strip():
                new_vault_path = os.path.join(parent_dir_for_new_vault, new_vault_name.strip())
                try:
                    if os.path.exists(new_vault_path) and os.listdir(new_vault_path):
                        if not messagebox.askyesno("Directory Exists",
                                                   f"The directory '{new_vault_path}' already exists and is not empty.\n"
                                                   "Using it might involve existing files.\n"
                                                   "Do you want to proceed and use this directory for your new vault?",
                                                   parent=temp_parent):
                            temp_parent.destroy()
                            return False

                    os.makedirs(new_vault_path, exist_ok=True)
                    self.current_vault_directory = new_vault_path
                    temp_parent.destroy()
                    return True
                except Exception as e:
                    messagebox.showerror("Error", f"Could not create directory '{new_vault_path}': {e}", parent=temp_parent)
                    temp_parent.destroy()
                    return False
            else: # User cancelled name input or entered empty name
                temp_parent.destroy()
                return False
        else: # User pressed Cancel on the initial Yes/No/Cancel dialog
            temp_parent.destroy()
            return False

    def _setup_master_password_for_vault(self) -> bool:
        """
        Sets up or verifies the master password for self.current_vault_directory.
        Sets self.salt_file_path, self.password_file_path, self.salt, self.master_password_key.
        Returns True on success, False on critical failure or cancellation.
        """
        if not self.current_vault_directory:
            # This should not happen if _select_or_create_vault_directory was successful
            messagebox.showerror("Internal Error", "Vault directory not set.", parent=self.master if self.winfo_exists() else None)
            return False

        self.salt_file_path = os.path.join(self.current_vault_directory, SALT_FILENAME)
        self.password_file_path = os.path.join(self.current_vault_directory, PASSWORD_FILENAME)

        # Use a temporary hidden Toplevel for modal dialogs if main window is hidden
        temp_parent = tk.Toplevel(self)
        temp_parent.withdraw()
        temp_parent.grab_set()

        if os.path.exists(self.salt_file_path):
            # Existing vault - try to unlock
            messagebox.showinfo("Open Vault", f"Opening vault: {self.current_vault_directory}", parent=temp_parent)
            attempts = 0
            max_attempts = 3
            while attempts < max_attempts:
                mp = simpledialog.askstring("Master Password", "Enter Master Password for this vault:", show='*', parent=temp_parent)
                if mp is None: temp_parent.destroy(); return False # User cancelled

                if not mp:
                    messagebox.showwarning("Input Error", "Master password cannot be empty.", parent=temp_parent)
                    attempts += 1
                    continue
                
                try:
                    with open(self.salt_file_path, "rb") as f:
                        self.salt = f.read()
                    
                    derived_key_attempt = derive_key(mp, self.salt)

                    # Test decryption if password file exists
                    if os.path.exists(self.password_file_path) and os.path.getsize(self.password_file_path) > 0:
                        with open(self.password_file_path, "rb") as f:
                            encrypted_content = f.read()
                        if decrypt_data(encrypted_content, derived_key_attempt) is not None:
                            self.master_password_key = derived_key_attempt
                            messagebox.showinfo("Success", "Master password accepted.", parent=temp_parent)
                            temp_parent.destroy()
                            return True
                        else:
                            messagebox.showerror("Access Denied", "Invalid Master Password.", parent=temp_parent)
                            attempts += 1
                    else: # Salt exists, but no password file (empty vault)
                        self.master_password_key = derived_key_attempt
                        messagebox.showinfo("Success", "Master password accepted for empty vault.", parent=temp_parent)
                        temp_parent.destroy()
                        return True
                except Exception as e:
                    messagebox.showerror("Error", f"Error during login: {e}", parent=temp_parent)
                    attempts += 1 # Consider this an attempt
            
            if attempts >= max_attempts:
                messagebox.showerror("Access Denied", "Maximum login attempts reached.", parent=temp_parent)
            temp_parent.destroy()
            return False

        else:
            # New vault setup (salt file does not exist in the chosen/created directory)
            messagebox.showinfo("New Vault", f"Setting up new vault in: {self.current_vault_directory}", parent=temp_parent)
            while True: # Loop for setting and confirming new password
                mp1 = simpledialog.askstring("Set Master Password", "Set a Master Password for this new vault:", show='*', parent=temp_parent)
                if mp1 is None: temp_parent.destroy(); return False # User cancelled
                if not mp1:
                    messagebox.showwarning("Input Error", "Master password cannot be empty.", parent=temp_parent)
                    continue

                mp2 = simpledialog.askstring("Confirm Master Password", "Confirm your Master Password:", show='*', parent=temp_parent)
                if mp2 is None: temp_parent.destroy(); return False # User cancelled
                
                if mp1 == mp2:
                    self.salt = generate_salt()
                    try:
                        with open(self.salt_file_path, "wb") as f:
                            f.write(self.salt)
                        self.master_password_key = derive_key(mp1, self.salt)
                        messagebox.showinfo("Success", "New vault initialized and master password set.", parent=temp_parent)
                        temp_parent.destroy()
                        return True
                    except Exception as e:
                        messagebox.showerror("Error", f"Could not save salt file: {e}", parent=temp_parent)
                        temp_parent.destroy()
                        return False # Critical error
                else:
                    messagebox.showerror("Error", "Master passwords do not match. Please try again.", parent=temp_parent)
    
    def _create_widgets(self): # (Content of _create_widgets is what gets adjusted)
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(expand=True, fill=tk.BOTH)

        # --- Input Fields ---
        ttk.Label(main_frame, text="Website Name:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.website_name_entry = ttk.Entry(main_frame, width=40)
        self.website_name_entry.grid(row=0, column=1, columnspan=2, sticky=tk.EW, pady=2)

        ttk.Label(main_frame, text="Website Link (Optional):").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.website_link_entry = ttk.Entry(main_frame, width=40)
        self.website_link_entry.grid(row=1, column=1, columnspan=2, sticky=tk.EW, pady=2)

        ttk.Label(main_frame, text="Password Length (12-64):").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.min_chars_var = tk.IntVar(value=16)
        self.min_chars_spinbox = ttk.Spinbox(main_frame, from_=12, to=64, textvariable=self.min_chars_var, width=5)
        self.min_chars_spinbox.grid(row=2, column=1, sticky=tk.W, pady=2)

        # --- Character Set Configuration ---
        char_options_frame = ttk.LabelFrame(main_frame, text="Character Types")
        char_options_frame.grid(row=3, column=0, columnspan=4, sticky=tk.EW, pady=(10,5), padx=2)

        self.include_lowercase_var = tk.BooleanVar(value=True)
        self.include_lowercase_check = ttk.Checkbutton(char_options_frame, text="Lowercase (a-z)", variable=self.include_lowercase_var)
        self.include_lowercase_check.grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)

        self.include_uppercase_var = tk.BooleanVar(value=True)
        self.include_uppercase_check = ttk.Checkbutton(char_options_frame, text="Uppercase (A-Z)", variable=self.include_uppercase_var)
        self.include_uppercase_check.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)

        self.include_digits_var = tk.BooleanVar(value=True)
        self.include_digits_check = ttk.Checkbutton(char_options_frame, text="Digits (0-9)", variable=self.include_digits_var)
        self.include_digits_check.grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)

        self.include_symbols_var = tk.BooleanVar(value=True)
        self.include_symbols_check = ttk.Checkbutton(char_options_frame, text="Symbols", variable=self.include_symbols_var, command=self._toggle_symbols_entry)
        self.include_symbols_check.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)

        ttk.Label(char_options_frame, text="Allowed Symbols:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.custom_symbols_var = tk.StringVar(value="!@#$%^&*()_+-=[]{}|;:,.<>?") # Default common symbols
        self.custom_symbols_entry = ttk.Entry(char_options_frame, textvariable=self.custom_symbols_var, width=30)
        self.custom_symbols_entry.grid(row=2, column=1, columnspan=2, sticky=tk.EW, padx=5, pady=2)

        # --- Generated Password ---
        ttk.Label(main_frame, text="Generated Password:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.generated_password_var = tk.StringVar()
        self.generated_password_entry = ttk.Entry(main_frame, textvariable=self.generated_password_var, state="readonly", width=40)
        self.generated_password_entry.grid(row=4, column=1, columnspan=2, sticky=tk.EW, pady=5)
        
        self.copy_button = ttk.Button(main_frame, text="Copy", command=self._copy_password)
        self.copy_button.grid(row=4, column=3, padx=5, pady=5, sticky=tk.W)


        # --- Reminder ---
        self.reminder_var = tk.BooleanVar(value=False)
        self.reminder_check = ttk.Checkbutton(main_frame, text="Set Reminder?", variable=self.reminder_var,
                                              command=self._toggle_reminder_duration)
        self.reminder_check.grid(row=5, column=0, sticky=tk.W, pady=2)

        self.reminder_duration_var = tk.StringVar()
        reminder_durations = [f"{i} days" for i in range(30, 181, 30)]
        self.reminder_duration_combo = ttk.Combobox(main_frame, textvariable=self.reminder_duration_var,
                                                    values=reminder_durations, state="disabled")
        self.reminder_duration_combo.grid(row=5, column=1, sticky=tk.EW, pady=2)
        if reminder_durations:
            self.reminder_duration_var.set(reminder_durations[0]) # Default to 30 days

        # --- Buttons ---
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=4, pady=10) # Adjusted columnspan for copy button

        self.generate_button = ttk.Button(button_frame, text="Generate Password", command=self._generate_password)
        self.generate_button.pack(side=tk.LEFT, padx=5)

        self.save_button = ttk.Button(button_frame, text="Save Password", command=self._save_password_entry)
        self.save_button.pack(side=tk.LEFT, padx=5)

        # --- Status/Info ---
        self.status_label = ttk.Label(main_frame, text="")
        self.status_label.grid(row=7, column=0, columnspan=4, pady=5, sticky=tk.W)

        # --- Password List ---
        ttk.Label(main_frame, text="Saved Entries:", font=("TkDefaultFont", 10, "bold")).grid(row=8, column=0, columnspan=4, sticky=tk.W, pady=(10,0))
        self.password_list_text = tk.Text(main_frame, height=8, width=60, state=tk.DISABLED) # Width might need adjustment
        self.password_list_text.grid(row=9, column=0, columnspan=3, sticky=tk.NSEW, pady=5) # Changed columnspan to 3

        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.password_list_text.yview)
        scrollbar.grid(row=9, column=3, sticky='nsew') # Place scrollbar in column 3
        self.password_list_text['yscrollcommand'] = scrollbar.set

        main_frame.columnconfigure(1, weight=1)
        main_frame.columnconfigure(2, weight=1) # For link/password entry if they expand

        self._toggle_symbols_entry() # Initialize state of symbols entry

    def _toggle_reminder_duration(self): # (Same as before)
        if self.reminder_var.get():
            self.reminder_duration_combo.config(state="readonly")
        else:
            self.reminder_duration_combo.config(state="disabled")

    def _toggle_symbols_entry(self):
        if self.include_symbols_var.get():
            self.custom_symbols_entry.config(state="normal")
        else:
            self.custom_symbols_entry.config(state="disabled")

    def _generate_password(self):
        try:
            length = self.min_chars_var.get()
            if not (12 <= length <= 64):
                messagebox.showerror("Error", "Password length must be between 12 and 64 characters.")
                return
        except tk.TclError:
            messagebox.showerror("Error", "Invalid character length. Please enter a number.")
            return

        char_pool = ""
        guaranteed_chars = []

        if self.include_lowercase_var.get():
            char_pool += string.ascii_lowercase
            if length > len(guaranteed_chars): # Ensure we don't add more guaranteed than length
                guaranteed_chars.append(random.choice(string.ascii_lowercase))

        if self.include_uppercase_var.get():
            char_pool += string.ascii_uppercase
            if length > len(guaranteed_chars):
                guaranteed_chars.append(random.choice(string.ascii_uppercase))

        if self.include_digits_var.get():
            char_pool += string.digits
            if length > len(guaranteed_chars):
                guaranteed_chars.append(random.choice(string.digits))

        if self.include_symbols_var.get():
            custom_symbols = self.custom_symbols_var.get()
            if not custom_symbols:
                messagebox.showwarning("Warning", "Symbols checkbox is checked, but no symbols are provided in the 'Allowed Symbols' field.")
                # Optionally, you could prevent generation or use a default small set
            else:
                char_pool += custom_symbols
                if length > len(guaranteed_chars):
                    guaranteed_chars.append(random.choice(custom_symbols))

        if not char_pool:
            messagebox.showerror("Error", "No character types selected. Please select at least one character type.")
            return
        
        if len(guaranteed_chars) > length:
            # This can happen if length is very small and many types are selected.
            # Prioritize the guaranteed characters, truncating if necessary, or shuffling and picking.
            # For simplicity, we'll just take the first 'length' guaranteed chars if this unlikely scenario occurs.
            # A better approach for very small lengths might be to warn the user.
            password_chars = random.sample(guaranteed_chars, length) # Ensure unique if taking a sample
            random.shuffle(password_chars) # Shuffle them
        else:
            remaining_length = length - len(guaranteed_chars)
            password_chars = list(guaranteed_chars) # Start with guaranteed ones
            if remaining_length > 0:
                password_chars.extend(random.choices(char_pool, k=remaining_length))
            
            random.shuffle(password_chars) # Shuffle all characters

        password = "".join(password_chars)
        self.generated_password_var.set(password)
        self.status_label.config(text="Password generated successfully.", foreground="green")
        
    def _copy_password(self): # (Same as before)
        password = self.generated_password_var.get()
        if password:
            self.clipboard_clear()
            self.clipboard_append(password)
            self.update() 
            self.status_label.config(text="Password copied to clipboard!", foreground="blue")
        else:
            self.status_label.config(text="No password generated to copy.", foreground="red")

    def _save_password_entry(self): # (Same as before, uses self.password_file_path)
        website_name = self.website_name_entry.get().strip()
        password = self.generated_password_var.get()
        website_link = self.website_link_entry.get().strip()

        if not website_name:
            messagebox.showerror("Error", "Website Name cannot be empty.")
            return
        if not password:
            messagebox.showerror("Error", "No password generated to save.")
            return

        entry = {
            "website_name": website_name,
            "password": password,
            "website_link": website_link,
            "creation_date": datetime.now().isoformat()
        }

        if self.reminder_var.get():
            try:
                duration_days = int(self.reminder_duration_var.get().split()[0])
                reminder_date = datetime.now() + timedelta(days=duration_days)
                entry["reminder_date"] = reminder_date.isoformat()
                entry["reminder_days"] = duration_days
            except ValueError:
                messagebox.showerror("Error", "Invalid reminder duration selected.")
                return
        
        existing_entry_index = -1
        for i, e in enumerate(self.passwords_data):
            if e['website_name'].lower() == website_name.lower():
                existing_entry_index = i
                break
        
        if existing_entry_index != -1:
            if not messagebox.askyesno("Confirm Overwrite", f"An entry for '{website_name}' already exists. Overwrite it?"):
                return
            self.passwords_data[existing_entry_index] = entry # Update existing
        else:
            self.passwords_data.append(entry) # Add new

        self._save_passwords_to_file()
        self.status_label.config(text=f"Password for '{website_name}' saved.", foreground="green")
        self._clear_inputs()
        self._update_password_list_display()

    def _clear_inputs(self):
        self.website_name_entry.delete(0, tk.END)
        self.website_link_entry.delete(0, tk.END)
        self.generated_password_var.set("")
        self.reminder_var.set(False)
        self._toggle_reminder_duration()
        self.min_chars_var.set(16) # Reset to default length

        # Reset character type options
        self.include_lowercase_var.set(True)
        self.include_uppercase_var.set(True)
        self.include_digits_var.set(True)
        self.include_symbols_var.set(True)
        self.custom_symbols_var.set("!@#$%^&*()_+-=[]{}|;:,.<>?")
        self._toggle_symbols_entry() # Update state of symbols entry

        self.status_label.config(text="") # Clear status label
        
    def _save_passwords_to_file(self): # (Uses self.password_file_path)
        if not self.master_password_key or not self.password_file_path:
            messagebox.showerror("Error", "Master password not set or path not configured. Cannot save.")
            return
        
        os.makedirs(os.path.dirname(self.password_file_path), exist_ok=True) # Ensure dir exists

        try:
            data_json = json.dumps(self.passwords_data, indent=4)
            encrypted_data = encrypt_data(data_json, self.master_password_key)
            with open(self.password_file_path, "wb") as f:
                f.write(encrypted_data)
        except Exception as e:
            messagebox.showerror("Save Error", f"Could not save passwords: {e}")

    def _load_passwords(self): # (Uses self.password_file_path)
        if not self.master_password_key or not self.password_file_path:
            # This case should be rare if __init__ logic is correct
            print("Master password key or path not available for loading.")
            return

        if os.path.exists(self.password_file_path) and os.path.getsize(self.password_file_path) > 0 :
            try:
                with open(self.password_file_path, "rb") as f:
                    encrypted_data = f.read()
                
                decrypted_json = decrypt_data(encrypted_data, self.master_password_key)
                if decrypted_json:
                    self.passwords_data = json.loads(decrypted_json)
                    self.status_label.config(text=f"{len(self.passwords_data)} entries loaded from vault.", foreground="blue")
                else:
                    # Decrypt_data would have failed if master key was wrong during initial setup,
                    # this branch is more for an empty or corrupted file that decrypts to None.
                    self.passwords_data = [] 
                    messagebox.showwarning("Load Warning", "Password file could not be decrypted or is empty. Starting fresh for this vault.")
            except json.JSONDecodeError:
                messagebox.showerror("Load Error", "Could not parse password data. File may be corrupted.")
                self.passwords_data = []
            except Exception as e:
                messagebox.showerror("Load Error", f"Could not load passwords: {e}")
                self.passwords_data = []
        else:
            self.passwords_data = []
            self.status_label.config(text="No passwords in this vault yet. A new file will be created on save.", foreground="orange")
        
        self._check_reminders()
        self._update_password_list_display()

    def _update_password_list_display(self): # (Same as before)
        self.password_list_text.config(state=tk.NORMAL)
        self.password_list_text.delete(1.0, tk.END)
        if not self.passwords_data:
            self.password_list_text.insert(tk.END, "No passwords saved in this vault yet.")
        else:
            for entry in sorted(self.passwords_data, key=lambda x: x['website_name'].lower()):
                display_text = f"Site: {entry['website_name']}"
                if entry.get("reminder_date"):
                    try:
                        r_date = datetime.fromisoformat(entry["reminder_date"]).strftime('%Y-%m-%d')
                        display_text += f" (Reminder: {r_date})"
                    except:
                        pass
                self.password_list_text.insert(tk.END, display_text + "\n")
        self.password_list_text.config(state=tk.DISABLED)

    def _check_reminders(self): # (Same as before)
        now = datetime.now()
        due_reminders = []
        for entry in self.passwords_data:
            if "reminder_date" in entry:
                try:
                    reminder_date = datetime.fromisoformat(entry["reminder_date"])
                    if reminder_date <= now:
                        due_reminders.append(f"- {entry['website_name']} (was due on {reminder_date.strftime('%Y-%m-%d')})")
                except ValueError:
                    print(f"Warning: Invalid reminder_date format for {entry['website_name']}")

        if due_reminders:
            message = "The following password change reminders are due or overdue:\n\n" + "\n".join(due_reminders)
            messagebox.showinfo("Password Reminders", message, parent=self)


if __name__ == "__main__":
    app = PasswordManagerApp()
    # The __init__ method now handles destroying the window if setup fails or is cancelled.
    # We only run mainloop if the window still exists and master_password_key is set (implies successful setup).
    if app.winfo_exists() and app.master_password_key:
        app.mainloop()
    else:
        print("Application startup cancelled or failed.")
