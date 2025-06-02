# --- START OF FILE password_manager_app_kivy.py ---

# Kivy imports
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.checkbox import CheckBox
from kivy.uix.spinner import Spinner
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.screenmanager import ScreenManager, Screen, FadeTransition
from kivy.uix.filechooser import FileChooserListView
from kivy.core.window import Window
from kivy.core.clipboard import Clipboard
from kivy.metrics import dp
from kivy.utils import platform as kivy_platform_name # Renamed to avoid confusion
from kivy.clock import Clock

# Standard library imports
import string
import random
import json
import os
import platform # To check OS, as chmod behaves differently or is unavailable (standard library module)
from datetime import datetime, timedelta
import time # For delays and timestamps
import logging # For logging

# Encryption/Decryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

# Cleanup
import secrets # For cryptographically secure random numbers
import gc      # For garbage collection

# --- Constants ---
SALT_FILENAME = "salt.key"
PASSWORD_FILENAME = "passwords.enc"
CHAR_SETS = { # This is not directly used in the current generator logic structure, but retained
    "low": string.ascii_lowercase + string.digits,
    "medium": string.ascii_lowercase + string.ascii_uppercase + string.digits,
    "high": string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?",
    "extreme": string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
}

# Helper function to set restrictive permissions
def set_restrictive_permissions(filepath):
    """Sets file permissions to 0o600 (owner read/write only) on Unix-like systems."""
    if platform.system() != "Windows": # 'platform' here is the standard library module
        try:
            os.chmod(filepath, 0o600) # Simpler chmod, umask handling can be complex
        except OSError as e:
            logging.error(f"SECURITY: Failed to set restrictive permissions for '{filepath}': {e}")
        except Exception as e_general: # Catch any other potential issues during chmod
            logging.error(f"SECURITY: Unexpected error setting permissions for '{filepath}': {e_general}")
    else:
        # On Windows, os.chmod has limited effect.
        pass

# For memory protection
def secure_zero_memory(data_to_clear):
    """
    Attempts to securely zero out a mutable bytearray or a string/bytes object
    by converting it to a bytearray first.
    This is best-effort in Python.
    """
    if data_to_clear is None:
        return

    data_ba = None
    # original_type = type(data_to_clear) # Not used

    if isinstance(data_to_clear, bytearray):
        data_ba = data_to_clear
    elif isinstance(data_to_clear, str):
        try:
            # Create a temporary bytearray from the string for overwriting
            # Note: The original string in memory is immutable and cannot be directly changed.
            temp_ba_for_string = bytearray(data_to_clear.encode('utf-8', 'surrogateescape'))
            random_fill = secrets.token_bytes(len(temp_ba_for_string))
            for i in range(len(temp_ba_for_string)):
                temp_ba_for_string[i] = random_fill[i]
            for i in range(len(temp_ba_for_string)):
                temp_ba_for_string[i] = 0
            del temp_ba_for_string # Remove reference to the overwritten bytearray
            return # For strings, we operate on a copy; further data_ba logic is skipped.
        except Exception: 
            return 
    elif isinstance(data_to_clear, bytes):
        data_ba = bytearray(data_to_clear) # Create a mutable copy to zero out
    else:
        return

    if data_ba:
        random_fill = secrets.token_bytes(len(data_ba))
        for i in range(len(data_ba)):
            data_ba[i] = random_fill[i]
        for i in range(len(data_ba)):
            data_ba[i] = 0
    
    
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
    except Exception:
        return None

# --- Kivy Popup Helpers ---
def show_info_popup(title, message, on_dismiss_callback=None):
    content = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
    content.add_widget(Label(text=message, halign='center', valign='middle', size_hint_y=None, height=dp(60)))
    btn_ok = Button(text='OK', size_hint_y=None, height=dp(40))
    content.add_widget(btn_ok)
    
    popup = Popup(title=title, content=content, size_hint=(0.7, 0.3), auto_dismiss=False)
    def _dismiss(*args):
        popup.dismiss()
        if on_dismiss_callback:
            on_dismiss_callback()
    btn_ok.bind(on_press=_dismiss)
    popup.open()

def show_confirm_popup(title, message, callback_yes, callback_no=None, callback_cancel=None):
    content = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
    content.add_widget(Label(text=message, halign='center', valign='middle', text_size=(dp(300), None))) 
    
    buttons_layout = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(10))
    btn_yes = Button(text='Yes')
    btn_no = Button(text='No')
    
    buttons_layout.add_widget(btn_yes)
    buttons_layout.add_widget(btn_no)
    
    if callback_cancel: 
        btn_cancel = Button(text='Cancel')
        buttons_layout.add_widget(btn_cancel)
        def _cancel(*args):
            popup.dismiss()
            if callback_cancel:
                callback_cancel()
        btn_cancel.bind(on_press=_cancel)

    content.add_widget(buttons_layout)
    
    popup = Popup(title=title, content=content, size_hint=(0.8, 0.4), auto_dismiss=False)

    def _yes(*args):
        popup.dismiss()
        callback_yes()
    btn_yes.bind(on_press=_yes)

    def _no(*args):
        popup.dismiss()
        if callback_no:
            callback_no()
    btn_no.bind(on_press=_no)
    
    popup.open()

def show_text_input_popup(title, message, callback_ok, callback_cancel=None, is_password=False):
    content = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
    content.add_widget(Label(text=message, size_hint_y=None, height=dp(30)))
    text_input = TextInput(multiline=False, password=is_password, size_hint_y=None, height=dp(40))
    content.add_widget(text_input)
    
    buttons_layout = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(10))
    btn_ok = Button(text='OK')
    btn_cancel = Button(text='Cancel')
    buttons_layout.add_widget(btn_ok)
    buttons_layout.add_widget(btn_cancel)
    content.add_widget(buttons_layout)
    
    popup = Popup(title=title, content=content, size_hint=(0.8, 0.4), auto_dismiss=False)

    def _ok(*args):
        entered_text = text_input.text
        # Attempt to clear text_input internal buffer if possible (Kivy specific, often not feasible)
        text_input.text = "" # Clears visually, internal buffer might still exist for a short while
        popup.dismiss()
        callback_ok(entered_text) 
    btn_ok.bind(on_press=_ok)

    def _cancel(*args):
        text_input.text = "" # Also clear on cancel
        popup.dismiss()
        if callback_cancel:
            callback_cancel()
    btn_cancel.bind(on_press=_cancel)
    
    popup.open()
    text_input.focus = True

def show_file_chooser_popup(title, callback_select, callback_cancel=None, mode='dir', path=None):
    content = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
    
    if path is None:
        path = os.path.expanduser("~") 
        if kivy_platform_name == 'android': 
             from android.storage import primary_external_storage_path
             path = primary_external_storage_path()


    file_chooser = FileChooserListView(path=path, dirselect=(mode == 'dir'), show_hidden=False)
    content.add_widget(file_chooser)
    
    buttons_layout = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(10))
    btn_select = Button(text='Select')
    btn_cancel = Button(text='Cancel')
    buttons_layout.add_widget(btn_select)
    buttons_layout.add_widget(btn_cancel)
    content.add_widget(buttons_layout)
    
    popup = Popup(title=title, content=content, size_hint=(0.9, 0.9), auto_dismiss=False)

    def _select(*args):
        selection = file_chooser.selection
        if selection:
            popup.dismiss()
            callback_select(selection[0])
        else:
            show_info_popup("Selection Error", "Please select a directory/file.")
            
    btn_select.bind(on_press=_select)

    def _cancel(*args):
        popup.dismiss()
        if callback_cancel:
            callback_cancel()
    btn_cancel.bind(on_press=_cancel)
    
    popup.open()

# --- Main Application Screen ---
class MainAppScreen(Screen):
    def __init__(self, app_instance, **kwargs):
        super().__init__(**kwargs)
        self.app = app_instance 
        self.build_ui()
        # These attributes seem intended for UI-level attempt tracking, distinct from vault login.
        # Retaining them as they might be used for features within MainAppScreen not related to initial vault auth.
        self.login_attempts = 0 
        self.max_login_attempts_before_short_lockout = 3 
        self.failed_login_timestamps = [] 
        self.short_lockout_duration_seconds = 60 
        self.lockout_until_timestamp = 0 
        
        self.session_timeout_seconds = 15 * 60 
        self.last_activity_timestamp = time.time()
        # self._activity_clock_event = None # This attribute is managed by PasswordManagerKivyApp

    def build_ui(self):
        main_layout = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))

        input_grid = GridLayout(cols=2, spacing=dp(5), size_hint_y=None, height=dp(230)) 

        input_grid.add_widget(Label(text="Website Name:", size_hint_x=0.3))
        self.website_name_entry = TextInput(multiline=False, size_hint_x=0.7)
        input_grid.add_widget(self.website_name_entry)

        input_grid.add_widget(Label(text="Website Link (Optional):", size_hint_x=0.3))
        self.website_link_entry = TextInput(multiline=False, size_hint_x=0.7)
        input_grid.add_widget(self.website_link_entry)

        input_grid.add_widget(Label(text="Password Length (12-64):", size_hint_x=0.3))
        self.min_chars_spinner = Spinner(
            text='16',
            values=[str(i) for i in range(12, 65)],
            size_hint_x=0.7
        )
        input_grid.add_widget(self.min_chars_spinner)

        input_grid.add_widget(Label(text="Character Types:", size_hint_x=None, width=dp(150))) 
        char_options_layout = BoxLayout(orientation='vertical', spacing=dp(2))

        h_layout1 = BoxLayout(spacing=dp(5))
        self.include_lowercase_check = CheckBox(active=True)
        h_layout1.add_widget(self.include_lowercase_check)
        h_layout1.add_widget(Label(text="Lowercase (a-z)"))
        self.include_uppercase_check = CheckBox(active=True)
        h_layout1.add_widget(self.include_uppercase_check)
        h_layout1.add_widget(Label(text="Uppercase (A-Z)"))
        char_options_layout.add_widget(h_layout1)
        
        h_layout2 = BoxLayout(spacing=dp(5))
        self.include_digits_check = CheckBox(active=True)
        h_layout2.add_widget(self.include_digits_check)
        h_layout2.add_widget(Label(text="Digits (0-9)"))
        self.include_symbols_check = CheckBox(active=True)
        self.include_symbols_check.bind(active=self._toggle_symbols_entry_active)
        h_layout2.add_widget(self.include_symbols_check)
        h_layout2.add_widget(Label(text="Symbols"))
        char_options_layout.add_widget(h_layout2)
        input_grid.add_widget(char_options_layout)


        input_grid.add_widget(Label(text="Allowed Symbols:", size_hint_x=0.3))
        self.custom_symbols_entry = TextInput(
            text="!@#$%^&*()_+-=[]{}|;:,.<>?",
            multiline=False, size_hint_x=0.7
        )
        input_grid.add_widget(self.custom_symbols_entry)
        
        input_grid.add_widget(Label(text="Generated Password:", size_hint_x=0.3))
        generated_pass_layout = BoxLayout(size_hint_x=0.7)
        self.generated_password_entry = TextInput(readonly=True, multiline=False, size_hint_x=0.8)
        generated_pass_layout.add_widget(self.generated_password_entry)
        self.copy_button = Button(text="Copy", size_hint_x=0.2, on_press=self.app._copy_password)
        generated_pass_layout.add_widget(self.copy_button)
        input_grid.add_widget(generated_pass_layout)

        input_grid.add_widget(Label(text="Set Reminder?", size_hint_x=0.3))
        reminder_layout = BoxLayout(size_hint_x=0.7)
        self.reminder_check = CheckBox(active=False)
        self.reminder_check.bind(active=self._toggle_reminder_duration_active)
        reminder_layout.add_widget(self.reminder_check)
        
        reminder_durations = [f"{i} days" for i in range(30, 181, 30)]
        self.reminder_duration_spinner = Spinner(
            text=reminder_durations[0] if reminder_durations else "30 days",
            values=reminder_durations,
            disabled=True
        )
        reminder_layout.add_widget(self.reminder_duration_spinner)
        input_grid.add_widget(reminder_layout)

        main_layout.add_widget(input_grid)

        button_frame = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(10), padding=(0, dp(10)))
        self.generate_button = Button(text="Generate Password", on_press=self.app._generate_password)
        button_frame.add_widget(self.generate_button)
        self.save_button = Button(text="Save Password", on_press=self.app._save_password_entry)
        button_frame.add_widget(self.save_button)
        main_layout.add_widget(button_frame)
        self.lock_button = Button(text="Lock Vault", on_press=self.app.lock_vault_button_action)
        button_frame.add_widget(self.lock_button) 

        self.status_label = Label(text="", size_hint_y=None, height=dp(30))
        main_layout.add_widget(self.status_label)

        main_layout.add_widget(Label(text="Saved Entries:", size_hint_y=None, height=dp(30), font_size='15sp', bold=True))
        
        scroll_view = ScrollView(size_hint=(1, 1))
        self.password_list_layout = GridLayout(cols=1, spacing=dp(5), size_hint_y=None)
        self.password_list_layout.bind(minimum_height=self.password_list_layout.setter('height')) 
        scroll_view.add_widget(self.password_list_layout)
        main_layout.add_widget(scroll_view)
        
        self.add_widget(main_layout)
        self._toggle_symbols_entry_active() 

    def _toggle_reminder_duration_active(self, instance=None, value=None):
        self.reminder_duration_spinner.disabled = not self.reminder_check.active

    def _toggle_symbols_entry_active(self, instance=None, value=None):
        self.custom_symbols_entry.disabled = not self.include_symbols_check.active

# --- Kivy Application Class ---
class PasswordManagerKivyApp(App):
    def build(self):
        Window.size = (dp(550), dp(700)) 
        Window.bind(on_request_close=self.on_request_close) 
        # Window.set_icon('icon.png') 

        self.master_password_key = None
        self.salt = None
        self.passwords_data = []
        self.current_vault_directory = None
        self.password_file_path = None
        self.salt_file_path = None
        
        # Vault login attempt tracking and lockout parameters
        self.login_attempts = 0 
        self.max_login_attempts = 3 
        self.short_lockout_duration_seconds = 60 # seconds
        self.failed_login_timestamps = [] 
        self.lockout_until_timestamp = 0 

        # Session inactivity tracking
        self._activity_clock_event = None # FIX: Initialize attribute

        self.screen_manager = ScreenManager(transition=FadeTransition())
        loading_screen = Screen(name='loading')
        loading_screen.add_widget(Label(text="Initializing setup..."))
        self.screen_manager.add_widget(loading_screen)
        
        return self.screen_manager

    def on_start(self):
        self._initiate_vault_setup_flow()

    def on_request_close(self, *args, **kwargs):
        self.stop() 
        return True 

    def _exit_app(self, message="Application will close."):
        show_info_popup("Exiting", message, on_dismiss_callback=self.stop)

    def _initiate_vault_setup_flow(self):
        self.screen_manager.current = 'loading' 
        
        # Reset vault-specific login attempt counters for a new flow
        self.login_attempts = 0
        self.failed_login_timestamps = []
        self.lockout_until_timestamp = 0 # Reset any previous lockout if starting fresh

        show_confirm_popup(
            title="Vault Setup",
            message="Do you want to OPEN an existing vault directory?\n\n(Choose 'No' to CREATE a new vault directory)",
            callback_yes=self._select_existing_vault_start,
            callback_no=self._create_new_vault_start_select_parent,
            callback_cancel=lambda: self._exit_app("Vault setup cancelled."),
        )


    def _select_existing_vault_start(self):
        show_file_chooser_popup(
            title="Select Existing Vault Directory",
            callback_select=self._handle_existing_vault_selected,
            callback_cancel=self._initiate_vault_setup_flow, 
            mode='dir'
        )

    def _handle_existing_vault_selected(self, chosen_dir):
        if not os.path.isdir(chosen_dir): 
            show_info_popup("Error", "Invalid directory selected.", self._select_existing_vault_start)
            return
        self.current_vault_directory = chosen_dir
        self._setup_master_password_for_vault()

    def _create_new_vault_start_select_parent(self):
        show_file_chooser_popup(
            title="Select Location for New Vault Directory",
            callback_select=self._handle_parent_dir_for_new_vault_selected,
            callback_cancel=self._initiate_vault_setup_flow,
            mode='dir'
        )
    
    def _handle_parent_dir_for_new_vault_selected(self, parent_dir):
        show_text_input_popup(
            title="New Vault Name",
            message="Enter a name for your new vault directory:",
            callback_ok=lambda name: self._process_new_vault_name(parent_dir, name),
            callback_cancel=self._create_new_vault_start_select_parent
        )

    def _process_new_vault_name(self, parent_dir, new_vault_name):
        if not new_vault_name or not new_vault_name.strip():
            show_info_popup("Error", "Vault name cannot be empty.", 
                            lambda: self._handle_parent_dir_for_new_vault_selected(parent_dir))
            return

        new_vault_path = os.path.join(parent_dir, new_vault_name.strip())
        
        if os.path.exists(new_vault_path) and os.listdir(new_vault_path):
            show_confirm_popup(
                title="Directory Exists",
                message=f"Directory '{new_vault_path}' exists and is not empty.\nUse it anyway?",
                callback_yes=lambda: self._finalize_new_vault_creation(new_vault_path),
                callback_no=lambda: self._handle_parent_dir_for_new_vault_selected(parent_dir) 
            )
        else:
            self._finalize_new_vault_creation(new_vault_path)

    def _finalize_new_vault_creation(self, new_vault_path):
        try:
            os.makedirs(new_vault_path, exist_ok=True)
            self.current_vault_directory = new_vault_path
            self._setup_master_password_for_vault()
        except Exception as e:
            show_info_popup("Error", f"Could not create directory: {e}", self._initiate_vault_setup_flow)

    def _setup_master_password_for_vault(self):
        if not self.current_vault_directory:
            self._exit_app("Internal Error: Vault directory not set.")
            return

        self.salt_file_path = os.path.join(self.current_vault_directory, SALT_FILENAME)
        self.password_file_path = os.path.join(self.current_vault_directory, PASSWORD_FILENAME)
        
        # Reset login attempts for this specific vault access
        self.login_attempts = 0 
        self.failed_login_timestamps = []
        # self.lockout_until_timestamp = 0 # Keep existing lockout if user is cycling through options quickly

        if os.path.exists(self.salt_file_path):
            show_info_popup("Open Vault", f"Opening vault: {os.path.basename(self.current_vault_directory)}",
                            self._prompt_master_password_login)
        else:
            show_info_popup("New Vault", f"Setting up new vault in: {os.path.basename(self.current_vault_directory)}",
                            self._prompt_set_new_master_password)

    def _prompt_master_password_login(self):
        current_time = time.time()

        if self.lockout_until_timestamp > current_time:
            remaining_lockout = int(self.lockout_until_timestamp - current_time)
            show_info_popup(
                "Login Locked",
                f"Too many failed attempts. Please wait {remaining_lockout} seconds.",
                self._initiate_vault_setup_flow 
            )
            return
        
        # Simplified delay logic for Kivy (consider Clock.schedule_once if complex delays needed)
        # For now, direct prompt or rely on popup chain
        # if self.login_attempts > 0:
        #     delay_seconds = self.login_attempts * 2 
        #     show_info_popup("Login Delay", f"Delaying login for {delay_seconds} seconds due to previous failed attempt.",
        #                     lambda: self._actually_prompt_for_password(delay_seconds))
        #     return
        # else:
        self._actually_prompt_for_password(0) # No explicit delay here for simplicity

    def _actually_prompt_for_password(self, delay_seconds): # delay_seconds currently unused
        show_text_input_popup(
            title="Master Password",
            message=f"Enter Master Password (Attempt {self.login_attempts + 1}/{self.max_login_attempts}):",
            callback_ok=self._verify_master_password_login,
            callback_cancel=self._initiate_vault_setup_flow,
            is_password=True
        )

    def _verify_master_password_login(self, mp_str):
        current_time = time.time()

        if not mp_str:
            show_info_popup("Input Error", "Master password cannot be empty.", self._prompt_master_password_login)
            self.login_attempts += 1 
            secure_zero_memory(mp_str) # Handles None or empty string
            # del mp_str # mp_str is a local variable, will be garbage collected.
            return

        try:
            with open(self.salt_file_path, "rb") as f:
                self.salt = f.read()
            
            derived_key_attempt = derive_key(mp_str, self.salt)
            login_successful = False
            
            if os.path.exists(self.password_file_path) and os.path.getsize(self.password_file_path) > 0:
                with open(self.password_file_path, "rb") as f:
                    encrypted_content = f.read()
                
                key_for_fernet = bytearray(derived_key_attempt) # Use a copy for Fernet
                decrypted_json_data = decrypt_data(encrypted_content, bytes(key_for_fernet))
                secure_zero_memory(key_for_fernet)
                del key_for_fernet

                if decrypted_json_data is not None:
                    self.master_password_key = bytearray(derived_key_attempt)
                    login_successful = True
                    show_info_popup("Success", "Master password accepted.", self._load_main_application_ui)
                # else: decryption failed, login_successful remains False
            else: # Salt exists, but no password file (empty vault)
                self.master_password_key = bytearray(derived_key_attempt)
                login_successful = True
                show_info_popup("Success", "Master password accepted for empty vault.", self._load_main_application_ui)
            
            secure_zero_memory(mp_str) # Clear mp_str after its use
            # del mp_str

            if login_successful:
                self.login_attempts = 0 
                self.failed_login_timestamps = [] 
                self.lockout_until_timestamp = 0
                return

            # If not successful by now, it's a login failure (decryption failed)
            self.login_attempts += 1
            self.failed_login_timestamps.append(current_time)
            
            if self.login_attempts >= self.max_login_attempts:
                self.lockout_until_timestamp = current_time + self.short_lockout_duration_seconds
                show_info_popup(
                    "Login Failed",
                    f"Invalid Master Password. Account locked for {self.short_lockout_duration_seconds} seconds.",
                    self._initiate_vault_setup_flow 
                )
                # Reset attempts after lockout is set, or keep counting for longer lockouts (current: reset for next cycle)
                self.login_attempts = 0 
                self.failed_login_timestamps = []
            else:
                show_info_popup("Access Denied", "Invalid Master Password.", self._prompt_master_password_login)
            return

        except FileNotFoundError:
            secure_zero_memory(mp_str)
            # del mp_str
            show_info_popup("Error", "Vault integrity error: Salt file not found. Ensure vault is correctly set up.", self._initiate_vault_setup_flow)
            return
        except Exception as e:
            self.login_attempts += 1 
            secure_zero_memory(mp_str)
            # del mp_str
            # Consider if lockout should apply for generic errors too
            show_info_popup("Error", f"Error during login: {e}", self._prompt_master_password_login)
            return

    def _prompt_set_new_master_password(self, mp1_candidate=None):
        if mp1_candidate is None: 
             show_text_input_popup(
                title="Set Master Password",
                message="Set a Master Password for this new vault:",
                callback_ok=lambda mp1: self._prompt_set_new_master_password(mp1_candidate=mp1), 
                callback_cancel=self._initiate_vault_setup_flow,
                is_password=True
            )
        else: 
            mp1 = mp1_candidate
            if not mp1:
                show_info_popup("Input Error", "Master password cannot be empty.", 
                                lambda: self._prompt_set_new_master_password(mp1_candidate=None)) 
                secure_zero_memory(mp1) # Clear if non-empty but logic fails later
                return

            show_text_input_popup(
                title="Confirm Master Password",
                message="Confirm your Master Password:",
                callback_ok=lambda mp2: self._verify_new_master_passwords(mp1, mp2),
                callback_cancel=lambda: (secure_zero_memory(mp1), self._prompt_set_new_master_password(mp1_candidate=None)),
                is_password=True
            )

    def _verify_new_master_passwords(self, mp1_str, mp2_str):
        if mp1_str == mp2_str:
            self.salt = generate_salt()
            try:
                os.makedirs(os.path.dirname(self.salt_file_path), exist_ok=True)

                with open(self.salt_file_path, "wb") as f:
                    f.write(self.salt)
                set_restrictive_permissions(self.salt_file_path)
                
                # Use bytearray for master_password_key consistency
                self.master_password_key = bytearray(derive_key(mp1_str, self.salt))
                show_info_popup("Success", "New vault initialized and master password set.", self._load_main_application_ui)
            except Exception as e:
                show_info_popup("Error", f"Could not save salt file: {e}", self._initiate_vault_setup_flow)
        else:
            show_info_popup("Error", "Master passwords do not match. Please try again.", 
                            lambda: self._prompt_set_new_master_password(mp1_candidate=None)) 
        
        secure_zero_memory(mp1_str)
        secure_zero_memory(mp2_str)
        # del mp1_str, mp2_str

    def _load_main_application_ui(self):
        Window.title = f"Password Vault - {os.path.basename(self.current_vault_directory)}"
        self.main_screen = MainAppScreen(app_instance=self, name='main_app')
        self.screen_manager.add_widget(self.main_screen)
        self.screen_manager.current = 'main_app'
        self._load_passwords() 
        self._check_reminders()
        self.reset_inactivity_timer() 
        Window.bind(on_motion=self.on_user_activity,
                on_touch_down=self.on_user_activity,
                on_key_down=self.on_user_activity)
        self._start_inactivity_check()

    def on_user_activity(self, *args):
        self.reset_inactivity_timer()

    def reset_inactivity_timer(self):
        self.last_activity_timestamp = time.time()
        # print(f"Activity detected / timer reset at {self.last_activity_timestamp}") # Debug

    def _start_inactivity_check(self):
        if self._activity_clock_event:
            self._activity_clock_event.cancel()
        self._activity_clock_event = Clock.schedule_interval(self.check_session_timeout, 30)

    def check_session_timeout(self, dt):
        if not self.master_password_key: 
            if self._activity_clock_event: 
                 self._activity_clock_event.cancel()
                 self._activity_clock_event = None
            return
        idle_duration = time.time() - self.last_activity_timestamp
        # print(f"Idle for: {idle_duration:.2f}s / Timeout: {self.main_screen.session_timeout_seconds}s") # Debug, use app level timeout
        if idle_duration > self.main_screen.session_timeout_seconds: # session_timeout_seconds is on MainAppScreen
            self.lock_vault("Session timed out due to inactivity.")

    def lock_vault(self, reason="Vault locked."):
        if self.master_password_key:
            secure_zero_memory(self.master_password_key) 
            self.master_password_key = None

        if self._activity_clock_event: 
            self._activity_clock_event.cancel()
            self._activity_clock_event = None

        show_info_popup("Vault Locked", reason, on_dismiss_callback=self._return_to_vault_selection_or_login)

    def lock_vault_button_action(self, instance=None): 
        self.lock_vault("Vault locked by user.")

    def _return_to_vault_selection_or_login(self):
        if self.screen_manager.has_screen('main_app'):
            main_app_screen = self.screen_manager.get_screen('main_app')
            self.screen_manager.remove_widget(main_app_screen)
            if hasattr(self, 'main_screen') and self.main_screen == main_app_screen:
                del self.main_screen 
            gc.collect() # Hint for garbage collection

        if self.current_vault_directory and self.salt_file_path and self.password_file_path:
            self.login_attempts = 0
            self.failed_login_timestamps = []
            # Keep lockout if it was due to prior failed attempts for this vault,
            # unless _initiate_vault_setup_flow is intended to fully reset it.
            # self.lockout_until_timestamp = 0 # Resetting here makes sense for a re-login prompt

            show_info_popup("Re-authentication Required",
                            f"Re-enter master password for vault: {os.path.basename(self.current_vault_directory)}",
                            self._prompt_master_password_login)
        else:
            self._initiate_vault_setup_flow()

    def on_stop(self):
        if self._activity_clock_event: # FIX: Check if attribute exists (now initialized to None)
            self._activity_clock_event.cancel()
            self._activity_clock_event = None # Good practice to nullify after cancel
        if self.master_password_key:
            secure_zero_memory(self.master_password_key)
            self.master_password_key = None
        # Kivy's super().on_stop() handles its own cleanup.
        # super().on_stop() # Call if App class has specific on_stop actions other than event dispatch.
                          # Kivy's base App.on_stop is usually empty, but good practice if overridden in future.

    # --- Main App Functionality (adapted for Kivy) ---
    def _generate_password(self, instance=None): 
        try:
            length = int(self.main_screen.min_chars_spinner.text)
            if not (12 <= length <= 64):
                show_info_popup("Error", "Password length must be between 12 and 64 characters.")
                return
        except ValueError:
            show_info_popup("Error", "Invalid character length. Please enter a number.")
            return

        char_pool = ""
        guaranteed_chars = []

        if self.main_screen.include_lowercase_check.active:
            char_pool += string.ascii_lowercase
            if length > len(guaranteed_chars):
                guaranteed_chars.append(random.choice(string.ascii_lowercase))
        if self.main_screen.include_uppercase_check.active:
            char_pool += string.ascii_uppercase
            if length > len(guaranteed_chars):
                guaranteed_chars.append(random.choice(string.ascii_uppercase))
        if self.main_screen.include_digits_check.active:
            char_pool += string.digits
            if length > len(guaranteed_chars):
                guaranteed_chars.append(random.choice(string.digits))
        if self.main_screen.include_symbols_check.active:
            custom_symbols = self.main_screen.custom_symbols_entry.text
            if not custom_symbols:
                show_info_popup("Warning", "Symbols enabled, but no symbols provided.")
            else:
                char_pool += custom_symbols
                if length > len(guaranteed_chars) and custom_symbols: 
                    guaranteed_chars.append(random.choice(custom_symbols))
        
        if not char_pool:
            show_info_popup("Error", "No character types selected.")
            return
        
        if len(guaranteed_chars) > length:
            # This case means more types selected than length allows for guarantees; select from guaranteed pool
            password_chars = random.sample(guaranteed_chars, length)
        else:
            remaining_length = length - len(guaranteed_chars)
            password_chars = list(guaranteed_chars)
            if remaining_length > 0: # Fill remaining length from the full pool
                password_chars.extend(random.choices(char_pool, k=remaining_length))
        
        random.shuffle(password_chars) # Shuffle all characters together

        password = "".join(password_chars)
        self.main_screen.generated_password_entry.text = password
        self.main_screen.status_label.text = "Password generated successfully."
        self.main_screen.status_label.color = (0, 1, 0, 1) 

    def _copy_password(self, instance=None):
        password = self.main_screen.generated_password_entry.text
        if password:
            Clipboard.copy(password)
            self.main_screen.status_label.text = "Password copied to clipboard!"
            self.main_screen.status_label.color = (0, 0, 1, 1) 
            
            # Attempt to clear the copied password from clipboard after a delay (platform dependent, complex)
            # For now, just clear the local variable containing the password after copying.
            temp_pass_ba = bytearray(password.encode('utf-8','surrogateescape')) # FIX: password_str -> password
            secure_zero_memory(temp_pass_ba)
            del temp_pass_ba
            # Note: 'password' string itself is immutable. Clipboard content is outside direct Python control for clearing.
        else:
            self.main_screen.status_label.text = "No password generated to copy."
            self.main_screen.status_label.color = (1, 0, 0, 1) 
            
    def _save_password_entry(self, instance=None):
        website_name = self.main_screen.website_name_entry.text.strip()
        password_to_save = self.main_screen.generated_password_entry.text # This is a string
        website_link = self.main_screen.website_link_entry.text.strip()

        if not website_name:
            show_info_popup("Error", "Website Name cannot be empty.")
            return
        if not password_to_save:
            show_info_popup("Error", "No password generated to save.")
            return

        entry = {
            "website_name": website_name,
            "password": password_to_save, 
            "website_link": website_link,
            "creation_date": datetime.now().isoformat()
        }

        if self.main_screen.reminder_check.active:
            try:
                duration_days = int(self.main_screen.reminder_duration_spinner.text.split()[0])
                reminder_date = datetime.now() + timedelta(days=duration_days)
                entry["reminder_date"] = reminder_date.isoformat()
                entry["reminder_days"] = duration_days 
            except ValueError:
                show_info_popup("Error", "Invalid reminder duration selected.")
                return
        
        existing_entry_index = -1
        for i, e in enumerate(self.passwords_data):
            if e['website_name'].lower() == website_name.lower():
                existing_entry_index = i
                break
        
        def _do_save():
            if existing_entry_index != -1:
                self.passwords_data[existing_entry_index] = entry
            else:
                self.passwords_data.append(entry)
            self._save_passwords_to_file() # This encrypts and saves
            self.main_screen.status_label.text = f"Password for '{website_name}' saved."
            self.main_screen.status_label.color = (0,1,0,1)
            self._clear_inputs_kivy()
            self._update_password_list_display_kivy()
            
            # Securely clear the password_to_save variable after it has been processed by _save_passwords_to_file
            secure_zero_memory(password_to_save)
            # del password_to_save # It's a local var, will be GC'd

        if existing_entry_index != -1:
            show_confirm_popup(
                title="Confirm Overwrite",
                message=f"An entry for '{website_name}' already exists. Overwrite it?",
                callback_yes=_do_save
            )
        else:
            _do_save()

    def _clear_inputs_kivy(self):
        self.main_screen.website_name_entry.text = ""
        self.main_screen.website_link_entry.text = ""
        self.main_screen.generated_password_entry.text = "" # This holds the sensitive password visually
        self.main_screen.min_chars_spinner.text = '16' 

        self.main_screen.reminder_check.active = False

        self.main_screen.include_lowercase_check.active = True
        self.main_screen.include_uppercase_check.active = True
        self.main_screen.include_digits_check.active = True
        self.main_screen.include_symbols_check.active = True
        self.main_screen.custom_symbols_entry.text = "!@#$%^&*()_+-=[]{}|;:,.<>?"

        self.main_screen.status_label.text = ""

    def _save_passwords_to_file(self):
        if not self.master_password_key or not self.password_file_path:
            show_info_popup("Error", "Master key/path not set. Cannot save.")
            return
        if not isinstance(self.master_password_key, bytearray):
            logging.critical("CRITICAL: master_password_key is not a bytearray before saving!") # FIX: security_logger -> logging
            show_info_popup("Internal Error", "Key material error. Cannot save.")
            return

        os.makedirs(os.path.dirname(self.password_file_path), exist_ok=True)

        temp_file_path = self.password_file_path + ".tmp" 
        data_json = None # Initialize for finally block
        key_for_fernet_bytes = None # Initialize for finally block

        try:
            # Important: Passwords in self.passwords_data are strings. They are encrypted here.
            data_json = json.dumps(self.passwords_data, indent=4)

            key_for_fernet_bytes = bytes(self.master_password_key) 
            encrypted_data = encrypt_data(data_json, key_for_fernet_bytes)
            
            # Securely clear intermediate sensitive data
            # data_json_ba = bytearray(data_json.encode('utf-8')) # If data_json itself considered highly sensitive raw
            # secure_zero_memory(data_json_ba)
            # del data_json_ba
            # key_for_fernet_bytes is a copy of master_password_key, master_password_key (bytearray) is kept.

            if encrypted_data:
                with open(temp_file_path, "wb") as f:
                    f.write(encrypted_data)
                set_restrictive_permissions(temp_file_path) 
                os.replace(temp_file_path, self.password_file_path) 
                # temp_file_path will be removed in finally if os.replace fails or if it still exists
            else:
                logging.error("Encryption resulted in no data. Save aborted.")
                show_info_popup("Save Error", "Encryption failed unexpectedly.")
                return 
        except Exception as e:
            logging.error(f"Could not save passwords: {e}", exc_info=True)
            show_info_popup("Save Error", f"Could not save passwords: {e}")
        finally:
            if data_json: # Clear the JSON string data if it was created
                data_json_ba = bytearray(data_json.encode('utf-8', 'surrogateescape'))
                secure_zero_memory(data_json_ba)
                del data_json_ba
                del data_json
            # key_for_fernet_bytes is local, will be GC'd. The sensitive part is master_password_key, which persists.

            if os.path.exists(temp_file_path):
                try:
                    secure_zero_memory(temp_file_path) # Not for file paths, but if it contained data
                    os.remove(temp_file_path)
                except OSError as e_remove:
                    logging.warning(f"Could not remove temporary save file {temp_file_path}: {e_remove}")

    def _load_passwords(self):
        if not self.master_password_key or not self.password_file_path:
            # logging.warning("Master password key or path not available for loading.") # More appropriate logging
            return

        if os.path.exists(self.password_file_path) and os.path.getsize(self.password_file_path) > 0:
            try:
                with open(self.password_file_path, "rb") as f:
                    encrypted_data = f.read()
                
                # Use bytes() for key, master_password_key is bytearray
                decrypted_json = decrypt_data(encrypted_data, bytes(self.master_password_key))
                
                # Clear encrypted_data from memory
                enc_data_ba = bytearray(encrypted_data)
                secure_zero_memory(enc_data_ba)
                del enc_data_ba
                del encrypted_data

                if decrypted_json:
                    self.passwords_data = json.loads(decrypted_json)
                    # Clear decrypted_json from memory
                    dec_json_ba = bytearray(decrypted_json.encode('utf-8', 'surrogateescape'))
                    secure_zero_memory(dec_json_ba)
                    del dec_json_ba
                    del decrypted_json

                    if hasattr(self, 'main_screen') and self.main_screen:
                        self.main_screen.status_label.text = f"{len(self.passwords_data)} entries loaded."
                        self.main_screen.status_label.color = (0,0,1,1) 
                else:
                    self.passwords_data = [] 
                    show_info_popup("Load Warning", "Password file empty or could not be decrypted (invalid master password?).")
            except json.JSONDecodeError:
                show_info_popup("Load Error", "Could not parse password data. File may be corrupted.")
                self.passwords_data = []
            except Exception as e:
                show_info_popup("Load Error", f"Could not load passwords: {e}")
                self.passwords_data = []
        else:
            self.passwords_data = []
            if hasattr(self, 'main_screen') and self.main_screen:
                self.main_screen.status_label.text = "No passwords in this vault yet."
                self.main_screen.status_label.color = (1, 0.5, 0, 1) 
        
        self._update_password_list_display_kivy()

    def _update_password_list_display_kivy(self):
        if not hasattr(self, 'main_screen') or self.main_screen is None: 
            return

        list_layout = self.main_screen.password_list_layout
        list_layout.clear_widgets() 

        if not self.passwords_data:
            list_layout.add_widget(Label(text="No passwords saved in this vault yet.", size_hint_y=None, height=dp(30)))
        else:
            # Passwords in self.passwords_data["password"] are plaintext here (after decryption)
            # Be mindful if displaying them or parts of them. Currently, only website_name and reminder_date.
            for entry in sorted(self.passwords_data, key=lambda x: x['website_name'].lower()):
                display_text = f"Site: {entry['website_name']}"
                if entry.get("reminder_date"):
                    try:
                        r_date = datetime.fromisoformat(entry["reminder_date"]).strftime('%Y-%m-%d')
                        display_text += f" (Reminder: {r_date})"
                    except: pass 
                
                entry_label = Label(text=display_text, size_hint_y=None, height=dp(30), halign='left', valign='middle')
                entry_label.bind(size=entry_label.setter('text_size')) 
                list_layout.add_widget(entry_label)
        list_layout.do_layout()


    def _check_reminders(self):
        now = datetime.now()
        due_reminders = []
        for entry in self.passwords_data:
            if "reminder_date" in entry:
                try:
                    reminder_date = datetime.fromisoformat(entry["reminder_date"])
                    if reminder_date <= now:
                        due_reminders.append(f"- {entry['website_name']} (due: {reminder_date.strftime('%Y-%m-%d')})")
                except ValueError:
                    logging.warning(f"Warning: Invalid reminder_date format for {entry['website_name']}")

        if due_reminders:
            message = "Password change reminders due/overdue:\n\n" + "\n".join(due_reminders)
            show_info_popup("Password Reminders", message)

if __name__ == "__main__":
    # Basic logging configuration (optional, Kivy might have its own setup)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    PasswordManagerKivyApp().run()

# --- END OF FILE password_manager_app_kivy.py ---
