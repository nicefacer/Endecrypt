from tkinter import Tk, Frame, Label, Button, Entry, StringVar, DISABLED, NORMAL,BOTTOM, SUNKEN, W, X
from tkinter import filedialog, messagebox, EXTENDED, BooleanVar
from tkinter import ttk,BOTH,END,Scrollbar,VERTICAL,Listbox,RIGHT,Y,LEFT,SINGLE,Text
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from google.cloud import storage
from dotenv import load_dotenv
import os
import threading
import shutil
import socket
import json
import base64


load_dotenv()

# Retrieve the JSON credentials string from the environment variable
credentials_json_string = os.getenv('GOOGLE_APPLICATION_CREDENTIALS_JSON')

if credentials_json_string is None:
    raise ValueError('GOOGLE_APPLICATION_CREDENTIALS_JSON environment variable is not set')

# Convert the JSON string back to a JSON object
credentials = json.loads(credentials_json_string)

# Initialize Google Cloud Storage client using the credentials JSON object
client = storage.Client.from_service_account_info(credentials)

BUCKET_NAME = os.getenv('BUCKET_NAME')
bucket = client.bucket(BUCKET_NAME)

# Retrieve and encode the SALT
salt_b64 = os.getenv('SALT')

# Decode the base64 string to get the actual salt bytes
SALT = base64.b64decode(salt_b64)


def derive_key(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# GUI Setup
root = Tk()
root.title("ENCRYPT/DECRYPT App")
root.geometry("800x500")

key = None
status_bar_text = StringVar()
def on_selection_change(event):
    # Update the variable when a selection in the listbox changes
    var_selected_files.set(True)

def check_network():
    try:
        socket.create_connection(("www.google.com", 80))
        return True
    except OSError:
        return False

def encrypt_and_upload(files):
    global key
    for file in files:
        with open(file, 'rb') as f:
            data = f.read()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        blob = bucket.blob(os.path.basename(file) + '.enc')
        blob.upload_from_string(iv + encrypted_data)
        os.remove(file)
        update_status_bar(f"Uploaded encrypted: {file}")

def handle_encrypt():
    if not check_network():
        update_status_bar("No network connection available.")
        return

    files = filedialog.askopenfilenames()
    if not files:
        return

    confirmation = messagebox.askyesno("Confirm", "Encryption finished. Upload now?")
    if confirmation:
        threading.Thread(target=encrypt_and_upload, args=(files,)).start()

var_selected_files = BooleanVar(value=False)
file_listbox = Listbox(root, selectmode=EXTENDED, width=85, height=270)
file_listbox.place(x=12, y=275)
#var_selected_files = StringVar()
file_listbox.bind('<<ListboxSelect>>', on_selection_change)


def populate_listbox():
    global bucket
    file_listbox.delete(0, 'end')  # Clear existing entries
    for blob in bucket.list_blobs():  # Assume bucket.list_blobs() gets all files in the bucket
        file_listbox.insert('end', blob.name)

def get_selected_files():
    selected_indices = file_listbox.curselection()
    return [file_listbox.get(i) for i in selected_indices]




def decrypt_and_save(file_name):
    global key
    try:
        with open(file_name, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        iv = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()

        with open(os.path.splitext(file_name)[0], 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)
        
        # Optionally delete the downloaded encrypted file after decryption
        os.remove(file_name)

    except Exception as e:
        update_status_bar(f"Error decrypting {file_name}: {e}")


def handle_decrypt():
    if not check_network():
        update_status_bar("No network connection available.")
        return

    populate_listbox()  # Assume this function populates a GUI element with files from the cloud bucket
    
    # Wait for file selection and user action to proceed with decryption
    var_selected_files.set(False)
    root.wait_variable(var_selected_files)  # Assume var_selected_files gets set when files are selected in the GUI

    selected_files = get_selected_files()  # Assume this function retrieves the list of selected files from the GUI
    if not selected_files:
        messagebox.showinfo("No file selected", "Please select one or more files to decrypt.")
        return

    confirmation = messagebox.askyesno("Confirm", "Do you want to download and decrypt the selected files?")
    if confirmation:
        download_path = 'download_path'
        if not os.path.exists(download_path):
            os.makedirs(download_path)
        for file_name in selected_files:
            update_status_bar(f"Downloading: {file_name}")
            blob = bucket.blob(file_name)
            local_file_path = os.path.join('download_path', file_name)  # Set a proper download path
            blob.download_to_filename(local_file_path)
            decrypt_and_save(local_file_path)
            update_status_bar(f"Decrypted: {file_name}")
            
        update_status_bar("All selected files have been decrypted.")


def update_status_bar(text):
    status_bar_text.set(text)

def delete_log():
    if messagebox.askyesno("Confirm", "Delete the log file?"):
        if os.path.exists("log.txt"):
            os.remove("log.txt")
            update_status_bar("Log deleted.")
        else:
            update_status_bar("Log file does not exist.")

def stop_operation():
    global current_operation
    if current_operation and current_operation.is_alive():
        current_operation.join()
        update_status_bar("Operation stopped.")
    else:
        update_status_bar("No active operation.")

def show_log():
    if os.path.exists("log.txt"):
        with open("log.txt", "r") as f:
            log_contents = f.read()
            messagebox.showinfo("Log", log_contents)
    else:
        update_status_bar("Log file does not exist.")
        
def set_master_password():
    global key
    password = master_password_entry.get()
    key = derive_key(password)
    update_status_bar("Master password set and key derived.")

# Button Encrypt
encrypt_button = Button(root, text="Encrypt", width=20, height=3, bg="green", fg="white",font=("Arial", 10), command=handle_encrypt)
encrypt_button.place(x=50, y=60)

# Button Decrypt
decrypt_button = Button(root, text="Decrypt", width=20, height=3, bg="dark gray", fg="white",font=("Arial", 10), command=handle_decrypt)
decrypt_button.place(x=300, y=60)

# Button Stop Operation
stop_button = Button(root, text="Stop operation", width=20, height=3, bg="red", fg="white",font=("Arial", 10), command=stop_operation)
stop_button.place(x=600, y=60)

# Master Password Entry
master_password_label = Label(root, text="Master Password:")
master_password_label.place(x=250, y=140)
master_password_entry = Entry(root, width=20, show='*')
master_password_entry.place(x=350, y=166)
set_password_button = Button(root, text="Set Master Password", width=20, height=2, bg="blue",fg="white", font=("Arial", 10), command=set_master_password)
set_password_button.place(x=480, y=166)

# Horizontal line
line2 = Frame(root, height=2, bg="black")
line2.place(x=5, y=264, relwidth=1)

# Button Show Log
show_log_button = Button(root, text="Show Log", width=20, height=3, bg="yellow", fg="black", font=("Arial", 10), command=show_log)
show_log_button.place(x=612, y=325)

# Button Delete Log
delete_log_button = Button(root, text="Delete Log", width=20, height=3, bg="black", fg="white",font=("Arial", 10), command=delete_log)
delete_log_button.place(x=620, y=418)

# Status Bar Setup
status_bar = Label(root, textvariable=status_bar_text, bg="light gray", fg="black", font=("Arial", 10), anchor='w')
status_bar.pack(side='bottom', fill='x')

# Making The UI Responsive
root.resizable(False, False)

root.mainloop()