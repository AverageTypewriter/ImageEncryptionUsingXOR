from __future__ import division, print_function, unicode_literals

import sys
import os
from tkinter import *
from tkinter import filedialog, messagebox
from PIL import Image
import math # Still useful for general math, though less so with XOR


passg = None

# --- Helper Functions ---
def load_image(name):
    """Loads an image from the given path."""
    try:
        return Image.open(name)
    except FileNotFoundError:
        messagebox.showerror("Error", f"Image file not found: {name}")
        return None
    except Exception as e:
        messagebox.showerror("Error", f"Could not load image {name}: {e}")
        return None

def save_image(image, path):
    """Saves an image to the given path."""
    try:
        image.save(path)
        return True
    except Exception as e:
        messagebox.showerror("Error", f"Could not save image to {path}: {e}")
        return False

# --- XOR Encryption/Decryption (Core Logic) ---

def xor_encrypt_decrypt_bytes(data_bytes, numeric_key):
    """
    Encrypts or decrypts bytes using a simple XOR cipher with a numeric key.
    XOR is its own inverse, so the same function is used for both.
    """
    if not isinstance(numeric_key, int) or not (0 <= numeric_key <= 255):
        raise ValueError("Numeric key must be an integer between 0 and 255.")
    
    # Create a bytearray from the input data to allow in-place modification
    processed_bytes = bytearray(data_bytes)
    
    # XOR each byte with the numeric key
    for i in range(len(processed_bytes)):
        processed_bytes[i] = processed_bytes[i] ^ numeric_key
        
    return bytes(processed_bytes) # Convert back to immutable bytes

def process_image_xor(image_path, numeric_key_str, output_dir, is_encrypt=True):
    """
    Encrypts or decrypts an image file using the XOR cipher.
    Reads image data as raw bytes and applies XOR.
    """
    try:
        # Validate numeric key
        try:
            numeric_key = int(numeric_key_str) % 256 # Use modulo 256 to ensure key is within byte range
        except ValueError:
            messagebox.showerror("Key Error", "Please enter a valid numeric key (integer).")
            return False
        
        if not (0 <= numeric_key <= 255):
             messagebox.showwarning("Key Warning", f"Key '{numeric_key_str}' converted to {numeric_key}. For XOR, a key between 0 and 255 is ideal.")

        base_name = os.path.basename(image_path)
        name_without_ext = os.path.splitext(base_name)[0]
        original_ext = os.path.splitext(base_name)[1] # Keep original extension or use a custom one

        # Read the raw binary data of the image file
        with open(image_path, 'rb') as f:
            image_data = f.read()

        # Apply XOR encryption/decryption
        processed_data = xor_encrypt_decrypt_bytes(image_data, numeric_key)

        # Determine output file path and message
        if is_encrypt:
            output_file_path = os.path.join(output_dir, f"{name_without_ext}_encrypted{original_ext}")
            success_message = "Encryption Complete"
            detail_message = f"Image encrypted successfully!\nEncrypted File: {output_file_path}"
        else:
            output_file_path = os.path.join(output_dir, f"{name_without_ext}_decrypted{original_ext}")
            success_message = "Decryption Complete"
            detail_message = f"Image decrypted successfully!\nDecrypted File: {output_file_path}"

        # Write the processed binary data back to a new file
        with open(output_file_path, 'wb') as f:
            f.write(processed_data)

        messagebox.showinfo(success_message, detail_message)
        return True

    except FileNotFoundError:
        messagebox.showerror("Error", f"File not found: {image_path}")
        return False
    except ValueError as e:
        messagebox.showerror("Error", f"Processing error: {e}")
        return False
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")
        return False

# --- GUI Stuff ---
def pass_alert():
   messagebox.showwarning("Key Alert", "Please enter a numeric key.")

def encrypt_action():
    """Action for the Encrypt button."""
    key_input = passg.get()
    if not key_input:
        pass_alert()
        return

    filename = filedialog.askopenfilename(
        title="Select Image to Encrypt",
        filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.gif")]
    )
    if not filename:
        return # User cancelled

    output_dir = os.path.dirname(filename)
    process_image_xor(filename, key_input, output_dir, is_encrypt=True)

def decrypt_action():
    """Action for the Decrypt button."""
    key_input = passg.get()
    if not key_input:
        pass_alert()
        return

    filename = filedialog.askopenfilename(
        title="Select Encrypted File to Decrypt",
        # We assume the encrypted file still has its original image extension (e.g., .jpg, .png)
        filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.gif")]
    )
    if not filename:
        return # User cancelled
    
    output_dir = os.path.dirname(filename)
    process_image_xor(filename, key_input, output_dir, is_encrypt=False)

class App:
  def __init__(self, master):
    global passg # Access the global variable for the Entry widget
    
    master.title("Image Encryption/Decryption (XOR Cipher)")
    master.geometry("400x300") # Set initial window size
    master.resizable(False, False) # Prevent resizing

    # Title and Author
    title_label = Label(master, text="Image Encryption/Decryption", font=('Helvetica', 16, 'bold'))
    title_label.pack(pady=10)
    
    author_label = Label(master, text="Made by Aditya", font=('Helvetica', 10, 'italic')) # Removed "Enhanced by AI"
    author_label.pack(pady=5)

    # Key input
    key_frame = Frame(master)
    key_frame.pack(pady=10)

    key_label = Label(key_frame, text="Enter Numeric Key (0-255):")
    key_label.pack(side=LEFT)
    
    passg = Entry(key_frame, width=30, font=('Arial', 10)) # Removed show="*" to show numeric key
    passg.pack(side=RIGHT)

    # Buttons
    button_frame = Frame(master)
    button_frame.pack(pady=20)

    self.encrypt_button = Button(button_frame,
                                 text="Encrypt Image",
                                 command=encrypt_action, # Changed command
                                 width=20, height=3,
                                 bg='#4CAF50', fg='white',
                                 font=('Arial', 12, 'bold'))
    self.encrypt_button.pack(side=LEFT, padx=15)

    self.decrypt_button = Button(button_frame,
                                 text="Decrypt Image",
                                 command=decrypt_action, # Changed command
                                 width=20, height=3,
                                 bg='#f44336', fg='white',
                                 font=('Arial', 12, 'bold'))
    self.decrypt_button.pack(side=RIGHT, padx=15)

# --- Main Execution ---
if __name__ == "__main__":
    root = Tk()
    app = App(root)
    root.mainloop()