import tkinter as tk
from tkinter import messagebox

import rsa

class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.title("RSA Program")
        self.pack()
        self.size= None
        self.public_key = None
        self.private_key = None
    
        self.create_widgets()
     


    def create_widgets(self):
        self.generate_keys_button = tk.Button(self)
        self.generate_keys_button["text"] = "Generate Keys"
        self.generate_keys_button["command"] = self.generate_keys
        self.generate_keys_button.pack(side="top")
        self.Pukeys_label = tk.Label(self, text="")
        self.Pukeys_label.pack(side="top")
        self.Prkeys_label = tk.Label(self, text="")
        self.Prkeys_label.pack(side="top")
        self.mod_label = tk.Label(self, text="")
        self.mod_label.pack(side="top")


        self.message_label = tk.Label(self, text="Message:")
        self.message_label.pack(side="top")

        self.message_entry = tk.Entry(self)
        self.message_entry.pack(side="top")

        self.encrypt_button = tk.Button(self)
        self.encrypt_button["text"] = "Encrypt"
        self.encrypt_button["command"] = self.encrypt_message
        self.encrypt_button.pack(side="top")

        self.ciphertext_label = tk.Label(self, text="Ciphertext:")
        self.ciphertext_label.pack(side="top")

        self.ciphertext_entry = tk.Entry(self)
        self.ciphertext_entry.pack(side="top")

        self.decrypt_button= tk.Button(self)
        self.decrypt_button["text"] = "Decrypt"
        self.decrypt_button["command"] = self.decrypt_ciphertext
        self.decrypt_button.pack(side="top")

        self.decrypted_message_label = tk.Label(self, text="Decrypted Message:")
        self.decrypted_message_label.pack(side="top")

        self.decrypted_message_entry = tk.Entry(self)
        self.decrypted_message_entry.pack(side="top")

        self.sign_button = tk.Button(self)
        self.sign_button["text"] = "Sign"
        self.sign_button["command"] = self.sign_message
        self.sign_button.pack(side="top")

        self.signature_label = tk.Label(self, text="Signature:")
        self.signature_label.pack(side="top")

        self.signature_entry = tk.Entry(self)
        self.signature_entry.pack(side="top")

        self.verify_button = tk.Button(self)
        self.verify_button["text"] = "Verify"
        self.verify_button["command"] = self.verify_signature
        self.verify_button.pack(side="top")

        self.verify_result_label = tk.Label(self, text="")
        self.verify_result_label.pack(side="top")

    def generate_keys(self):
        self.size=1024

        public_key, private_key = rsa.generate_keypair(self.size)
        self.public_key = public_key
        self.private_key = private_key

        self.Pukeys_label.configure(text="Public key: (n,e)" + str(public_key))
        self.Prkeys_label.configure(text="Private key: (n,d) " + str(private_key))
        self.mod_label.configure(text="n: " + str(public_key[0]))



    def encrypt_message(self):
        plaintext = self.message_entry.get()
        if not plaintext:
            messagebox.showerror("Error", "Please enter a message to encrypt")
            return

  

        if self.public_key is None:
            messagebox.showerror("Error", "Public key has not been generated yet")
            return


        ciphertext = rsa.encrypt_message(plaintext, self.public_key)

        self.ciphertext_entry.delete(0, tk.END)
        self.ciphertext_entry.insert(0, ciphertext)

    def decrypt_ciphertext(self):
        ciphertext = self.ciphertext_entry.get()
 

        if self.private_key is None:
            messagebox.showerror("Error", "Private key has not been generated yet")
            return

        # Decrypt ciphertext using private key
        message_dec = rsa.decrypt_message(ciphertext, self.private_key)

        self.decrypted_message_entry.delete(0, tk.END)
        self.decrypted_message_entry.insert(0, message_dec)

    def sign_message(self):
        message = self.message_entry.get()
        signature = rsa.sign_message(message, self.private_key)
        self.signature_entry.delete(0, tk.END)
        self.signature_entry.insert(0, signature)

    def verify_signature(self):
        signature = self.signature_entry.get()
        message=self.message_entry.get()
        result = rsa.verify_signature(message, signature, self.public_key)
        if result:
            self.verify_result_label.configure(text="Signature is valid")
        else:
            self.verify_result_label.configure(text="Signature is invalid")

root = tk.Tk()
app = Application(master=root)
app.mainloop()