from cryptography.fernet import Fernet
from tkinter import *
from random import randint, shuffle, choice
from tkinter import messagebox
import pyperclip
import json
import hashlib
import heapq

# ---------------------------- Hashing ------------------------------- #
MASTER_HASH = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

def hash_pass(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_master():
    def hash_pass(password):
        return hashlib.sha256(password.encode()).hexdigest()

    def check_password():
        entered = entry.get()
        if hash_pass(entered) == MASTER_HASH:
            login_win.destroy()
        else:
            messagebox.showerror("Access Denied", "Incorrect master password")

    def toggle_password():
        if entry.cget('show') == '*':
            entry.config(show='')
        else:
            entry.config(show='*')

    login_win = Tk()
    login_win.title("🔐 Master Login")
    login_win.geometry("300x180")
    login_win.config(padx=20, pady=20)
    login_win.eval('tk::PlaceWindow . center')  # Center on screen
    login_win.resizable(False, False)

    Label(login_win, text="Enter Master Password", font=("Arial", 12, "bold")).pack(pady=(10, 5))

    entry = Entry(login_win, show='*', width=30, font=("Arial", 10))
    entry.pack(pady=5)
    entry.focus()

    show_check = Checkbutton(login_win, text="Show Password", command=toggle_password)
    show_check.pack(pady=(0, 10))

    Button(login_win, text="Login", width=15, command=check_password, bg="#4CAF50", fg="white", font=("Arial", 10)).pack(pady=5)

    login_win.mainloop()

# ---------------------------- Encryption ------------------------------- #
def load_key():
    return open("secret.key", "rb").read()
key = load_key()
fernet = Fernet(key)

# ---------------------------- PASSWORD GENERATOR ------------------------------- #
def generate():
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

    list1=[choice(letters) for i in range(randint(8, 10))]
    list2=[choice(symbols) for i in range(randint(2, 4))]
    list3=[choice(numbers) for i in range(randint(2, 4))]
    password_list=list1+list2+list3
    shuffle(password_list)

    password = "".join(password_list) #to make the list into a string directly
    input3.insert(0,password)
    pyperclip.copy(password)

# ---------------------------- SAVE PASSWORD ------------------------------- #
def save():
    website = input1.get()
    mail = input2.get()
    password = input3.get()

    if len(website) == 0 or len(password) == 0:
        messagebox.showinfo(title="Oops", message="Can't leave any fields empty")
        return

    # Encrypt the password
    encrypted_password = fernet.encrypt(password.encode()).decode()

    new_data = {
        website: {
            "email": mail,
            "password": encrypted_password,
        }
    }

    try:
        with open("Password_File.json", "r") as pass_file:
            data = json.load(pass_file)
    except FileNotFoundError:
        data = {}

    data.update(new_data)
    with open("Password_File.json", "w") as pass_file:
        json.dump(data, pass_file, indent=4)

    input1.delete(0, END)
    input3.delete(0, END)

# ---------------------------- SEARCH PASSWORD ------------------------------- #
def find_password():
    website = input1.get()
    try:
        with open("Password_File.json", "r") as pass_file:
            data = json.load(pass_file)
    except FileNotFoundError:
        messagebox.showinfo(title="Error", message="No Data File Found")
        return

    if website in data:
        email = data[website]["email"]
        encrypted_password = data[website]["password"]

        try:
            decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
        except:
            messagebox.showerror("Error", "Password could not be decrypted")
            return

        messagebox.showinfo(title="Password Found", message=f"Email: {email}\nPassword: {decrypted_password}")
    else:
        messagebox.showinfo(title="Oops", message="No details for the website exist")

    # Update frequency
    try:
        with open("frequency.json", "r") as freq_file:
            freq_data = json.load(freq_file)
    except FileNotFoundError:
        freq_data = {}

    freq_data[website] = freq_data.get(website, 0) + 1

    with open("frequency.json", "w") as freq_file:
        json.dump(freq_data, freq_file, indent=4)

def show_most_used():
    try:
        with open("frequency.json", "r") as freq_file:
            freq_data = json.load(freq_file)
    except FileNotFoundError:
        messagebox.showinfo("Info", "No usage data available")
        return

    # Build a max heap using negative counts
    heap = [(-count, website) for website, count in freq_data.items()]
    heapq.heapify(heap)

    top_entries = heapq.nsmallest(5, heap)  # Get top 5 used sites

    result = ""
    for i, (neg_count, site) in enumerate(top_entries, 1):
        result += f"{i}. {site} (used {-neg_count} times)\n"

    messagebox.showinfo("Top Used Sites", result or "No data")


# TO GENERATE A KEY FOR ENCRYPTION
# key = Fernet.generate_key()
# with open("secret.key", "wb") as key_file:
#     key_file.write(key)


# TO GENERATE A MASTER HASH
# def hash_pass(password):
#     return hashlib.sha256(password.encode()).hexdigest()
#
# print(hash_pass("mystrongpassword"))

# ---------------------------- UI SETUP ------------------------------- #
verify_master()
# ---------------------------- UI SETUP ------------------------------- #
window = Tk()
window.title("🔐 Password Manager")
window.config(padx=50, pady=50,bg="#121212")
window.resizable(False, False)

canvas = Canvas(width=200, height=200, highlightthickness=0,bg="#121212")
lock_image = PhotoImage(file="lock - Copy.png")  # Make sure logo is good quality
canvas.create_image(100, 100, image=lock_image)
canvas.grid(row=0, column=1)

# Labels
Label(
    text="Website:",
    font=("Arial", 10, "bold"),
    fg="white",
    bg="#121212"
).grid(row=1, column=0, sticky="e", pady=5)
Label(
    text="Email/Username:",
    font=("Arial", 10, "bold"),
    fg="white",
    bg="#121212"
).grid(row=2, column=0, sticky="e", pady=5)

Label(
    text="Password:",
    font=("Arial", 10, "bold"),
    fg="white",
    bg="#121212"
).grid(row=3, column=0, sticky="e", pady=5)

# Inputs
input1 = Entry(width=32, bg="#1E1E1E", fg="white", insertbackground='white')
input1.grid(row=1, column=1, pady=5, sticky="w")
input1.focus()

input2 = Entry(width=51, bg="#1E1E1E", fg="white", insertbackground='white')
input2.grid(row=2, column=1, columnspan=2, pady=5, sticky="w")
input2.insert(0, "Devanshtyagi@gmail.com")  # Change default email

input3 = Entry(width=32, bg="#1E1E1E", fg="white", insertbackground='white')
input3.grid(row=3, column=1, pady=5, sticky="w")

# Buttons
Button(text="Search", width=15, command=find_password, bg="#2196F3", fg="white").grid(row=1, column=2, padx=5)
Button(text="Generate Password", command=generate, bg="#FF9800", fg="white").grid(row=3, column=2, padx=5)
Button(text="Add", width=44, command=save, bg="#4CAF50", fg="white").grid(row=4, column=1, columnspan=2, pady=10)
Button(text="Most Used", width=44, command=show_most_used, bg="#9C27B0", fg="white").grid(row=5, column=1, columnspan=2, pady=5)


window.mainloop()