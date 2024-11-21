import customtkinter as ctk
from tkinter import filedialog, messagebox
from PyPDF2 import PdfReader, PdfWriter

# Function to add a password to a PDF
def add_password(input_pdf, output_pdf, password):
    try:
        reader = PdfReader(input_pdf)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        writer.encrypt(password)
        with open(output_pdf, "wb") as output_file:
            writer.write(output_file)
        messagebox.showinfo("Success", f"Password added and saved as:\n{output_pdf}")
    except Exception as e:
        messagebox.showerror("Error", str(e))


# Function to remove a password from a PDF
def remove_password(input_pdf, output_pdf, password):
    try:
        reader = PdfReader(input_pdf)
        if reader.is_encrypted:
            reader.decrypt(password)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        with open(output_pdf, "wb") as output_file:
            writer.write(output_file)
        messagebox.showinfo("Success", f"Password removed and saved as:\n{output_pdf}")
    except Exception as e:
        messagebox.showerror("Error", str(e))


# Browse for the input file
def browse_input_file():
    file_path = filedialog.askopenfilename(title="Select a PDF file", filetypes=[("PDF files", "*.pdf")])
    input_entry.set(file_path)


# Browse for the output file
def browse_output_file():
    file_path = filedialog.asksaveasfilename(title="Save As", defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
    output_entry.set(file_path)


# Start the selected process
def start_process():
    input_pdf = input_entry.get()
    output_pdf = output_entry.get()
    password = password_entry.get()

    if not input_pdf or not output_pdf or not password:
        messagebox.showwarning("Input Error", "Please fill in all fields.")
        return

    if action_var.get() == "Remove Password":
        remove_password(input_pdf, output_pdf, password)
    elif action_var.get() == "Add Password":
        add_password(input_pdf, output_pdf, password)


# Initialize CustomTkinter
ctk.set_appearance_mode("dark")  # Modes: "dark", "light", or "system"
ctk.set_default_color_theme("blue")  # Themes: "blue", "green", "dark-blue"

# Create the window
app = ctk.CTk()
app.title("PDF Password Manager")
app.geometry("600x450")

# Variables for user inputs
input_entry = ctk.StringVar()
output_entry = ctk.StringVar()
password_entry = ctk.StringVar()
action_var = ctk.StringVar(value="Remove Password")

# UI Components
ctk.CTkLabel(app, text="PDF Password Manager", font=("Arial", 18)).pack(pady=10)

# Action selection
ctk.CTkLabel(app, text="Select Action:", font=("Arial", 12)).pack(anchor="w", padx=20)
action_button = ctk.CTkSegmentedButton(app, values=["Remove Password", "Add Password"], variable=action_var)
action_button.pack(pady=10, padx=20, fill="x")

# Input File
ctk.CTkLabel(app, text="Select PDF File:", font=("Arial", 12)).pack(anchor="w", padx=20)
input_frame = ctk.CTkFrame(app)
input_frame.pack(pady=5, padx=20, fill="x")
ctk.CTkEntry(input_frame, textvariable=input_entry).pack(side="left", fill="x", expand=True, padx=5)
ctk.CTkButton(input_frame, text="Browse", command=browse_input_file).pack(side="right", padx=5)

# Output File
ctk.CTkLabel(app, text="Save As:", font=("Arial", 12)).pack(anchor="w", padx=20)
output_frame = ctk.CTkFrame(app)
output_frame.pack(pady=5, padx=20, fill="x")
ctk.CTkEntry(output_frame, textvariable=output_entry).pack(side="left", fill="x", expand=True, padx=5)
ctk.CTkButton(output_frame, text="Browse", command=browse_output_file).pack(side="right", padx=5)

# Password
ctk.CTkLabel(app, text="Password:", font=("Arial", 12)).pack(anchor="w", padx=20)
password_frame = ctk.CTkFrame(app)
password_frame.pack(pady=5, padx=20, fill="x")
ctk.CTkEntry(password_frame, textvariable=password_entry, show="*").pack(fill="x", padx=5)

# Process Button
ctk.CTkButton(app, text="Apply", command=start_process, font=("Arial", 14)).pack(pady=20, padx=20, fill="x")

# Run the app
app.mainloop()
