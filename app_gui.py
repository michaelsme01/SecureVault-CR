import sys
import argparse
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import os
from crypto_core import CryptoCore

class SecureVaultApp:
    def __init__(self, root, profile_name, user_label):
        self.root = root
        self.profile_name = profile_name
        self.user_label = user_label
        self.core = CryptoCore(profile_name)

        self.root.title(f"SecureVault CR — Perfil: {self.user_label}")
        self.root.geometry("860x580")

        self.dest_label = "Destinatario Desconocido"
        self.sender_label = "Emisor Desconocido"

        self._build_ui()

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")

        self.tab_control = ttk.Notebook(self.root)
        self.tab_profile = ttk.Frame(self.tab_control)
        self.tab_send = ttk.Frame(self.tab_control)
        self.tab_recv = ttk.Frame(self.tab_control)
        self.tab_hist = ttk.Frame(self.tab_control)

        self.tab_control.add(self.tab_profile, text=" 👤 Perfil & Llaves ")
        self.tab_control.add(self.tab_send, text=" 📤 Enviar Archivo ")
        self.tab_control.add(self.tab_recv, text=" 📥 Recibir Paquete ")
        self.tab_control.add(self.tab_hist, text=" 📜 Historial ")
        self.tab_control.pack(expand=1, fill="both")

        self._build_tab_profile()
        self._build_tab_send()
        self._build_tab_recv()
        self._build_tab_history()

    # --- PESTAÑA 1: PERFIL & LLAVES ---
    def _build_tab_profile(self):
        frame = ttk.LabelFrame(self.tab_profile, text=" Identidad Criptográfica del Usuario ", padding=15)
        frame.pack(fill="both", expand=True, padx=20, pady=15)

        ttk.Label(frame, text=f"Usuario activo: {self.user_label}", font=("Arial", 12, "bold")).pack(anchor="w", pady=5)
        ttk.Label(frame, text=f"Directorio local: {self.profile_name}/", foreground="gray").pack(anchor="w", pady=2)

        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=10)

        ttk.Label(frame, text="Contraseña de protección para Llaves Privadas (PKCS#8):").pack(anchor="w", pady=2)
        self.entry_pwd = ttk.Entry(frame, show="*", width=30)
        self.entry_pwd.pack(anchor="w", pady=4)
        self.entry_pwd.insert(0, "clave123")

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(anchor="w", pady=10)

        ttk.Button(btn_frame, text="Generar Nuevos Pares de Llaves", command=self._generar_identidad).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Exportar Conjunto Público (.json)", command=self._exportar_publicas).pack(side="left", padx=5)

        self.lbl_status_keys = ttk.Label(frame, text="", font=("Arial", 9, "italic"))
        self.lbl_status_keys.pack(anchor="w", pady=5)

        self.txt_fingerprints = tk.Text(frame, height=5, wrap="word", background="#f0f0f0")
        self.txt_fingerprints.pack(fill="x", pady=5)
        self._refrescar_huellas()

    def _generar_identidad(self):
        pwd = self.entry_pwd.get()
        try:
            self.core.crearIdentidad(pwd)
            messagebox.showinfo("Éxito", f"Identidad creada exitosamente para {self.user_label}.\nLlaves privadas protegidas.")
            self._refrescar_huellas()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _refrescar_huellas(self):
        pwd = self.entry_pwd.get()
        if self.core.tiene_identidad():
            try:
                pubs = self.core.exportarPublicas(pwd)
                self.lbl_status_keys.config(text="✓ Llaves cargadas y autenticadas correctamente.", foreground="green")
                self.txt_fingerprints.delete("1.0", tk.END)
                self.txt_fingerprints.insert(tk.END, f"Huella Cifrado (SHA-256): {pubs['enc_fingerprint']}\n")
                self.txt_fingerprints.insert(tk.END, f"Huella Firma (SHA-256):   {pubs['sig_fingerprint']}")
            except Exception:
                self.lbl_status_keys.config(text="⚠ Llaves existentes pero contraseña inválida.", foreground="red")
        else:
            self.lbl_status_keys.config(text="ℹ No hay llaves creadas. Ingrese una contraseña y presione 'Generar'.", foreground="#555")

    def _exportar_publicas(self):
        pwd = self.entry_pwd.get()
        try:
            pubs = self.core.exportarPublicas(pwd)
            pubs["owner_name"] = self.user_label
            f = filedialog.asksaveasfilename(defaultextension=".json", initialfile=f"public_{self.user_label}.json")
            if f:
                with open(f, "w") as fp:
                    json.dump(pubs, fp, indent=2)
                messagebox.showinfo("Exportado", f"Claves públicas y huellas exportadas en:\n{f}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # --- PESTAÑA 2: ENVIAR ARCHIVO ---
    def _build_tab_send(self):
        frame = ttk.LabelFrame(self.tab_send, text=" Preparación de Envío Cifrado ", padding=15)
        frame.pack(fill="both", expand=True, padx=20, pady=15)

        ttk.Label(frame, text="1. Seleccionar archivo a enviar (Hasta 5 MiB):", font=("Arial", 10, "bold")).pack(anchor="w", pady=5)
        self.lbl_send_file = ttk.Label(frame, text="Ningún archivo seleccionado", foreground="gray")
        self.lbl_send_file.pack(anchor="w", padx=15)
        ttk.Button(frame, text="Examinar Archivo...", command=self._seleccionar_archivo_envio).pack(anchor="w", padx=15, pady=3)

        ttk.Label(frame, text="2. Cargar Clave Pública del Destinatario (.json):", font=("Arial", 10, "bold")).pack(anchor="w", pady=10)
        self.lbl_send_dest = ttk.Label(frame, text="Sin destinatario configurado", foreground="gray")
        self.lbl_send_dest.pack(anchor="w", padx=15)
        ttk.Button(frame, text="Cargar Destinatario...", command=self._cargar_destinatario).pack(anchor="w", padx=15, pady=3)

        ttk.Separator(frame, orient="horizontal").pack(fill="x", pady=20)
        ttk.Button(frame, text="🔒 Generar y Guardar Paquete Seguro (.pkg)", command=self._procesar_envio).pack(pady=10)

    def _seleccionar_archivo_envio(self):
        f = filedialog.askopenfilename()
        if f:
            self.selected_file_path = f
            self.lbl_send_file.config(text=f, foreground="black")

    def _cargar_destinatario(self):
        f = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if f:
            with open(f, "r") as fp:
                data = json.load(fp)
                self.dest_enc_pem = data["enc_public_pem"]
                self.dest_label = data.get("owner_name", os.path.basename(f).replace(".json", ""))
                self.lbl_send_dest.config(text=f"Destinatario: {self.dest_label} | Huella: {data['enc_fingerprint'][:20]}...", foreground="green")

    def _procesar_envio(self):
        pwd = self.entry_pwd.get()
        try:
            if not hasattr(self, 'selected_file_path'):
                raise ValueError("Debe seleccionar un archivo.")
            if not hasattr(self, 'dest_enc_pem'):
                raise ValueError("Debe cargar las llaves públicas del destinatario.")

            pkg_str = self.core.crearEnvio(self.selected_file_path, self.dest_enc_pem, self.dest_label, pwd)
            out = filedialog.asksaveasfilename(defaultextension=".pkg", initialfile="paquete_seguro.pkg")
            if out:
                with open(out, "w") as fp:
                    fp.write(pkg_str)
                messagebox.showinfo("Éxito", f"Paquete cifrado para '{self.dest_label}' guardado en:\n{out}")
                self._cargar_datos_historial()
        except Exception as e:
            messagebox.showerror("Error de Envío", str(e))

    # --- PESTAÑA 3: RECIBIR PAQUETE ---
    def _build_tab_recv(self):
        frame = ttk.LabelFrame(self.tab_recv, text=" Recepción, Verificación y Descifrado ", padding=15)
        frame.pack(fill="both", expand=True, padx=20, pady=15)

        ttk.Label(frame, text="1. Cargar Clave Pública de Firma del Emisor Confiable (.json):", font=("Arial", 10, "bold")).pack(anchor="w", pady=5)
        self.lbl_recv_sender = ttk.Label(frame, text="Sin emisor verificado", foreground="gray")
        self.lbl_recv_sender.pack(anchor="w", padx=15)
        ttk.Button(frame, text="Cargar Emisor Confiable...", command=self._cargar_emisor).pack(anchor="w", padx=15, pady=3)

        ttk.Label(frame, text="2. Importar Paquete Recibido (.pkg):", font=("Arial", 10, "bold")).pack(anchor="w", pady=10)
        ttk.Button(frame, text="🔓 Importar Paquete y Descifrar...", command=self._procesar_recepcion).pack(anchor="w", padx=15, pady=5)

    def _cargar_emisor(self):
        f = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if f:
            with open(f, "r") as fp:
                data = json.load(fp)
                self.sender_sig_pem = data["sig_public_pem"]
                self.sender_label = data.get("owner_name", os.path.basename(f).replace(".json", ""))
                self.lbl_recv_sender.config(text=f"Emisor: {self.sender_label} | Huella: {data['sig_fingerprint'][:20]}...", foreground="green")

    def _procesar_recepcion(self):
        pwd = self.entry_pwd.get()
        try:
            if not hasattr(self, 'sender_sig_pem'):
                raise ValueError("Primero debe cargar el emisor confiable para verificar la firma.")

            pkg_file = filedialog.askopenfilename(filetypes=[("Paquete Seguro", "*.pkg"), ("JSON", "*.json")])
            if not pkg_file: return
            with open(pkg_file, "r") as fp:
                pkg_str = fp.read()

            out_dir = filedialog.askdirectory(title="Seleccionar carpeta donde guardar el archivo descifrado")
            if out_dir:
                res = self.core.recibirEnvio(pkg_str, self.sender_sig_pem, self.sender_label, out_dir, pwd)
                messagebox.showinfo("Éxito", f"¡Firma de '{self.sender_label}' verificada!\nArchivo guardado en:\n{res}")
                self._cargar_datos_historial()
        except Exception as e:
            messagebox.showerror("Rechazo de Recepción", str(e))

    # --- PESTAÑA 4: HISTORIAL (SIN '(SQLite)') ---
    def _build_tab_history(self):
        frame = ttk.LabelFrame(self.tab_hist, text=" Registro persistente de paquetes aceptados ", padding=10)
        frame.pack(fill="both", expand=True, padx=20, pady=15)

        cols = ("Tipo", "Contraparte", "Archivo", "ID Paquete", "Fecha", "Estado", "Detalle")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings", height=12)

        self.tree.heading("Tipo", text="Operación")
        self.tree.heading("Contraparte", text="Emisor / Destinatario")
        self.tree.heading("Archivo", text="Archivo")
        self.tree.heading("ID Paquete", text="ID Paquete (128-bit)")
        self.tree.heading("Fecha", text="Fecha (UTC)")
        self.tree.heading("Estado", text="Estado")
        self.tree.heading("Detalle", text="Detalle Técnico")

        self.tree.column("Tipo", width=90, anchor="center")
        self.tree.column("Contraparte", width=130)
        self.tree.column("Archivo", width=110)
        self.tree.column("ID Paquete", width=130)
        self.tree.column("Fecha", width=130)
        self.tree.column("Estado", width=80, anchor="center")
        self.tree.column("Detalle", width=190)

        self.tree.pack(fill="both", expand=True, pady=5)
        ttk.Button(frame, text="Refrescar Historial", command=self._cargar_datos_historial).pack(pady=5)
        self._cargar_datos_historial()

    def _cargar_datos_historial(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        registros = self.core.consultarHistorial()
        for r in registros:
            # r: (tipo, pkg_id, fecha, contraparte, filename, estado, detalle)
            self.tree.insert("", tk.END, values=(r[0], r[3], r[4], r[1][:16] + "...", r[2], r[5], r[6]))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="profile_default")
    parser.add_argument("--user", default="Usuario")
    args = parser.parse_args()

    root = tk.Tk()
    app = SecureVaultApp(root, args.profile, args.user)
    root.mainloop()
