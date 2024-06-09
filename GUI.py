import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from PIL import Image, ImageTk
import asyncio

class MyGUI:
    def __init__(self, root, image_path):
        self.root = root
        self.root.title("主窗口")
        self.root.geometry("400x400")

        # 加载并调整图片大小
        self.image_path = image_path
        self.image = self.resize_image(image_path, 200, 200)

        image_label = tk.Label(self.root, image=self.image)
        image_label.pack(pady=20)

        # 放置按钮
        query_button = tk.Button(self.root, text="查询", command=self.open_query_window)
        query_button.pack(pady=10)

        create_button = tk.Button(self.root, text="新建", command=self.open_create_window)
        create_button.pack(pady=10)

    def resize_image(self, image_path, width, height):
        image = Image.open(image_path)
        image = image.resize((width, height), Image.LANCZOS)
        return ImageTk.PhotoImage(image)

    def handle_query(self, who, with_whom):
        messagebox.showinfo("查询", f"查询: 谁: {who}, 和谁: {with_whom}")

    async def handle_create(self, who, with_whom, encryption, how_met):
        # 模拟一个异步任务
        await asyncio.sleep(2)  # 模拟长时间运行的任务
        messagebox.showinfo("新建", f"新建: 谁: {who}, 和谁: {with_whom}, 加密: {encryption}, 如何认识的: {how_met}")

    def open_query_window(self):
        query_window = tk.Toplevel(self.root)
        query_window.title("查询")
        query_window.geometry("300x200")

        tk.Label(query_window, text="谁？").pack(pady=5)
        who_entry = tk.Entry(query_window)
        who_entry.pack(pady=5)

        tk.Label(query_window, text="和谁？").pack(pady=5)
        with_whom_entry = tk.Entry(query_window)
        with_whom_entry.pack(pady=5)

        def on_query():
            who = who_entry.get()
            with_whom = with_whom_entry.get()
            if not who or not with_whom:
                messagebox.showwarning("输入错误", "请输入完整的信息")
            else:
                self.handle_query(who, with_whom)

        tk.Button(query_window, text="查询", command=on_query).pack(pady=10)

    def open_create_window(self):
        create_window = tk.Toplevel(self.root)
        create_window.title("新建")
        create_window.geometry("300x300")

        # 配置列权重，使内容居中
        create_window.columnconfigure(0, weight=1)
        create_window.columnconfigure(1, weight=1)

        tk.Label(create_window, text="谁？").grid(row=0, column=0, padx=10, pady=5, sticky='e')
        who_entry = tk.Entry(create_window)
        who_entry.grid(row=0, column=1, padx=10, pady=5, sticky='w')

        tk.Label(create_window, text="和谁？").grid(row=1, column=0, padx=10, pady=5, sticky='e')
        with_whom_entry = tk.Entry(create_window)
        with_whom_entry.grid(row=1, column=1, padx=10, pady=5, sticky='w')

        tk.Label(create_window, text="如何认识的").grid(row=2, column=0, padx=10, pady=5, sticky='e')
        how_met_entry = tk.Entry(create_window)
        how_met_entry.grid(row=2, column=1, padx=10, pady=5, sticky='w')

        tk.Label(create_window, text="选择加密方式").grid(row=3, column=0, columnspan=2, pady=5)
        encryption = tk.StringVar(value="加密")
        tk.Radiobutton(create_window, text="加密", variable=encryption, value="加密").grid(row=4, column=0, padx=10, pady=5)
        tk.Radiobutton(create_window, text="不加密", variable=encryption, value="不加密").grid(row=4, column=1, padx=10, pady=5)

        def on_create():
            who = who_entry.get()
            with_whom = with_whom_entry.get()
            how_met = how_met_entry.get()
            encryption_choice = encryption.get()
            if not who or not with_whom or not how_met:
                messagebox.showwarning("输入错误", "请输入完整的信息")
            else:
                asyncio.create_task(self.handle_create(who, with_whom, encryption_choice, how_met))

        tk.Button(create_window, text="确定", command=on_create).grid(row=5, column=0, columnspan=2, pady=10)

def create_and_run_gui(image_path='C:/Users/Administrator/Desktop/yx.png'):
    root = tk.Tk()
    app = MyGUI(root, image_path)

    # 将 asyncio 事件循环嵌入到 Tkinter 事件循环中
    async def main_loop():
        while True:
            try:
                root.update()
                await asyncio.sleep(0.01)
            except tk.TclError as e:
                if "application has been destroyed" not in str(e):
                    raise
                break

    asyncio.run(main_loop())

create_and_run_gui()
