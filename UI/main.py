import pathlib
import tkinter as tk
import tkinter.ttk as ttk
import pygubu

PROJECT_PATH = pathlib.Path(__file__).parent
PROJECT_UI = PROJECT_PATH / "main.ui"

class App:
    def __init__(self, master=None):
        self.builder = builder = pygubu.Builder()
        builder.add_resource_path(PROJECT_PATH)

        builder.add_from_file(PROJECT_UI)

        self.mainwindow = builder.get_object('开盒', master)

        builder.connect_callbacks(self)

        self.retrieve = builder.get_object('retrieveWindow', master)
        self.write = builder.get_object('writeWindow', master)
        self.retrieve.withdraw()
        self.write.withdraw()

        # 绑定Radiobutton
        self.privacy_var = tk.StringVar()
        self.radio_private = builder.get_object('radioPrivate', master)
        self.radio_private.config(variable=self.privacy_var, value='private')

        self.radio_not_private = builder.get_object('radioNotPrivate', master)
        self.radio_not_private.config(variable=self.privacy_var, value='not_private')

        # 绑定Entry
        self.write_who_var = tk.StringVar()
        self.write_with_whom_var = tk.StringVar()
        self.write_relation_var = tk.StringVar()

        self.write_who = builder.get_object('writeWho', master)
        self.write_who.config(textvariable=self.write_who_var)

        self.write_with_whom = builder.get_object('writeWithWhom', master)
        self.write_with_whom.config(textvariable=self.write_with_whom_var)

        self.write_relation = builder.get_object('writeRelation', master)
        self.write_relation.config(textvariable=self.write_relation_var)

        self.retrieve_who_var = tk.StringVar()
        self.retrieve_with_whom_var = tk.StringVar()

        self.retrieve_who = builder.get_object('retrieveWho', master)
        self.retrieve_who.config(textvariable=self.retrieve_who_var)

        self.retrieve_with_whom = builder.get_object('retrieveWithWhom', master)
        self.retrieve_with_whom.config(textvariable=self.retrieve_with_whom_var)

    def run(self):
        self.mainwindow.mainloop()

    def showWrite(self, event=None):
        self.write.deiconify()

    def showRetrieve(self, event=None):
        self.retrieve.deiconify()

    def retrieveButtonHandler(self, event=None):
        print('fuck you')
        print(self.retrieve_who_var.get(), self.retrieve_with_whom_var.get())

    def writeButtonHandler(self, event=None):
        print(self.privacy_var.get(), self.write_who_var.get(), self.write_with_whom_var.get(), self.write_relation_var.get())

if __name__ == '__main__':
    app = App()
    app.run()
