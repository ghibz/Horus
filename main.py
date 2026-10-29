# Launch the Horus dashboard
import sys
import traceback

from ids import config


def _log(text):
    # Under pythonw / a double-clicked .pyw there is no console (sys.stderr is
    # None), so printing there would itself crash. Only print if it exists.
    if sys.stderr is not None:
        print(text, file=sys.stderr)


def show_startup_error(title, message):
    # Tell the user what went wrong: console (if any) AND a message box, so the
    # failure is visible even when Horus was started without a console.
    _log(f"[ERROR] {title}\n{message}")
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(title, message, parent=root)
        root.destroy()
    except Exception:
        pass   # no tkinter / no display: the console message above is all we have


def _load_gui():
    # imported here, not at the top, so config problems are caught first
    from ids.gui.app import run
    return run


def main(load_gui=_load_gui):
    # Returns the exit code: 0 = normal exit, 1 = Horus could not start / crashed.
    try:
        config.validate()           # check config.yaml before anything else
        run = load_gui()
        run()
    except config.ConfigError as e:
        show_startup_error(
            "Horus - invalid settings",
            f"Horus could not start because of a problem in the settings file:\n\n"
            f"{e}\n\n"
            f"File: {config.config_path()}\n\n"
            f"Fix the line above, or delete the file to use the built-in "
            f"defaults, then start Horus again.")
        return 1
    except Exception as e:
        _log(traceback.format_exc())
        show_startup_error(
            "Horus - error",
            f"Horus stopped because of an unexpected error:\n\n"
            f"{type(e).__name__}: {e}\n\n"
            f"Common causes: Npcap is not installed, or a required package is "
            f"missing (pip install -r requirements.txt).")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())