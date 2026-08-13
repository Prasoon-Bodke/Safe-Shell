# query -> expected top-1 command (you decide these, by hand)
TEST_CASES = [
    ("unlink notes.txt", "rm"),
    ("delete a directory permanently", "rm"),
    ("erase all files in folder", "rm"),
    ("give everyone write access", "chmod"),
    ("run this as root", "sudo"),
    ("wipe the disk", "dd"),
    ("kill a running process", "kill"),
    ("download and run a script", "curl"),
    ("undo my last git commit", "git"),
    ("remove empty folders", "rm"),
    ("format the drive", "mkfs"),
    ("change file owner", "chown"),
    ("stop a service", "systemctl"),
    ("find files by name", "find"),
]