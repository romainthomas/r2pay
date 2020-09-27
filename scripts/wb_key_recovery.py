import pathlib
import phoenixAES

CWD = pathlib.Path(__file__).parent
trace_dir = CWD / ".." / "assets" / "wb-traces"

for f in trace_dir.iterdir():
    x = phoenixAES.crack_file(f)
    if x is not None:
        print(x, f.name)
