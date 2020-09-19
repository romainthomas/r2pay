import lief
import pathlib
import sys
CWD = pathlib.Path(__file__).parent

if len(sys.argv) != 2:
    print("Usage: {} <path to libnative-lib.so>".format(sys.argv[0]), file=sys.stderr)
    sys.exit(1)

target_lib = pathlib.Path(sys.argv[1])
output = CWD / (target_lib.stem + "-patched" + target_lib.suffix)
lib = lief.parse(target_lib.as_posix())

# Keys are str object for a better understanding :)
INST = {
    "mov x0, #0":  [0xe0, 0x03, 0x1f, 0xaa],
    "ret":         [0xc0, 0x03, 0x5f, 0xd6],
    "nop":         [0x1f, 0x20, 0x03, 0xd5],
}

PATCHES = [
    # Patch the .plt entry of pthread_create
    (0x5870, INST["mov x0, #0"]),
    (0x5874, INST["ret"]),

    # Disable anti-frida checks
    (0x0d718c, INST["mov x0, #0"]), # /proc/self/fd : patch the result of readlinkat syscall
    (0x0e1940, INST["mov x0, #0"]), # /proc/self/task/<tid>/status: patch the result of read syscall

    # Disable .text integrity checks
    (0xB64D0, INST["nop"]),
]

for patch in PATCHES:
    lib.patch_address(*patch)

lib.write(output.as_posix())
