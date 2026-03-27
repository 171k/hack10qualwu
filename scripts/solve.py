import math
import re
import socket
import sys
import random
from typing import List, Tuple


HOST = "34.126.187.50"
PORT = 5500
E = 17
LEAKS_NEEDED = 624
MASK32 = 0xFFFFFFFF
PROMPTS = (
    b"Guess the next number: ",
    b"Predict the next number or type 'exit': ",
)


def recv_until_prompt(sock: socket.socket) -> bytes:
    data = bytearray()
    while not any(marker in data for marker in PROMPTS):
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed")
        data.extend(chunk)
    return bytes(data)


def send_line(sock: socket.socket, line: str) -> None:
    sock.sendall(line.encode() + b"\n")


def undo_right_shift_xor(value: int, shift: int) -> int:
    result = 0
    for bit in range(31, -1, -1):
        shifted = (result >> (bit + shift)) & 1 if bit + shift <= 31 else 0
        current = ((value >> bit) & 1) ^ shifted
        result |= current << bit
    return result & MASK32


def undo_left_shift_xor_mask(value: int, shift: int, mask: int) -> int:
    result = 0
    for bit in range(32):
        shifted = ((result >> (bit - shift)) & 1) if bit - shift >= 0 and ((mask >> bit) & 1) else 0
        current = ((value >> bit) & 1) ^ shifted
        result |= current << bit
    return result & MASK32


def untemper(value: int) -> int:
    value = undo_right_shift_xor(value, 18)
    value = undo_left_shift_xor_mask(value, 15, 0xEFC60000)
    value = undo_left_shift_xor_mask(value, 7, 0x9D2C5680)
    value = undo_right_shift_xor(value, 11)
    return value & MASK32


class MT19937Clone:
    def __init__(self, outputs: List[int]):
        if len(outputs) != LEAKS_NEEDED:
            raise ValueError(f"need {LEAKS_NEEDED} outputs")
        self.mt = [untemper(value) for value in outputs]
        self.index = LEAKS_NEEDED

    def extract_number(self) -> int:
        if self.index >= LEAKS_NEEDED:
            self.twist()
        y = self.mt[self.index]
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        self.index += 1
        return y & MASK32

    def twist(self) -> None:
        for i in range(LEAKS_NEEDED):
            y = (self.mt[i] & 0x80000000) + (self.mt[(i + 1) % LEAKS_NEEDED] & 0x7FFFFFFF)
            self.mt[i] = self.mt[(i + 397) % LEAKS_NEEDED] ^ (y >> 1)
            if y & 1:
                self.mt[i] ^= 0x9908B0DF
        self.index = 0


def crt(residues: List[int], moduli: List[int]) -> Tuple[int, int]:
    modulus = math.prod(moduli)
    total = 0
    for residue, mod in zip(residues, moduli):
        partial = modulus // mod
        inverse = pow(partial, -1, mod)
        total += residue * partial * inverse
    return total % modulus, modulus


def iroot(n: int, k: int) -> int:
    low = 0
    high = 1
    while high**k <= n:
        high <<= 1
    while low + 1 < high:
        mid = (low + high) // 2
        if mid**k <= n:
            low = mid
        else:
            high = mid
    return low


def parse_last_int(pattern: str, text: str) -> int:
    matches = re.findall(pattern, text)
    if not matches:
        raise ValueError(f"pattern not found: {pattern!r}")
    return int(matches[-1])


def exploit(host: str, port: int) -> bytes:
    leaked: List[int] = []
    moduli: List[int] = []
    residues: List[int] = []

    with socket.create_connection((host, port)) as sock:
        banner = recv_until_prompt(sock)
        sys.stdout.write(banner.decode(errors="replace"))

        while len(leaked) < LEAKS_NEEDED:
            send_line(sock, "0")
            response = recv_until_prompt(sock)
            text = response.decode(errors="replace")
            if "Wrong." in text:
                leaked.append(parse_last_int(r"Wrong\. The number was (\d+)\.", text))
            elif "Correct." in text:
                leaked.append(0)
            else:
                raise RuntimeError("unexpected response while collecting leaks")
            sys.stdout.write(text)

        clone = MT19937Clone(leaked)

        while len(moduli) < E:
            guess = clone.extract_number()
            send_line(sock, str(guess))
            response = recv_until_prompt(sock)
            text = response.decode(errors="replace")
            sys.stdout.write(text)

            if "Wrong." in text:
                raise RuntimeError("prediction desynced")

            ns = re.findall(r"n = (\d+)", text)
            cs = re.findall(r"c = (\d+)", text)
            if ns and cs:
                moduli.append(int(ns[-1]))
                residues.append(int(cs[-1]))
                print(f"[+] collected sample {len(moduli)}/{E}")

        send_line(sock, "exit")

    combined, _ = crt(residues, moduli)
    message = iroot(combined, E)
    if pow(message, E) != combined:
        raise RuntimeError("failed to recover exact e-th root")
    return message.to_bytes((message.bit_length() + 7) // 8, "big")


def self_test() -> None:
    original = random.Random(0xC0FFEE)
    leaked = [original.getrandbits(32) for _ in range(LEAKS_NEEDED)]
    clone = MT19937Clone(leaked)
    for _ in range(100):
        if clone.extract_number() != original.getrandbits(32):
            raise RuntimeError("MT clone self-test failed")
    print("[+] self-test passed")


def main() -> None:
    if len(sys.argv) >= 2 and sys.argv[1] == "--self-test":
        self_test()
        return

    host = HOST
    port = PORT
    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        port = int(sys.argv[2])

    flag = exploit(host, port)
    print(f"[+] flag: {flag.decode(errors='replace')}")


if __name__ == "__main__":
    main()
