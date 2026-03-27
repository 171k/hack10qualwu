from pathlib import Path
import hashlib


CORE_START = 15
CORE_END = 90
CORE_LEN = CORE_END - CORE_START


def build_core_map() -> dict[str, bytes]:
    core_map: dict[str, bytes] = {}
    for i in range(256):
        for j in range(256):
            chunk = bytes([i, j])
            core = hashlib.sha512(chunk).hexdigest()[CORE_START:CORE_END]
            core_map[core] = chunk
    for i in range(256):
        chunk = bytes([i])
        core = hashlib.sha512(chunk).hexdigest()[CORE_START:CORE_END]
        core_map[core] = chunk
    return core_map


def find_matches(cipher_hex: str, core_map: dict[str, bytes]) -> list[tuple[int, bytes]]:
    matches: list[tuple[int, bytes]] = []
    for pos in range(len(cipher_hex) - CORE_LEN + 1):
        chunk = core_map.get(cipher_hex[pos : pos + CORE_LEN])
        if chunk is not None:
            matches.append((pos, chunk))
    return matches


def valid_start(core_pos: int) -> bool:
    return any(
        0 <= core_pos - pre <= 62 and (core_pos - pre) % 2 == 0
        for pre in range(15)
    )


def valid_gap(prev_core_pos: int, next_core_pos: int) -> bool:
    gap = next_core_pos - prev_core_pos - CORE_LEN
    for post in range(39):
        for pre in range(15):
            junk = gap - post - pre
            if 0 <= junk <= 62 and junk % 2 == 0:
                return True
    return False


def valid_end(core_pos: int, total_len: int) -> bool:
    trailing = total_len - (core_pos + CORE_LEN)
    return 0 <= trailing <= 38


def recover_flag(cipher_hex: str) -> str:
    core_map = build_core_map()
    matches = find_matches(cipher_hex, core_map)

    dp = [-10**9] * len(matches)
    prev = [-1] * len(matches)

    for i, (pos, chunk) in enumerate(matches):
        if valid_start(pos):
            dp[i] = len(chunk)
        for j in range(i):
            if dp[j] < 0:
                continue
            if not valid_gap(matches[j][0], pos):
                continue
            candidate = dp[j] + len(chunk)
            if candidate > dp[i]:
                dp[i] = candidate
                prev[i] = j

    end_idx = max(
        (i for i, (pos, _) in enumerate(matches) if valid_end(pos, len(cipher_hex))),
        key=lambda i: dp[i],
    )

    chunks: list[bytes] = []
    while end_idx != -1:
        chunks.append(matches[end_idx][1])
        end_idx = prev[end_idx]
    chunks.reverse()
    return b"".join(chunks).decode("ascii")


if __name__ == "__main__":
    cipher_hex = Path("output").read_bytes().hex()
    print(recover_flag(cipher_hex))
