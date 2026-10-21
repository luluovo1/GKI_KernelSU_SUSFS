#!/usr/bin/env python3
"""提取 APK v2 签名证书与包名，供内核编译时对齐管理器身份。

用法: apk_cert.py <apk>
输出: "<证书DER长度> <证书sha256> <包名>"

内核侧 (kernel/Kbuild) 用 KSU_EXPECTED_SIZE / KSU_EXPECTED_HASH 校验管理器
APK 的 v2 签名证书，用 KSU_PACKAGE_NAME 在 packages.list 里找管理器。
这三个值必须与用户实际安装的 APK 一致，否则内核认不出管理器。
"""

import hashlib
import struct
import sys
import zipfile


def certificate(apk_path):
    with open(apk_path, "rb") as fp:
        data = fp.read()

    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise SystemExit("not a zip/apk: no EOCD")

    cd_offset = struct.unpack("<I", data[eocd + 16:eocd + 20])[0]
    tail = cd_offset - 16
    if data[tail:tail + 16] != b"APK Sig Block 42":
        raise SystemExit("no APK signing block")

    block_size = struct.unpack("<Q", data[tail - 8:tail])[0]
    pos = cd_offset - block_size - 8 + 8
    end = cd_offset - 16

    while pos < end:
        length = struct.unpack("<Q", data[pos:pos + 8])[0]
        pair_id = struct.unpack("<I", data[pos + 8:pos + 12])[0]
        value = data[pos + 12:pos + 8 + length]
        if pair_id == 0x7109871A:  # APK Signature Scheme v2
            return parse_v2(value)
        pos += 8 + length

    raise SystemExit("no v2 signature")


def parse_v2(value):
    cursor = 4                       # signers sequence length
    cursor += 4                      # first signer length
    signed_len = struct.unpack("<I", value[cursor:cursor + 4])[0]
    cursor += 4
    signed = value[cursor:cursor + signed_len]

    offset = 0
    digest_len = struct.unpack("<I", signed[offset:offset + 4])[0]
    offset += 4 + digest_len
    offset += 4                      # certificates sequence length
    cert_len = struct.unpack("<I", signed[offset:offset + 4])[0]
    offset += 4
    return signed[offset:offset + cert_len]


def string_pool(data, offset):
    _, header_size, _ = struct.unpack("<HHI", data[offset:offset + 8])
    count, _, flags, strings_start, _ = struct.unpack("<IIIII", data[offset + 8:offset + 28])
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack(f"<{count}I", data[offset + 28:offset + 28 + 4 * count])
    base = offset + strings_start
    strings = []

    for entry in offsets:
        pos = base + entry
        if utf8:
            # 两个 varint 长度：UTF-16 码元数、UTF-8 字节数
            pos += 2 if data[pos] & 0x80 else 1
            length = data[pos]
            pos += 1
            if length & 0x80:
                length = ((length & 0x7F) << 8) | data[pos]
                pos += 1
            strings.append(data[pos:pos + length].decode("utf-8", "replace"))
        else:
            length = struct.unpack("<H", data[pos:pos + 2])[0]
            pos += 2
            if length & 0x8000:
                length = ((length & 0x7FFF) << 16) | struct.unpack("<H", data[pos:pos + 2])[0]
                pos += 2
            strings.append(data[pos:pos + length * 2].decode("utf-16-le", "replace"))

    return strings, header_size


def manifest_package(manifest):
    strings, _ = string_pool(manifest, 8)
    offset = 8
    while offset + 8 <= len(manifest):
        chunk_type, header_size, chunk_size = struct.unpack("<HHI", manifest[offset:offset + 8])
        if chunk_size < 8:
            break
        if chunk_type == 0x0102:  # START_ELEMENT
            body = offset + header_size
            _, name_idx, attr_start, attr_size, attr_count, _, _, _ = struct.unpack(
                "<IIHHHHHH", manifest[body:body + 20]
            )
            if strings[name_idx] == "manifest":
                attr = body + attr_start
                for _ in range(attr_count):
                    _, attr_name, raw, _, _, data_type, data_value = struct.unpack(
                        "<IIIHBBI", manifest[attr:attr + 20]
                    )
                    if strings[attr_name] == "package":
                        idx = raw if raw != 0xFFFFFFFF else data_value
                        if idx < len(strings):
                            return strings[idx]
                    attr += attr_size
        offset += chunk_size
    return None


def package_name(apk_path, fallback):
    try:
        with zipfile.ZipFile(apk_path) as apk:
            manifest = apk.read("AndroidManifest.xml")
    except KeyError:
        return fallback
    try:
        return manifest_package(manifest) or fallback
    except (struct.error, IndexError):
        return fallback


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: apk_cert.py <apk>")
    apk_path = sys.argv[1]
    der = certificate(apk_path)
    digest = hashlib.sha256(der).hexdigest()

    fallback = re.split(r"[_]", apk_path.rsplit("/", 1)[-1])[0]
    pkg = package_name(apk_path, fallback)
    print(f"0x{len(der):x} {digest} {pkg}")


if __name__ == "__main__":
    main()
