"""Read only ZIP metadata and BuildManifest from the pinned Apple iPadOS IPSW."""
import hashlib
import io
import json
from pathlib import Path
import plistlib
import urllib.request
import zipfile

OUT = Path(__file__).resolve().parent
URL = "https://updates.cdn-apple.com/2026FallFCS/6074e110-d48d-40c2-b0e8-b611520941a3/iPad17,1,iPad17,2,iPad17,3,iPad17,4_27.0.1_24A446_Restore.ipsw"


class BoundedRemote(io.RawIOBase):
    def __init__(self):
        with urllib.request.urlopen(urllib.request.Request(URL, method="HEAD"), timeout=60) as response:
            self.size = int(response.headers["Content-Length"])
            self.http = {"url": response.url, "status": response.status, "headers": dict(response.headers)}
        self.pos = 0
        self.cache = {}
        self.transferred = 0
        self.requests = []

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=0):
        self.pos = {0: offset, 1: self.pos + offset, 2: self.size + offset}[whence]
        return self.pos

    def readinto(self, buffer):
        want = min(len(buffer), self.size - self.pos)
        copied = 0
        while copied < want:
            index, inside = divmod(self.pos, 1 << 20)
            if index not in self.cache:
                start = index << 20
                end = min(start + (1 << 20), self.size) - 1
                expected = end - start + 1
                request = urllib.request.Request(URL, headers={"Range": f"bytes={start}-{end}"})
                with urllib.request.urlopen(request, timeout=90) as response:
                    if response.status != 206 or response.headers.get("Content-Range") != f"bytes {start}-{end}/{self.size}":
                        raise ValueError("Apple CDN did not honor the exact byte range")
                    chunk = response.read(expected + 1)
                if len(chunk) != expected:
                    raise ValueError("Unexpected range length")
                self.cache[index] = chunk
                self.transferred += len(chunk)
                self.requests.append({"start": start, "end": end})
            chunk = self.cache[index][inside:inside + want - copied]
            buffer[copied:copied + len(chunk)] = chunk
            copied += len(chunk)
            self.pos += len(chunk)
        return copied


def main():
    stream = BoundedRemote()
    with zipfile.ZipFile(stream) as archive:
        manifest_bytes = archive.read("BuildManifest.plist")
        manifest = plistlib.loads(manifest_bytes)
        (OUT / "BuildManifest-24A446.plist").write_bytes(manifest_bytes)
        if manifest["ProductVersion"] != "27.0.1" or manifest["ProductBuildVersion"] != "24A446" or "iPad17,3" not in manifest["SupportedProductTypes"]:
            raise ValueError("Actual Apple IPSW differs from the official pinned profile")
        candidates = [item for item in manifest["BuildIdentities"] if item["Info"]["DeviceClass"] == "j820ap" and item["Info"]["RestoreBehavior"] == "Erase" and item["Info"].get("Variant") == "Customer Erase Install (IPSW)" and int(item["ApChipID"], 16) == 33090 and int(item["ApBoardID"], 16) == 12]
        if len(candidates) != 1:
            print(json.dumps({"matches": len(candidates), "identities": [{"Info": item["Info"], "ApChipID": item["ApChipID"], "ApBoardID": item["ApBoardID"]} for item in manifest["BuildIdentities"]]}, default=str, indent=2))
            raise ValueError("Expected exactly one j820ap Erase identity")
        identity = candidates[0]
        members = {}
        for name in ("KernelCache", "DeviceTree", "StaticTrustCache", "Cryptex1,SystemTrustCache", "OS", "Cryptex1,SystemOS", "Cryptex1,AppOS", "Cryptex1,AppTrustCache"):
            entry = identity["Manifest"].get(name)
            if not entry:
                members[name] = None
                continue
            member = entry["Info"]["Path"]
            info = archive.getinfo(member)
            members[name] = {"path": member, "bytes": info.file_size, "compressed_bytes": info.compress_size, "zip_crc32": f"{info.CRC:08x}"}
        listing = [{"path": item.filename, "bytes": item.file_size, "compressed_bytes": item.compress_size} for item in archive.infolist()]
    report = {"source": "Apple CDN URL pinned by UniXNU official iPadOS27 profile", "url": URL, "http": stream.http, "ipsw_bytes": stream.size, "bytes_downloaded_for_metadata": stream.transferred, "range_requests": stream.requests, "version": manifest["ProductVersion"], "build": manifest["ProductBuildVersion"], "products": manifest["SupportedProductTypes"], "identity": {"DeviceClass": identity["Info"]["DeviceClass"], "RestoreBehavior": identity["Info"]["RestoreBehavior"], "Variant": identity["Info"]["Variant"], "ContentEncoding": identity["Info"].get("ContentEncoding"), "ApChipID": identity["ApChipID"], "ApBoardID": identity["ApBoardID"]}, "BuildManifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(), "components": members}
    (OUT / "BuildManifest-24A446.plist").write_bytes(manifest_bytes)
    (OUT / "ipsw-24A446-metadata.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (OUT / "ipsw-24A446-members.json").write_text(json.dumps(listing, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
