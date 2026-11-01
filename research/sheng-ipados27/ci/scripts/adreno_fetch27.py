"""Adapt the pinned Adreno fetcher without editing the pinned source checkout.

Only the exact HTTPS GitHub API origin receives an environment credential.
The upstream SHA256/byte-count/Git-blob checks are preserved verbatim.
"""
import hashlib
import json
from pathlib import Path


SOURCE_SHA256 = "a854723a3a5530811aa628172b09096def25b6f319609b5f35dc29fe54b2fa15"
PINS_SHA256 = "770c85b715dbd325bf8813c72b5b4cde1e204faa79c14e8272fa1c4e93bb6434"
REQUEST_LINE = """        headers = {'User-Agent': 'sheng-offline-adreno-audit'}
        if TOKEN and urllib.parse.urlsplit(url).hostname in ('api.github.com', 'raw.githubusercontent.com'):
            headers['Authorization'] = f'Bearer {TOKEN}'
        request = urllib.request.Request(url, headers=headers)
"""
ROOT_LINE = "ROOT = Path(__file__).resolve().parents[1]\n"
PINS_LINE = "pins = json.loads((ROOT / 'scripts/data/adreno-inputs.json').read_text())\n"
AUTH_HELPER = '''def authenticated_request(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'sheng-offline-adreno-audit'})
    origin = urllib.parse.urlsplit(url)
    if origin.scheme == 'https' and origin.netloc.lower() == 'api.github.com':
        token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
        if token:
            if '\\r' in token or '\\n' in token:
                raise ValueError('GitHub credential contains invalid header characters')
            # urllib redirects copy headers, but not unredirected_hdrs.
            request.add_unredirected_header('Authorization', 'Bearer ' + token)
    return request


'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def transform(original, tree):
    require(sha(original) == SOURCE_SHA256, "Pinned Adreno fetcher source differs; review before adapting")
    source = original.decode("utf-8")
    for boundary in (ROOT_LINE, PINS_LINE, REQUEST_LINE, "import urllib.request\n"):
        require(source.count(boundary) == 1, "Pinned Adreno fetcher adaptation boundary differs")
    # Keep the exact fetch body, replacing only request construction. API blob
    # decoding, SHA256, byte count and Git blob SHA1 remain upstream code.
    source = source.replace(ROOT_LINE, AUTH_HELPER + "ROOT = Path(" + repr(str(Path(tree).resolve())) + ")\n")
    source = source.replace(PINS_LINE,
        "pins_path = ROOT / 'scripts/data/adreno-inputs.json'\n"
        "pins_bytes = pins_path.read_bytes()\n"
        "if hashlib.sha256(pins_bytes).hexdigest() != " + repr(PINS_SHA256) + ":\n"
        "    raise ValueError('Pinned Adreno input manifest differs; review before fetching')\n"
        "pins = json.loads(pins_bytes)\n")
    return source.replace(REQUEST_LINE, "        request = authenticated_request(url)\n").encode("utf-8")


def prepare(tree, output):
    """Return an independent local script for cloud.run(sys.executable, path).

    output is the result directory. The script/receipt contain no credential;
    the existing GH_TOKEN/GITHUB_TOKEN must be inherited at execution time.
    """
    tree, output = Path(tree).resolve(), Path(output)
    source = tree / "scripts/fetch-adreno-inputs.py"
    manifest = tree / "scripts/data/adreno-inputs.json"
    require(source.is_file() and manifest.is_file(), "Pinned Adreno fetcher/manifest is missing")
    require(sha(manifest.read_bytes()) == PINS_SHA256, "Pinned Adreno input manifest differs; review before adapting")
    adapted = transform(source.read_bytes(), tree)
    script = output / "fetch-adreno-inputs27-local.py"
    receipt = output / "adreno-fetch27-adapter.json"
    record = {"upstream_sha256": SOURCE_SHA256, "input_manifest_sha256": PINS_SHA256,
              "adapted_sha256": sha(adapted), "authenticated_origin": "https://api.github.com",
              "authorization_forwarded_on_redirect": False, "original_content_checks_preserved": True,
              "network_fetch_executed_at_prepare": False, "device_operations": False}
    receipt_bytes = (json.dumps(record, indent=2) + "\n").encode("utf-8")
    for target, data in ((script, adapted), (receipt, receipt_bytes)):
        require(not target.exists() or (target.is_file() and not target.is_symlink() and target.read_bytes() == data),
                "Preserve conflicting Adreno adapter output: " + target.name)
    output.mkdir(parents=True, exist_ok=True)
    for target, data in ((script, adapted), (receipt, receipt_bytes)):
        if not target.exists():
            with target.open("xb") as stream:
                stream.write(data)
    return script
