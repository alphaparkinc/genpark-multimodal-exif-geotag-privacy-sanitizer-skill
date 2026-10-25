import sys, json
from client import MultimodalExifGeotagPrivacySanitizerClient
sys.stdout.reconfigure(encoding='utf-8')

def handle_mcp():
    sanitizer = MultimodalExifGeotagPrivacySanitizerClient()
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print(json.dumps({"status": "ready", "skill": "genpark-multimodal-exif-geotag-privacy-sanitizer-skill"}))
        return
    req = json.loads(sys.stdin.read() or "{}")
    exif = req.get("exif_tags", {})
    res = sanitizer.audit_exif_tags(exif)
    print(json.dumps(res, indent=2))

if __name__ == "__main__":
    handle_mcp()
