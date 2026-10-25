from client import MultimodalExifGeotagPrivacySanitizerClient
import json, sys
sys.stdout.reconfigure(encoding='utf-8')

def main():
    sanitizer = MultimodalExifGeotagPrivacySanitizerClient()
    print("=== MULTIMODAL EXIF GEOTAG PRIVACY SANITIZER ===")
    
    # Simulated camera photo upload with raw GPS and hardware serial metadata
    exif_payload = {
        "CameraMake": "Sony",
        "CameraModel": "ILCE-7RM5",
        "BodySerialNumber": "SN-88492019A",
        "DateTimeOriginal": "2026-10-24 14:22:15",
        "GPSLatitude": (37, 46, 29.8),
        "GPSLatitudeRef": "N",
        "GPSLongitude": (122, 25, 9.5),
        "GPSLongitudeRef": "W"
    }
    
    res = sanitizer.audit_exif_tags(exif_payload)
    print()
    print(f"Privacy Risk Level: {res['privacy_risk_level']}")
    print(f"Extracted Coordinates: {res['extracted_gps_coordinates']}")
    print(f"Detected Leaks ({res['detected_leaks_count']}):")
    for leak in res['privacy_leaks']:
        print(f"  - [{leak['severity']}] {leak['category']}: {leak['data']}")
    print()
    print(f"Sanitization Result: {res['sanitized_file_guarantee']}")

if __name__ == "__main__":
    main()
