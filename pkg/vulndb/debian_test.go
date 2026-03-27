package vulndb

import "testing"

func TestLoadDebianSecurityTrackerBytesReleaseScoped(t *testing.T) {
	content := []byte(`{
  "openssl": {
    "CVE-2026-0001": {
      "description": "OpenSSL vulnerability",
      "releases": {
        "bookworm": {
          "status": "resolved",
          "fixed_version": "3.0.18-1~deb12u2",
          "urgency": "high"
        },
        "bullseye": {
          "status": "open",
          "repositories": {
            "bullseye-security": "1.1.1w-0+deb11u5"
          },
          "urgency": "medium"
        }
      }
    }
  }
}`)

	bookworm, err := LoadDebianSecurityTrackerBytes(content, "bookworm")
	if err != nil {
		t.Fatalf("LoadDebianSecurityTrackerBytes returned error: %v", err)
	}
	if len(bookworm.Advisories) != 1 || bookworm.Advisories[0].AffectedVersions[0] != "<3.0.18-1~deb12u2" {
		t.Fatalf("unexpected bookworm advisories %+v", bookworm.Advisories)
	}

	bullseye, err := LoadDebianSecurityTrackerBytes(content, "bullseye")
	if err != nil {
		t.Fatalf("LoadDebianSecurityTrackerBytes returned error: %v", err)
	}
	if len(bullseye.Advisories) != 1 || bullseye.Advisories[0].AffectedVersions[0] != "=1.1.1w-0+deb11u5" {
		t.Fatalf("unexpected bullseye advisories %+v", bullseye.Advisories)
	}
}
