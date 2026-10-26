package scanner

import (
	"testing"
)

func TestParseUnifiedDiffDetectsSecrets(t *testing.T) {
	diff := `diff --git a/app.js b/app.js
index 1234567..89abcdef 100644
--- a/app.js
+++ b/app.js
@@ -80,0 +81,2 @@
+var token = 'SECRET_TOKEN_f8ed84e8f41e4146403dd4a6bbcea5e418d23a9';
+var apiKey = 'AIzaSyD-9t4bK1234567890abcdef1234567890';
diff --git a/.env b/.env
new file mode 100644
--- /dev/null
+++ b/.env
@@ -0,0 +1 @@
+DB_PASS=secret
`

	findings := ParseUnifiedDiff(diff)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d: %+v", len(findings), findings)
	}

	wantRules := map[string]bool{
		"HARDCODED-SECRET-TOKEN": true,
		"GCP-API-KEY":            true,
		"PROHIBITED-ENV-FILE":    true,
	}
	for _, f := range findings {
		if !wantRules[f.RuleID] {
			t.Errorf("unexpected rule ID %q in finding %+v", f.RuleID, f)
		}
	}
}

func TestParseUnifiedDiffAllowsCleanCode(t *testing.T) {
	diff := `diff --git a/app.js b/app.js
index 1234567..89abcdef 100644
--- a/app.js
+++ b/app.js
@@ -42,1 +42,1 @@
-  secret: 'keyboard cat',
+  secret: secretManager.getRuntimeSessionSecret(),
`

	findings := ParseUnifiedDiff(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on remediated diff, got %d: %+v", len(findings), findings)
	}
}

func TestShannonEntropy(t *testing.T) {
	low := ShannonEntropy("aaaaaaaaaa")
	if low != 0 {
		t.Errorf("expected entropy 0 for identical chars, got %f", low)
	}
	high := ShannonEntropy("f8ed84e8f41e4146403dd4a6bbcea5e418d23a9")
	if high < 3.0 {
		t.Errorf("expected high entropy >= 3.0 for hex token, got %f", high)
	}
}
