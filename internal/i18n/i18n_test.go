package i18n

import "testing"

func TestResolve(t *testing.T) {
	tests := []struct {
		header string
		user   Lang
		want   Lang
	}{
		{"id", "", ID},
		{"id-ID,en;q=0.8", "", ID},
		{"in", "", ID},
		{"ID", "", ID},
		{"en-GB", ID, EN},
		{"ms-MY", ID, EN},
		{"", ID, ID},
		{"", EN, EN},
		{"", "", EN},
		{"  ", ID, ID},
	}
	for _, tt := range tests {
		if got := Resolve(tt.header, tt.user); got != tt.want {
			t.Errorf("Resolve(%q, %q) = %q, want %q", tt.header, tt.user, got, tt.want)
		}
	}
}

func TestTextIn(t *testing.T) {
	text := T("Sign in first", "Masuk dulu")
	if text.In(ID) != "Masuk dulu" || text.In(EN) != "Sign in first" {
		t.Errorf("In picked the wrong language: %+v", text)
	}
	if (Text{EN: "Only English"}).In(ID) != "Only English" {
		t.Error("a missing Bahasa string should fall back to English")
	}
}
