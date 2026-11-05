package account

import (
	"testing"

	"github.com/renora/renora-api/internal/authn"
)

func TestDeviceLabel(t *testing.T) {
	tests := []struct {
		ua     string
		client authn.Client
		want   string
	}{
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36", authn.ClientWeb, "Chrome on Mac"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15", authn.ClientWeb, "Safari on Mac"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0", authn.ClientWeb, "Edge on Windows"},
		{"Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0 Mobile Safari/537.36", authn.ClientWeb, "Samsung Internet on Android"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0 Mobile/15E148 Safari/604.1", authn.ClientWeb, "Chrome on iPhone"},
		{"Renora/1.4.0 (iPhone; iOS 18.1)", authn.ClientMobile, "Renora app on iPhone"},
		{"okhttp/4.12.0", authn.ClientMobile, "Renora app"},
		{"", authn.ClientWeb, "Browser"},
	}
	for _, tt := range tests {
		if got := deviceLabel(tt.ua, tt.client); got != tt.want {
			t.Errorf("deviceLabel(%q) = %q, want %q", tt.ua, got, tt.want)
		}
	}
}

func TestMaskPhone(t *testing.T) {
	if got := MaskPhone("+6281218804471"); got != "+62 812 •••• 4471" {
		t.Errorf("MaskPhone = %q, want the contract's +62 812 •••• 4471", got)
	}
}

func TestInitials(t *testing.T) {
	for name, want := range map[string]string{"Bu Dewi": "BD", "pak joko santoso": "PJ", "Arif": "A", "": "", "  ": ""} {
		if got := Initials(name); got != want {
			t.Errorf("Initials(%q) = %q, want %q", name, got, want)
		}
	}
}
