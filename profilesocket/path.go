package profilesocket

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const EnvDir = "TAILMIX_SOCKET_DIR"

func DefaultDir() string {
	if dir := strings.TrimSpace(os.Getenv(EnvDir)); dir != "" {
		return dir
	}
	return "/var/run/tailmix"
}

func Path(dir, profileID string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", errors.New("profile socket directory is required")
	}
	if profileID == "" {
		return "", errors.New("profile ID is required")
	}
	sum := sha256.Sum256([]byte(profileID))
	return filepath.Join(dir, fmt.Sprintf("%s-%x.sock", socketLabel(profileID), sum[:6])), nil
}

func socketLabel(profileID string) string {
	var b strings.Builder
	lastHyphen := false
	for _, r := range strings.ToLower(profileID) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
			lastHyphen = r == '-'
		} else if b.Len() > 0 && !lastHyphen {
			b.WriteByte('-')
			lastHyphen = true
		}
		if b.Len() >= 24 {
			break
		}
	}
	label := strings.Trim(b.String(), "-_")
	if label == "" {
		return "profile"
	}
	return label
}
