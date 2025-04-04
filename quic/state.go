package quic

var ownFingerprint string

func SetOwnFingerprint(fingerprint string) {
	ownFingerprint = fingerprint
}

func GetOwnFingerprint() string {
	return ownFingerprint
}
