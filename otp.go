// TOTP: https://en.wikipedia.org/wiki/One-time_password
//       https://datatracker.ietf.org/doc/html/rfc6238
// HOTP: https://en.wikipedia.org/wiki/HMAC-based_one-time_password
//       https://datatracker.ietf.org/doc/html/rfc4226
// The Google Authenticator: https://github.com/google/google-authenticator/wiki
package otputil

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// length defines the OTP code in character length.
	length = 6
	// period defines the TTL of a TOTP code in seconds.
	period = 30
	// previous - current - next
	window = 1
)

type OTP struct {
	// Issuer represents the service provider. It is you! e.g. your service,
	// your application, your organisation so on.
	Issuer string
	// Account represents the service user. It is the user! e.g. username, email
	// address so on.
	Account string
	// Secret is an arbitrary key value encoded in Base32 and belongs to the
	// service user.
	Secret string
	// Window is used for time (TOTP) and counter (HOTP) synchronization. Given
	// that the possible time and counter drifts between client and server, this
	// parameter helps overcome such issue. TOTP uses backward and forward time
	// window whereas HOTP uses look-ahead counter window that depends on the
	// Counter parameter.
	// Resynchronisation is an official recommended practise, however the
	// lower the better.
	// 0 = not recommended as synchronization is disabled
	//   TOTP: current time
	//   HOTP: current counter
	// 1 = recommended option
	//   TOTP: previous - current - next
	//   HOTP: current counter - next counter
	// 2 = being overcautious
	//   TOTP: previous,previous - current - next,next
	//   HOTP: current counter - next counter - next counter
	// * = Higher numbers may cause denial-of-service attacks.
	// REF: https://datatracker.ietf.org/doc/html/rfc6238#page-7
	// REF: https://datatracker.ietf.org/doc/html/rfc4226#page-11
	Window int
	// Counter is required for HOTP only and used for provisioning the code. Set
	// it to 0 if you with to use TOTP. Start from 1 for HOTP then fetch and use
	// the one in the persistent storage. The server counter is incremented only
	// after a successful code verification, however the counter on the code is
	// incremented every time a new code is requested by the user which causes
	// counters being out of sync. For that reason, time-synchronization should
	// be enabled.
	// REF: https://datatracker.ietf.org/doc/html/rfc4226#page-11
	Counter int
}

// CreateURI builds the authentication URI which is used to create a QR code.
// If the counter is set to 0, the algorithm is assumed to be TOTP, otherwise
// HOTP.
// REF: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func CreateTOTPURI(secret string, appName string, account string) string {
	algorithm := "totp"
	// counter := ""
	// if o.Counter != 0 {
	// 	algorithm = "hotp"
	// 	counter = fmt.Sprintf("&counter=%d", o.Counter)
	// }

	return strings.Join([]string{"otpauth://", algorithm, "/", appName, ":", account, "?secret=", secret, "&issuer=", appName, ""}, "")

	// return fmt.Sprintf("otpauth://%s/%s:%s?secret=%s&issuer=%s%s",
	// 	algorithm,
	// 	appName,
	// 	account,
	// 	secret,
	// 	appName,
	// 	counter,
	// )
}

// CreateHOTPCode creates a new HOTP with a specific counter. This method is
// ideal if you are planning to send manually created code via email, SMS etc.
// The user should not be present a QR code for this option otherwise there is
// a high posibility that the client and server counters will be out of sync,
// unless the user will be forced to rescan a newly generaed QR with up to date
// counter value.
// func (o *OTP) CreateHOTPCode(counter int) (string, error) {
// 	val, err := o.createCode(counter)
// 	if err != nil {
// 		return "", fmt.Errorf("create code: %w", err)
// 	}

// 	o.Counter = counter
// 	return val, nil
// }

// VerifyCode talks to an algorithm specific validator to verify the integrity
// of the code. If the counter is set to 0, the algorithm is assumed to be TOTP,
// otherwise HOTP.
// func (o *OTP) VerifyCode(code string) (bool, error) {
// 	if len(code) != length {
// 		return false, fmt.Errorf("invalid length")
// 	}

// 	if o.Counter != 0 {
// 		ok, err := o.verifyHOTP(code)
// 		if err != nil {
// 			return false, fmt.Errorf("verify HOTP: %w", err)
// 		}
// 		if !ok {
// 			return false, nil
// 		}
// 		return true, nil
// 	}

// 	ok, err := o.verifyTOTP(code)
// 	if err != nil {
// 		return false, fmt.Errorf("verify TOTP: %w", err)
// 	}
// 	if !ok {
// 		return false, nil
// 	}

// 	return true, nil
// }

// Depending on the given windows size, we handle clock resynchronisation. If
// the window size is set to 0, resynchronisation is disabled and we just use
// the current time. Otherwise, backward and forward window is taken into
// account as well.
func VerifyTOTP(secret string, code string) (bool, error) {
	curr := CurrInterval()
	back := curr
	forw := curr
	if window != 0 {
		back -= window
		forw += window
	}

	for i := back; i <= forw; i++ {
		val, err := CalcTOTPCode(secret, i)
		if err != nil {
			return false, fmt.Errorf("create code: %w", err)
		}
		if val == code {
			return true, nil
		}
	}

	return false, nil
}

func MustVerifyTOTP(secret string, code string) bool {
	b, err := VerifyTOTP(secret, code)
	if err != nil {
		panic(err)
	}

	return b
}

// // Depending on the given windows size, we handle counter resynchronisation. If
// // the window size is set to 0, resynchronisation is disabled and we just use
// // the current counter. Otherwise, look-ahead counter window is used. When the
// // look-ahead window is used, we calculate the next codes and determine if there
// // is a match by utilising counter resynchronisation.
// func (o *OTP) verifyHOTP(code string) (bool, error) {
// 	size := 0
// 	if o.Window != 0 {
// 		size = o.Window
// 	}

// 	for i := 0; i <= size; i++ {
// 		val, err := o.createCode(o.Counter + i)
// 		if err != nil {
// 			return false, fmt.Errorf("create code: %w", err)
// 		}
// 		if val == code {
// 			o.Counter += i + 1
// 			return true, nil
// 		}
// 	}

// 	o.Counter++
// 	return false, nil
// }

// createCode creates a new OTP code based on either a time or counter interval.
// The time is used for TOTP and the counter is used for HOTP algorithm.
func CalcTOTPCode(secret string, interval int64) (string, error) {
	sec, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("decode string: %w", err)
	}

	hash := hmac.New(sha1.New, sec)
	if err := binary.Write(hash, binary.BigEndian, interval); err != nil {
		return "", fmt.Errorf("binary write: %w", err)
	}
	sign := hash.Sum(nil)

	offset := sign[19] & 15
	trunc := binary.BigEndian.Uint32(sign[offset : offset+4])

	return strconv.FormatUint(uint64((trunc&0x7fffffff)%1000000), 10)[:length], nil
	// return fmt.Sprintf("%0*d", length, (trunc&0x7fffffff)%1000000), nil
}

func CurrInterval() int64 {
	return time.Now().UTC().Unix() / period
}
