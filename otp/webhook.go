package otp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// DefaultToleranceSeconds adalah selisih waktu maksimum antara timestamp
// webhook dan waktu sekarang yang masih diterima.
const DefaultToleranceSeconds = 300

// Event adalah payload webhook status delivery.
type Event struct {
	Event             string            `json:"event"`
	TransactionID     string            `json:"transactionId"`
	ApplicationCode   string            `json:"applicationCode"`
	Status            string            `json:"status"`  // SENT, DELIVERED, FAILED
	Channel           string            `json:"channel"` // WHATSAPP, SMS
	MSISDNMasked      string            `json:"msisdnMasked"`
	AttemptNo         int               `json:"attemptNo"`
	OccurredAt        string            `json:"occurredAt"`
	ErrorCode         *string           `json:"errorCode"`
	ErrorMessage      map[string]string `json:"errorMessage"`
	ProviderErrorCode *string           `json:"providerErrorCode"`
	ProviderCode      string            `json:"providerCode"`
}

// Key adalah idempotency key untuk satu event.
//
// Delivery bersifat at-least-once — satu event bisa datang lebih dari sekali,
// dan urutannya tidak dijamin. Simpan key ini, lalu skip event yang key-nya
// sudah pernah diproses.
func (e Event) Key() string {
	return fmt.Sprintf("%s:%s:%d", e.TransactionID, e.Status, e.AttemptNo)
}

// VerifyWebhook memeriksa signature satu request webhook.
//
// rawBody WAJIB berupa RAW BODY, persis seperti yang diterima. JSON yang sudah
// di-parse lalu di-serialize ulang umumnya berbeda byte-nya, sehingga
// signature tidak akan pernah match.
func VerifyWebhook(secret, timestamp, signature string, rawBody []byte) bool {
	return verifyWebhookPada(secret, timestamp, signature, rawBody, time.Now(), DefaultToleranceSeconds)
}

// VerifyWebhookAt sama dengan VerifyWebhook, tetapi acuan waktu dan toleransinya
// ditentukan sendiri. Berguna untuk menulis test di sisi receiver.
func VerifyWebhookAt(secret, timestamp, signature string, rawBody []byte,
	sekarang time.Time, toleransiDetik int) bool {
	return verifyWebhookPada(secret, timestamp, signature, rawBody, sekarang, toleransiDetik)
}

func verifyWebhookPada(secret, timestamp, signature string, rawBody []byte,
	sekarang time.Time, toleransiDetik int) bool {

	if secret == "" || timestamp == "" || signature == "" {
		return false
	}
	detik, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	// Timestamp ikut masuk ke perhitungan signature, bukan sekadar dikirim.
	// Tanpa pengecekan umur, request lama yang direkam pihak lain bisa dikirim
	// ulang kapan saja dan tetap lolos — replay attack.
	if math.Abs(float64(sekarang.Unix()-detik)) > float64(toleransiDetik) {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(rawBody)
	diharap := hex.EncodeToString(mac.Sum(nil))

	diterima := strings.TrimPrefix(signature, "sha256=")
	// hmac.Equal adalah constant-time compare. Perbandingan string biasa
	// berhenti di karakter pertama yang beda, dan selisih waktunya bisa dipakai
	// menebak signature yang benar karakter demi karakter.
	return hmac.Equal([]byte(diharap), []byte(diterima))
}

// ParseWebhook memverifikasi signature lalu mem-parse satu request webhook.
// Mengembalikan *Error dengan Code WEBHOOK_SIGNATURE_INVALID bila signature-nya
// tidak sah, sudah kedaluwarsa, atau body-nya berubah.
func ParseWebhook(secret, timestamp, signature string, rawBody []byte) (*Event, error) {
	if !VerifyWebhook(secret, timestamp, signature, rawBody) {
		return nil, &Error{
			Code:       "WEBHOOK_SIGNATURE_INVALID",
			Message:    "signature webhook tidak sah, sudah kedaluwarsa, atau body-nya berubah",
			HTTPStatus: 401,
			Details:    map[string]any{},
		}
	}
	var e Event
	if err := json.Unmarshal(rawBody, &e); err != nil {
		return nil, fmt.Errorf("otp: payload webhook tidak dapat di-parse: %w", err)
	}
	return &e, nil
}
