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

// ToleransiDetik adalah selisih waktu yang masih diterima pada webhook.
const ToleransiDetik = 300

// Event adalah muatan webhook status.
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

// Key adalah kunci idempotensi untuk satu peristiwa.
//
// Pengiriman bersifat at-least-once: satu peristiwa dapat tiba lebih dari
// sekali, dan urutannya tidak dijamin. Simpan kunci ini dan abaikan yang sudah
// pernah diproses.
func (e Event) Key() string {
	return fmt.Sprintf("%s:%s:%d", e.TransactionID, e.Status, e.AttemptNo)
}

// VerifyWebhook memeriksa tanda tangan satu panggilan webhook.
//
// rawBody WAJIB berupa badan mentah, persis seperti yang diterima. JSON yang
// diurai lalu dirakit ulang hampir pasti berbeda pada level byte, dan tanda
// tangannya tidak akan pernah cocok.
func VerifyWebhook(secret, timestamp, signature string, rawBody []byte) bool {
	return verifyWebhookPada(secret, timestamp, signature, rawBody, time.Now(), ToleransiDetik)
}

// VerifyWebhookDengan sama dengan VerifyWebhook, dengan toleransi dan acuan
// waktu yang dapat ditentukan. Dipakai pengujian.
func VerifyWebhookDengan(secret, timestamp, signature string, rawBody []byte,
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
	// Timestamp ikut ditandatangani, bukan sekadar dikirim: tanpa pemeriksaan
	// umur, panggilan sah yang direkam pihak lain dapat diputar ulang kapan pun.
	if math.Abs(float64(sekarang.Unix()-detik)) > float64(toleransiDetik) {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(rawBody)
	diharap := hex.EncodeToString(mac.Sum(nil))

	diterima := strings.TrimPrefix(signature, "sha256=")
	// hmac.Equal membandingkan dengan waktu tetap: perbandingan biasa
	// membocorkan tanda tangan yang benar sedikit demi sedikit lewat selisih
	// waktu tanggap.
	return hmac.Equal([]byte(diharap), []byte(diterima))
}

// ParseWebhook memverifikasi lalu mengurai satu panggilan webhook.
func ParseWebhook(secret, timestamp, signature string, rawBody []byte) (*Event, error) {
	if !VerifyWebhook(secret, timestamp, signature, rawBody) {
		return nil, &Error{
			Code:       "WEBHOOK_SIGNATURE_INVALID",
			Message:    "tanda tangan webhook tidak sah, kedaluwarsa, atau badannya sudah berubah",
			HTTPStatus: 401,
			Details:    map[string]any{},
		}
	}
	var e Event
	if err := json.Unmarshal(rawBody, &e); err != nil {
		return nil, fmt.Errorf("otp: muatan webhook tidak dapat diurai: %w", err)
	}
	return &e, nil
}
