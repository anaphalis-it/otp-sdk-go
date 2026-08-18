package otp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Diuji terhadap HTTP server sungguhan (httptest), bukan transport tiruan.
// Yang paling perlu dibuktikan bersifat perilaku antar permintaan — token
// dipakai ulang, disegarkan sebelum kedaluwarsa, dan tidak diterbitkan
// berkali-kali saat banyak goroutine memanggil bersamaan.

type trace struct {
	mu    sync.Mutex
	token int32
	count map[string]int
	last  map[string]*http.Request
	body  map[string]string
}

func server(t *testing.T, tokenTTL int) (*httptest.Server, *trace) {
	t.Helper()
	j := &trace{last: map[string]*http.Request{}, body: map[string]string{},
		count: map[string]int{}}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		j.mu.Lock()
		j.last[r.URL.Path] = r
		j.body[r.URL.Path] = string(b)
		j.count[r.URL.Path]++
		j.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/oauth/token":
			n := atomic.AddInt32(&j.token, 1)
			fmt.Fprintf(w, `{"access_token":"tok-%d","expires_in":%d}`, n, tokenTTL)
		case r.URL.Path == "/v1/otp/request":
			var in map[string]any
			_ = json.Unmarshal(b, &in)
			if in["msisdn"] == "+628000000000" {
				w.WriteHeader(429)
				fmt.Fprint(w, `{"error":{"code":"OTP_RATE_LIMITED","message":"Terlalu banyak permintaan.",`+
					`"requestId":"req_x","details":{"scope":"msisdn","retryAfterSeconds":1800}}}`)
				return
			}
			status := "SENT"
			if in["dispatch"] == false {
				status = "CREATED"
			}
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"transactionId":"otp_UJI","status":"%s","maskedMsisdn":"+6281****6789",`+
				`"expiresAt":"2026-08-18T09:00:00.000Z","retriesRemaining":3,`+
				`"resendAvailableAt":"2026-08-18T08:58:00.000Z"}`, status)
		case r.URL.Path == "/v1/otp/verify":
			fmt.Fprint(w, `{"transactionId":"otp_UJI","status":"VERIFIED","verifiedAt":"2026-08-18T08:57:00.000Z"}`)
		case strings.HasSuffix(r.URL.Path, "/resend"):
			fmt.Fprint(w, `{"transactionId":"otp_UJI","status":"SENT","channel":"SMS",`+
				`"expiresAt":"2026-08-18T09:00:00.000Z","retriesRemaining":3,`+
				`"resendAvailableAt":"2026-08-18T08:58:00.000Z"}`)
		case strings.HasSuffix(r.URL.Path, "/cancel"):
			fmt.Fprint(w, `{"transactionId":"otp_UJI","status":"CANCELLED"}`)
		default:
			fmt.Fprint(w, `{"transactionId":"otp_UJI","status":"SENT","purpose":"LOGIN",`+
				`"retriesRemaining":3,"expiresAt":"2026-08-18T09:00:00.000Z"}`)
		}
	}))
	t.Cleanup(s.Close)
	return s, j
}

func newTestClient(t *testing.T, s *httptest.Server) *Client {
	t.Helper()
	c, err := NewClient(Config{BaseURL: s.URL, ClientID: "uji", ClientSecret: "rahasia"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestTokenIsReusedAcrossCalls(t *testing.T) {
	s, j := server(t, 900)
	c := newTestClient(t, s)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := c.Status(ctx, "otp_UJI"); err != nil {
			t.Fatalf("Status: %v", err)
		}
	}
	if n := atomic.LoadInt32(&j.token); n != 1 {
		t.Fatalf("token diambil %d kali, seharusnya 1", n)
	}
}

func TestTokenFetchedOnceUnderConcurrency(t *testing.T) {
	// Tanpa kunci yang dipegang selama pengambilan, sepuluh goroutine yang
	// menemukan cache kosong akan menerbitkan sepuluh token sekaligus.
	s, j := server(t, 900)
	c := newTestClient(t, s)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.Status(context.Background(), "otp_UJI")
		}()
	}
	wg.Wait()
	if n := atomic.LoadInt32(&j.token); n != 1 {
		t.Fatalf("token diambil %d kali, seharusnya 1", n)
	}
}

func TestTokenRefreshedBeforeExpiry(t *testing.T) {
	// Umur 30 detik berada di dalam ambang penyegaran 60 detik.
	s, j := server(t, 30)
	c := newTestClient(t, s)
	ctx := context.Background()
	_, _ = c.Status(ctx, "otp_UJI")
	_, _ = c.Status(ctx, "otp_UJI")
	if n := atomic.LoadInt32(&j.token); n != 2 {
		t.Fatalf("token diambil %d kali, seharusnya 2", n)
	}
}

func TestPostAlwaysSendsContentTypeAndBody(t *testing.T) {
	// Sebagian proxy menyisipkan application/x-www-form-urlencoded pada POST
	// tanpa badan, dan server menolaknya sebelum handler berjalan.
	s, j := server(t, 900)
	c := newTestClient(t, s)
	if _, err := c.Resend(context.Background(), "otp_UJI", ""); err != nil {
		t.Fatalf("Resend: %v", err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	r := j.last["/v1/otp/otp_UJI/resend"]
	if r == nil {
		t.Fatal("permintaan resend tidak diterima server")
	}
	if got := r.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if b := j.body["/v1/otp/otp_UJI/resend"]; b != "{}" {
		t.Fatalf("badan = %q, seharusnya {}", b)
	}
}

func TestResendReturnsResponseBody(t *testing.T) {
	s, _ := server(t, 900)
	c := newTestClient(t, s)

	// Nilai inilah yang dipakai aplikasi untuk menghitung mundur tombol
	// "kirim ulang". Sebelumnya badan response dibuang dan client tidak punya
	// cara mengetahuinya selain menebak.
	hasil, err := c.Resend(context.Background(), "otp_UJI", "SMS")
	if err != nil {
		t.Fatalf("Resend: %v", err)
	}
	if hasil.ResendAvailableAt != "2026-08-18T08:58:00.000Z" {
		t.Fatalf("ResendAvailableAt = %q", hasil.ResendAvailableAt)
	}
	if hasil.Channel != "SMS" {
		t.Fatalf("Channel = %q, ingin SMS", hasil.Channel)
	}
	if hasil.RetriesRemaining != 3 {
		t.Fatalf("RetriesRemaining = %d, ingin 3", hasil.RetriesRemaining)
	}
}

func TestFlowIDIsSent(t *testing.T) {
	s, j := server(t, 900)
	c := newTestClient(t, s)

	if _, err := c.Request(context.Background(), RequestOptions{
		MSISDN: "+628123456789", Purpose: "LOGIN", FlowID: "daftar-akun",
	}); err != nil {
		t.Fatalf("Request: %v", err)
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	var in map[string]any
	_ = json.Unmarshal([]byte(j.body["/v1/otp/request"]), &in)
	if in["flowId"] != "daftar-akun" {
		t.Fatalf("flowId = %v, ingin daftar-akun", in["flowId"])
	}
}

func TestCancelCallsCorrectEndpoint(t *testing.T) {
	s, j := server(t, 900)
	c := newTestClient(t, s)

	hasil, err := c.Cancel(context.Background(), "otp_UJI")
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if hasil.Status != "CANCELLED" {
		t.Fatalf("status = %q, ingin CANCELLED", hasil.Status)
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	r := j.last["/v1/otp/otp_UJI/cancel"]
	if r == nil {
		t.Fatal("permintaan cancel tidak diterima server")
	}
	if r.Method != http.MethodPost {
		t.Fatalf("metode = %q, ingin POST", r.Method)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	// Badan "{}" tetap dikirim: POST tanpa badan dijawab 415 oleh platform.
	if b := j.body["/v1/otp/otp_UJI/cancel"]; b != "{}" {
		t.Fatalf("badan = %q, ingin {}", b)
	}
}

func TestCancelWithoutTransactionIDSkipsNetwork(t *testing.T) {
	s, j := server(t, 900)
	c := newTestClient(t, s)

	if _, err := c.Cancel(context.Background(), ""); err == nil {
		t.Fatal("transactionID kosong seharusnya ditolak")
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.last) != 0 {
		t.Fatalf("tidak boleh ada permintaan terkirim, ada %d", len(j.last))
	}
}

func TestTransactionIDIsEscapedInPath(t *testing.T) {
	s, j := server(t, 900)
	c := newTestClient(t, s)

	// transactionID yang memuat garis miring tidak boleh mengubah bentuk path.
	_, _ = c.Cancel(context.Background(), "otp uji/aneh")

	j.mu.Lock()
	defer j.mu.Unlock()
	// Kuncinya adalah path yang SUDAH diurai server; bentuk mentahnya hanya
	// terbaca pada RequestURI.
	r := j.last["/v1/otp/otp uji/aneh/cancel"]
	if r == nil {
		t.Fatal("permintaan cancel tidak diterima server")
	}
	const ingin = "/v1/otp/otp%20uji%2Faneh/cancel"
	if r.RequestURI != ingin {
		t.Fatalf("RequestURI = %q, ingin %q", r.RequestURI, ingin)
	}
}

func TestOptionalFieldsAreOmitted(t *testing.T) {
	s, j := server(t, 900)
	c := newTestClient(t, s)
	if _, err := c.Request(context.Background(),
		RequestOptions{MSISDN: "+628123456789", Purpose: "LOGIN"}); err != nil {
		t.Fatalf("Request: %v", err)
	}
	var in map[string]any
	j.mu.Lock()
	_ = json.Unmarshal([]byte(j.body["/v1/otp/request"]), &in)
	j.mu.Unlock()
	if len(in) != 2 {
		t.Fatalf("badan memuat %d medan, seharusnya 2: %v", len(in), in)
	}
}

func TestIdempotencyKeyBecomesHeader(t *testing.T) {
	s, j := server(t, 900)
	c := newTestClient(t, s)
	_, _ = c.Request(context.Background(), RequestOptions{
		MSISDN: "+628123456789", Purpose: "LOGIN", IdempotencyKey: "kunci-1"})
	j.mu.Lock()
	defer j.mu.Unlock()
	if got := j.last["/v1/otp/request"].Header.Get("X-Idempotency-Key"); got != "kunci-1" {
		t.Fatalf("header idempotensi = %q", got)
	}
}

func TestErrorCarriesCodeAndDetails(t *testing.T) {
	s, _ := server(t, 900)
	c := newTestClient(t, s)
	_, err := c.Request(context.Background(),
		RequestOptions{MSISDN: "+628000000000", Purpose: "LOGIN"})
	if err == nil {
		t.Fatal("seharusnya galat")
	}
	e, ok := err.(*Error)
	if !ok {
		t.Fatalf("galat bertipe %T, seharusnya *otp.Error", err)
	}
	if e.Code != "OTP_RATE_LIMITED" || e.HTTPStatus != 429 || e.RequestID != "req_x" {
		t.Fatalf("galat = %+v", e)
	}
	seconds, ok := e.RetryAfterSeconds()
	if !ok || seconds != 1800 {
		t.Fatalf("RetryAfterSeconds = %d, %v", seconds, ok)
	}
}

func TestNoSilentRetry(t *testing.T) {
	// Pengulangan tersembunyi menggandakan biaya pada endpoint berbayar.
	s, j := server(t, 900)
	c := newTestClient(t, s)
	_, err := c.Request(context.Background(),
		RequestOptions{MSISDN: "+628000000000", Purpose: "LOGIN"})
	if err == nil {
		t.Fatal("seharusnya galat")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if n := j.count["/v1/otp/request"]; n != 1 {
		t.Fatalf("permintaan dikirim %d kali, seharusnya 1 — pustaka tidak boleh "+
			"mengulang secara diam-diam", n)
	}
}

func TestNetworkFailureBecomesOtpError(t *testing.T) {
	c, _ := NewClient(Config{BaseURL: "http://127.0.0.1:1", ClientID: "a",
		ClientSecret: "b", Timeout: 300 * time.Millisecond})
	_, err := c.Status(context.Background(), "otp_UJI")
	e, ok := err.(*Error)
	if !ok || e.Code != "NETWORK_ERROR" {
		t.Fatalf("galat = %v", err)
	}
}

// ─────────────────────────────────────────────────── webhook

const rahasia = "rahasia-bersama-yang-cukup-panjang"

var muatan = []byte(`{"event":"otp.status","transactionId":"otp_UJI","status":"DELIVERED",` +
	`"channel":"WHATSAPP","attemptNo":1}`)

func sign(ts string, isi []byte) string {
	m := hmac.New(sha256.New, []byte(rahasia))
	m.Write([]byte(ts))
	m.Write([]byte("."))
	m.Write(isi)
	return hex.EncodeToString(m.Sum(nil))
}

func nowUnix() string { return strconv.FormatInt(time.Now().Unix(), 10) }

func TestWebhookValidSignature(t *testing.T) {
	ts := nowUnix()
	if !VerifyWebhook(rahasia, ts, sign(ts, muatan), muatan) {
		t.Fatal("tanda tangan sah ditolak")
	}
	if !VerifyWebhook(rahasia, ts, "sha256="+sign(ts, muatan), muatan) {
		t.Fatal("awalan sha256= tidak diterima")
	}
}

func TestWebhookTamperedBodyRejected(t *testing.T) {
	ts := nowUnix()
	tt := sign(ts, muatan)
	diubah := []byte(`{"event":"otp.status","transactionId":"otp_UJI","status":"VERIFIED",` +
		`"channel":"WHATSAPP","attemptNo":1}`)
	if VerifyWebhook(rahasia, ts, tt, diubah) {
		t.Fatal("badan yang diubah diterima")
	}
}

func TestWebhookWrongSecretRejected(t *testing.T) {
	ts := nowUnix()
	if VerifyWebhook("rahasia-lain-yang-juga-panjang", ts, sign(ts, muatan), muatan) {
		t.Fatal("rahasia salah diterima")
	}
}

func TestWebhookStaleRequestRejected(t *testing.T) {
	lama := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	if VerifyWebhook(rahasia, lama, sign(lama, muatan), muatan) {
		t.Fatal("panggilan lama diterima — pemutaran ulang tidak tercegah")
	}
}

func TestParseWebhook(t *testing.T) {
	ts := nowUnix()
	e, err := ParseWebhook(rahasia, ts, sign(ts, muatan), muatan)
	if err != nil {
		t.Fatalf("ParseWebhook: %v", err)
	}
	if e.Status != "DELIVERED" || e.Key() != "otp_UJI:DELIVERED:1" {
		t.Fatalf("peristiwa = %+v, key = %s", e, e.Key())
	}
	if _, err := ParseWebhook(rahasia, ts, "palsu", muatan); err == nil {
		t.Fatal("tanda tangan palsu seharusnya ditolak")
	}
}
