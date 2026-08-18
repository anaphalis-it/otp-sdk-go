// Package otp adalah SDK tipis untuk Platform OTP Transjakarta.
//
// Tipis dengan sengaja. Yang dibungkus hanya hal-hal yang, bila diserahkan ke
// setiap pemanggil, akan ditulis ulang berbeda-beda dan salah di tempat yang
// sama: pengelolaan access token, bentuk galat yang dapat dicabangkan, dan
// verifikasi tanda tangan webhook.
//
// Yang TIDAK dilakukan pustaka ini, juga dengan sengaja: ia tidak mengulang
// permintaan secara diam-diam. Pengulangan yang tidak terlihat pemanggil
// menyembunyikan kegagalan dan, pada endpoint yang mengirim pesan berbayar,
// menggandakan biaya. Galatnya dikembalikan apa adanya berikut RetryAfterSeconds.
//
// Hanya memakai pustaka standar.
package otp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const scopeBawaan = "otp:request otp:verify otp:read"

// Error adalah galat dari API. Code stabil dan aman dijadikan dasar percabangan.
type Error struct {
	Code       string
	Message    string
	HTTPStatus int
	RequestID  string
	Details    map[string]any
}

func (e *Error) Error() string {
	return fmt.Sprintf("otp: %s (%d): %s", e.Code, e.HTTPStatus, e.Message)
}

// RetryAfterSeconds mengembalikan sisa waktu tunggu, dan false bila galatnya
// tidak berbatas waktu.
//
// Diambil dari Details, bukan dihitung dari lockedUntil: menghitung selisih
// dari waktu absolut menuntut jam pemanggil sepakat dengan jam server, dan jam
// mesin dapat meleset.
func (e *Error) RetryAfterSeconds() (int, bool) {
	v, ada := e.Details["retryAfterSeconds"]
	if !ada {
		return 0, false
	}
	f, ok := v.(float64) // encoding/json membaca seluruh angka sebagai float64
	if !ok {
		return 0, false
	}
	return int(f), true
}

// Config menyusun Client.
type Config struct {
	BaseURL      string // misal https://otp.transjakarta.co.id
	ClientID     string
	ClientSecret string
	Scope        string        // kosong berarti scope bawaan
	Timeout      time.Duration // kosong berarti 10 detik
	HTTPClient   *http.Client  // kosong berarti klien baru dengan Timeout di atas
}

// Client memanggil Platform OTP.
type Client struct {
	baseURL string
	id      string
	secret  string
	scope   string
	hc      *http.Client

	mu      sync.Mutex
	token   string
	berlaku time.Time
}

// NewClient menyusun Client. Galat bila konfigurasinya kurang.
func NewClient(c Config) (*Client, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("otp: BaseURL wajib diisi")
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return nil, fmt.Errorf("otp: ClientID dan ClientSecret wajib diisi")
	}
	tenggat := c.Timeout
	if tenggat == 0 {
		tenggat = 10 * time.Second
	}
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: tenggat}
	}
	scope := c.Scope
	if scope == "" {
		scope = scopeBawaan
	}
	return &Client{
		baseURL: strings.TrimRight(c.BaseURL, "/"),
		id:      c.ClientID,
		secret:  c.ClientSecret,
		scope:   scope,
		hc:      hc,
	}, nil
}

// RequestOptions adalah masukan penerbitan OTP.
type RequestOptions struct {
	MSISDN            string
	Purpose           string
	Language          string // "id" atau "en"; kosong berarti bawaan aplikasi
	ChannelPreference string // "WHATSAPP" atau "SMS"
	// NoDispatch menerbitkan kode TANPA mengirim pesan. Untuk pengujian.
	NoDispatch     bool
	Metadata       map[string]string
	EndUserIP      string
	IdempotencyKey string
}

// RequestResult adalah jawaban penerbitan. Kode OTP tidak pernah disertakan.
type RequestResult struct {
	TransactionID     string `json:"transactionId"`
	Status            string `json:"status"`
	MaskedMSISDN      string `json:"maskedMsisdn"`
	ExpiresAt         string `json:"expiresAt"`
	RetriesRemaining  int    `json:"retriesRemaining"`
	ResendAvailableAt string `json:"resendAvailableAt"`
}

// VerifyResult adalah jawaban verifikasi yang berhasil.
type VerifyResult struct {
	TransactionID string `json:"transactionId"`
	Status        string `json:"status"`
	VerifiedAt    string `json:"verifiedAt"`
}

// CancelResult adalah jawaban pembatalan transaksi.
type CancelResult struct {
	TransactionID string `json:"transactionId"`
	Status        string `json:"status"`
}

// StatusResult adalah jawaban pembacaan status.
type StatusResult struct {
	TransactionID    string `json:"transactionId"`
	Status           string `json:"status"`
	Purpose          string `json:"purpose"`
	RetriesRemaining int    `json:"retriesRemaining"`
	ExpiresAt        string `json:"expiresAt"`
}

// Token mengembalikan access token yang masih berlaku, mengambil ulang bila perlu.
func (c *Client) Token(ctx context.Context) (string, error) {
	// Kunci dipegang selama pengambilan, bukan hanya saat membaca cache.
	// Tanpa itu, sepuluh goroutine yang bersamaan menemukan cache kosong akan
	// menerbitkan sepuluh token sekaligus.
	c.mu.Lock()
	defer c.mu.Unlock()

	// Disegarkan 60 detik SEBELUM kedaluwarsa. Token yang tepat habis di tengah
	// perjalanan permintaan menghasilkan 401 yang tidak perlu.
	if c.token != "" && time.Now().Before(c.berlaku.Add(-60*time.Second)) {
		return c.token, nil
	}

	badan := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     c.id,
		"client_secret": c.secret,
		"scope":         c.scope,
	}
	var jawab struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := c.kirim(ctx, http.MethodPost, "/v1/oauth/token", badan, nil, &jawab, true); err != nil {
		return "", err
	}
	umur := jawab.ExpiresIn
	if umur == 0 {
		umur = 900
	}
	c.token = jawab.AccessToken
	c.berlaku = time.Now().Add(time.Duration(umur) * time.Second)
	return c.token, nil
}

// Request menerbitkan dan mengirim OTP.
func (c *Client) Request(ctx context.Context, o RequestOptions) (*RequestResult, error) {
	if o.MSISDN == "" || o.Purpose == "" {
		return nil, fmt.Errorf("otp: MSISDN dan Purpose wajib diisi")
	}
	badan := map[string]any{"msisdn": o.MSISDN, "purpose": o.Purpose}
	if o.Language != "" {
		badan["language"] = o.Language
	}
	if o.ChannelPreference != "" {
		badan["channelPreference"] = o.ChannelPreference
	}
	if o.NoDispatch {
		badan["dispatch"] = false
	}
	if len(o.Metadata) > 0 {
		badan["metadata"] = o.Metadata
	}
	if o.EndUserIP != "" {
		badan["endUserIp"] = o.EndUserIP
	}
	var header map[string]string
	if o.IdempotencyKey != "" {
		header = map[string]string{"x-idempotency-key": o.IdempotencyKey}
	}
	var hasil RequestResult
	if err := c.kirim(ctx, http.MethodPost, "/v1/otp/request", badan, header, &hasil, false); err != nil {
		return nil, err
	}
	return &hasil, nil
}

// Verify memvalidasi kode yang dimasukkan pengguna.
func (c *Client) Verify(ctx context.Context, transactionID, code, purpose string) (*VerifyResult, error) {
	if transactionID == "" {
		return nil, fmt.Errorf("otp: transactionID wajib diisi")
	}
	badan := map[string]any{"transactionId": transactionID, "code": code, "purpose": purpose}
	var hasil VerifyResult
	if err := c.kirim(ctx, http.MethodPost, "/v1/otp/verify", badan, nil, &hasil, false); err != nil {
		return nil, err
	}
	return &hasil, nil
}

// Resend mengirim ulang KODE YANG SAMA. Masa berlakunya tidak diperpanjang.
func (c *Client) Resend(ctx context.Context, transactionID, channel string) error {
	if transactionID == "" {
		return fmt.Errorf("otp: transactionID wajib diisi")
	}
	badan := map[string]any{}
	if channel != "" {
		badan["channel"] = channel
	}
	return c.kirim(ctx, http.MethodPost,
		"/v1/otp/"+url.PathEscape(transactionID)+"/resend", badan, nil, nil, false)
}

// Cancel membatalkan transaksi sehingga kodenya tidak dapat lagi diverifikasi.
//
// Berguna saat pengguna meninggalkan alur verifikasi: tanpa pembatalan, kode
// yang ditinggalkan tetap berlaku sampai masa berlakunya habis.
func (c *Client) Cancel(ctx context.Context, transactionID string) (*CancelResult, error) {
	if transactionID == "" {
		return nil, fmt.Errorf("otp: transactionID wajib diisi")
	}
	var hasil CancelResult
	if err := c.kirim(ctx, http.MethodPost,
		"/v1/otp/"+url.PathEscape(transactionID)+"/cancel", nil, nil, &hasil, false); err != nil {
		return nil, err
	}
	return &hasil, nil
}

// Status membaca status transaksi. Kode OTP tidak pernah disertakan.
func (c *Client) Status(ctx context.Context, transactionID string) (*StatusResult, error) {
	if transactionID == "" {
		return nil, fmt.Errorf("otp: transactionID wajib diisi")
	}
	var hasil StatusResult
	if err := c.kirim(ctx, http.MethodGet,
		"/v1/otp/"+url.PathEscape(transactionID), nil, nil, &hasil, false); err != nil {
		return nil, err
	}
	return &hasil, nil
}

func (c *Client) kirim(ctx context.Context, metode, jalur string, badan any,
	header map[string]string, keluar any, tanpaToken bool) error {

	var isi io.Reader
	if metode != http.MethodGet {
		// Badan "{}" tetap dikirim meski kosong. Sebagian proxy menyisipkan
		// application/x-www-form-urlencoded pada POST tanpa badan, dan server
		// menolaknya sebelum handler berjalan.
		if badan == nil {
			badan = map[string]any{}
		}
		b, err := json.Marshal(badan)
		if err != nil {
			return fmt.Errorf("otp: gagal menyusun badan permintaan: %w", err)
		}
		isi = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, metode, c.baseURL+jalur, isi)
	if err != nil {
		return fmt.Errorf("otp: gagal menyusun permintaan: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if metode != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	if !tanpaToken {
		tok, err := c.Token(ctx)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	res, err := c.hc.Do(req)
	if err != nil {
		return &Error{Code: "NETWORK_ERROR", HTTPStatus: 0,
			Message: "tidak dapat menghubungi platform OTP: " + err.Error(),
			Details: map[string]any{}}
	}
	defer res.Body.Close()

	// Dibatasi supaya jawaban yang tidak terduga besarnya tidak menghabiskan memori.
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))

	if res.StatusCode < 200 || res.StatusCode > 299 {
		var bungkus struct {
			Error struct {
				Code      string         `json:"code"`
				Message   string         `json:"message"`
				RequestID string         `json:"requestId"`
				Details   map[string]any `json:"details"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &bungkus)
		kode := bungkus.Error.Code
		if kode == "" {
			kode = fmt.Sprintf("HTTP_%d", res.StatusCode)
		}
		pesan := bungkus.Error.Message
		if pesan == "" {
			pesan = fmt.Sprintf("platform OTP menjawab %d", res.StatusCode)
		}
		rincian := bungkus.Error.Details
		if rincian == nil {
			rincian = map[string]any{}
		}
		return &Error{Code: kode, Message: pesan, HTTPStatus: res.StatusCode,
			RequestID: bungkus.Error.RequestID, Details: rincian}
	}

	if keluar != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, keluar); err != nil {
			return fmt.Errorf("otp: jawaban tidak dapat diurai: %w", err)
		}
	}
	return nil
}
