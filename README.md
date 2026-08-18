# otp-sdk-go

Client Go untuk Platform One Time Password PT Transportasi Jakarta.

Membungkus REST API dan webhook status. Hanya memakai pustaka standar — tidak
ada dependensi pihak ketiga. Membutuhkan Go 1.21 atau lebih baru.

```bash
go get github.com/anaphalis-it/otp-sdk-go@v1.0.0
```

## Penggunaan

```go
import "github.com/anaphalis-it/otp-sdk-go/otp"

c, err := otp.NewClient(otp.Config{
    BaseURL:      os.Getenv("OTP_BASE_URL"),
    ClientID:     os.Getenv("OTP_CLIENT_ID"),
    ClientSecret: os.Getenv("OTP_CLIENT_SECRET"),
})
if err != nil {
    return err
}

// Menerbitkan dan mengirim OTP.
t, err := c.Request(ctx, otp.RequestOptions{
    MSISDN: "+628123456789", Purpose: "LOGIN", Language: "id",
})

// Memvalidasi kode yang dimasukkan pengguna.
if _, err := c.Verify(ctx, t.TransactionID, "418293", "LOGIN"); err != nil {
    var oe *otp.Error
    if errors.As(err, &oe) && oe.Code == "OTP_LOCKED" {
        detik, _ := oe.RetryAfterSeconds()
        log.Printf("terkunci, coba lagi dalam %d detik", detik)
    }
}
```

`NoDispatch: true` menerbitkan kode TANPA mengirim pesan — untuk pengujian
yang tidak boleh menimbulkan biaya.

## Method

| Kegunaan | Method |
| --- | --- |
| Menyusun klien | `otp.NewClient(otp.Config{...})` |
| Menerbitkan OTP | `c.Request(ctx, otp.RequestOptions{...})` |
| Memvalidasi | `c.Verify(ctx, id, code, purpose)` |
| Mengirim ulang | `c.Resend(ctx, id, channel)` |
| Membatalkan | `c.Cancel(ctx, id)` |
| Membaca status | `c.Status(ctx, id)` |

Access token tidak perlu dipanggil sendiri. Klien menerbitkannya pada
permintaan pertama dan menyegarkannya enam puluh detik sebelum berakhir; token
yang tepat berakhir di tengah perjalanan sebuah permintaan menghasilkan 401
yang tidak perlu. Permintaan yang datang bersamaan saat penyegaran berbagi
satu pengambilan, sehingga sepuluh permintaan serentak tidak menerbitkan
sepuluh token sekaligus.

## Penerima webhook

```go
func handler(w http.ResponseWriter, r *http.Request) {
    raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))

    e, err := otp.ParseWebhook(
        os.Getenv("OTP_WEBHOOK_SECRET"),
        r.Header.Get("X-Otp-Timestamp"),
        r.Header.Get("X-Otp-Signature"),
        raw,
    )
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }

    simpanBilaBaru(e.Key(), e)   // at-least-once: wajib idempotent
    w.WriteHeader(http.StatusNoContent)
}
```

Tiga hal yang wajib diperhatikan penerima webhook:

**Tanda tangan dihitung atas badan MENTAH.** JSON yang diurai lalu dirakit
ulang hampir pasti berbeda pada level byte, dan tanda tangannya tidak akan
pernah cocok. Baca raw body sebelum body parser bekerja.

**Pengiriman bersifat at-least-once dan urutannya tidak dijamin.** Pakai
`e.Key()` sebagai kunci idempotensi, dan perlakukan status sebagai tingkatan
yang tidak boleh mundur.

**Jawab cepat, proses di latar belakang.** Menahan response menyebabkan
panggilan timeout dan di-retry tanpa keperluan.

## Yang sengaja tidak dilakukan

**Pustaka ini tidak mengulang permintaan secara diam-diam.** Pengulangan yang
tidak terlihat pemanggil menyembunyikan kegagalan, dan pada endpoint yang
mengirim pesan berbayar ia menggandakan biaya. Galat dikembalikan apa adanya
berikut sisa waktu tunggunya lewat `RetryAfterSeconds()`, dan pemanggil yang
memutuskan apakah dan kapan mengulang.

**Pustaka ini tidak menangani failover.** Perpindahan WhatsApp ke SMS
dikerjakan platform, memakai kode yang sama pada transaksi yang sama.
Memanggil `Request` untuk kedua kalinya justru menerbitkan transaksi baru
dengan kode baru, dan pengguna menerima dua kode berbeda.

**Pustaka ini tidak menyimpan status transaksi.** Otoritasnya berada di
server, dan salinan di sisi klien hanya akan menjadi sumber kebenaran kedua
yang cepat atau lambat berbeda.

## Pengujian

```bash
go test ./...
```

Tujuh belas pengujian, seluruhnya terhadap HTTP server sungguhan alih-alih
transport tiruan — jaminan yang diuji bersifat perilaku antar permintaan, dan
tiruan akan meloloskan tepat kesalahan yang ingin ditangkap. Tidak ada
sambungan keluar. Lulus `go vet`, `gofmt`, dan `go test -race`.

---

© PT Anaphalis Inovasi Teknologi. Hak cipta dilindungi.
