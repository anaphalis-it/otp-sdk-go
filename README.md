# otp-sdk-go

Client Go untuk Platform One Time Password PT Transportasi Jakarta.

Membungkus REST API dan webhook status delivery. Hanya memakai standard
library — tidak ada dependensi pihak ketiga. Membutuhkan Go 1.21 atau lebih
baru.

```bash
go get github.com/anaphalis-it/otp-sdk-go@v1.2.1
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

// Membuat kode OTP sekaligus mengirimkannya.
t, err := c.Request(ctx, otp.RequestOptions{
    MSISDN: "+628123456789", Purpose: "LOGIN", Language: "id",
})

// Memvalidasi kode yang diketik user.
if _, err := c.Verify(ctx, t.TransactionID, "418293", "LOGIN"); err != nil {
    var oe *otp.Error
    if errors.As(err, &oe) && oe.Code == "OTP_LOCKED" {
        detik, _ := oe.RetryAfterSeconds()
        log.Printf("terkunci, coba lagi dalam %d detik", detik)
    }
}
```

`NoDispatch: true` membuat kode TANPA mengirim pesan — untuk testing yang tidak
boleh menimbulkan biaya.

`Client` aman dipakai dari banyak goroutine. Buat satu instance saat startup
dan pakai ulang; membuat client baru per request ikut membuang connection pool
dan cache token-nya.

## Method

| Kegunaan | Method |
| --- | --- |
| Membuat client | `otp.NewClient(otp.Config{...})` |
| Membuat + mengirim OTP | `c.Request(ctx, otp.RequestOptions{...})` |
| Memvalidasi kode | `c.Verify(ctx, id, code, purpose)` |
| Mengirim ulang kode yang sama | `c.Resend(ctx, id, channel)` |
| Membatalkan transaksi | `c.Cancel(ctx, id)` |
| Membaca status | `c.Status(ctx, id)` |

Access token tidak perlu diurus sendiri. Client mengambilnya pada pemanggilan
pertama dan me-refresh 60 detik sebelum expired; token yang kebetulan expired
di tengah request menghasilkan 401 yang sebenarnya bisa dihindari. Beberapa
goroutine yang bersamaan menemukan cache kosong hanya memicu satu kali
pengambilan.

Bila token ternyata ditolak di tengah masa berlakunya — misalnya karena client
secret dirotasi — client mengambil token baru lalu mengulang request itu **satu
kali**. Pengulangan ini terbatas pada penolakan di lapisan authentication.
`OTP_CODE_MISMATCH` juga berstatus 401 dan sengaja TIDAK pernah diulang, sebab
setiap pengulangan akan memakan satu jatah percobaan verifikasi milik user.
`scope_missing` juga dikecualikan, karena token baru tidak akan memberi scope
yang memang tidak dimiliki credential-nya.

`Resend` mengirim ulang **kode yang sama** dan **tidak** memperpanjang masa
berlaku. `ResendAvailableAt` pada hasilnya menyebutkan kapan resend berikutnya
boleh dilakukan — pakai nilai itu untuk hitung mundur tombol "kirim ulang".

`Cancel` dipakai saat user meninggalkan flow verifikasi. Tanpa cancel, kode itu
tetap valid sampai expired.

## Error

Semua error dari platform bertipe `*otp.Error`. Field `Code` stabil dan aman
dipakai untuk branching logic; `Message` bisa berubah sewaktu-waktu.

```go
var oe *otp.Error
if errors.As(err, &oe) {
    switch oe.Code {
    case "OTP_RATE_LIMITED", "OTP_LOCKED", "OTP_RESEND_TOO_SOON":
        if detik, ada := oe.RetryAfterSeconds(); ada {
            // tunggu `detik` sebelum mencoba lagi
        }
    }
}
```

`RetryAfterSeconds` dibaca langsung dari response, bukan dihitung dari
timestamp absolut. Perhitungan semacam itu mengandalkan jam client sama dengan
jam server, padahal jam mesin bisa meleset.

## Webhook receiver

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

Tiga hal yang wajib diperhatikan receiver:

**Kirim RAW BODY, bukan hasil parse.** JSON yang sudah di-parse lalu
di-serialize ulang umumnya berbeda byte-nya, sehingga signature tidak akan
pernah match. Ini kesalahan integrasi yang paling sering terjadi.

**Endpoint wajib idempotent.** Delivery bersifat at-least-once dan urutannya
tidak dijamin. Pakai `e.Key()` — gabungan `transactionId`, `status`, dan
`attemptNo`.

Ketiganya diperlukan, bukan hanya `transactionId`. Failover **tidak** membuat
transaksi baru: percobaan pengganti memakai `transactionId` dan kode OTP yang
sama, hanya `attemptNo` dan `channel`-nya yang berubah. Satu transaksi karena
itu dapat menghasilkan beberapa event:

```
transactionId  status     channel   attemptNo
otp_4XGJ…      SENT       WHATSAPP  1
otp_4XGJ…      FAILED     WHATSAPP  1     ← tidak sampai
otp_4XGJ…      SENT       SMS       2     ← failover, kode SAMA
otp_4XGJ…      DELIVERED  SMS       2
```

Bila `transactionId` dipakai sendirian sebagai kunci, event SMS akan dianggap
duplikat event WhatsApp lalu dibuang — dan aplikasi tidak pernah tahu kodenya
akhirnya sampai lewat channel lain.

**Balas cepat, proses di background.** Kalau response ditahan sampai proses
selesai, request-nya timeout dan platform akan retry padahal event-nya sudah
diterima.

`ParseWebhook` sendiri sudah menghitung HMAC dari raw body, menolak timestamp
yang sudah lama untuk menahan replay attack, dan membandingkan signature dengan
constant-time compare.

## Yang sengaja tidak dilakukan

**SDK ini tidak melakukan retry diam-diam.** Retry yang tidak terlihat client
menyembunyikan kegagalan, dan pada endpoint yang mengirim pesan berbayar hal
itu menggandakan biaya. Error dikembalikan apa adanya lengkap dengan sisa waktu
tunggunya, dan client yang memutuskan apakah dan kapan melakukan retry.

Satu-satunya pengecualian adalah pengulangan setelah re-auth di atas, dan itu
aman justru karena request yang ditolak di lapisan authentication belum pernah
menyentuh logic bisnis — tidak ada pesan yang terkirim dan tidak ada biaya yang
timbul pada percobaan pertamanya.

**SDK ini tidak menangani failover.** Perpindahan WhatsApp ke SMS dikerjakan
platform, memakai kode yang sama pada transaksi yang sama. Memanggil `Request`
untuk kedua kalinya justru membuat transaksi baru dengan kode baru, dan user
menerima dua kode berbeda.

**SDK ini tidak menyimpan status transaksi.** Otoritasnya ada di server, dan
salinan di sisi client hanya akan menjadi sumber kebenaran kedua yang cepat
atau lambat berbeda.

## Testing

```bash
go test ./...
```

Dua puluh empat test, seluruhnya terhadap HTTP server lokal alih-alih transport
tiruan — jaminan yang diuji bersifat perilaku antar request, dan tiruan akan
meloloskan tepat kesalahan yang ingin ditangkap. Tidak ada koneksi keluar.
Lulus `go vet`, `gofmt`, dan `go test -race`.

## Riwayat versi

**v1.2.1** — Hanya dokumentasi. README menjelaskan bahwa failover memakai
`transactionId` yang sama, sehingga kunci idempotensi webhook wajib menyertakan
`attemptNo`. Tidak ada perubahan kode.

**v1.2.0** — Token yang ditolak di tengah masa berlakunya memicu pengambilan
token baru dan pengulangan request satu kali, terbatas pada penolakan di
lapisan authentication. Tidak ada perubahan pada signature method mana pun.

**v1.1.1** — Identifier internal dan nama test diseragamkan ke bahasa Inggris.
Tidak ada perubahan pada API publik maupun perilaku.

**v1.1.0**

- `Resend` mengembalikan `*ResendResult`, sebelumnya hanya `error`.
  `ResendAvailableAt` di dalamnya diperlukan untuk hitung mundur tombol kirim
  ulang. **Memutus kompatibilitas terhadap v1.0.0.**
- `RequestOptions.FlowID` ditambahkan.
- `ToleransiDetik` menjadi `DefaultToleranceSeconds`, `VerifyWebhookDengan`
  menjadi `VerifyWebhookAt`.

**v1.0.0** — rilis pertama.

---

© PT Anaphalis Inovasi Teknologi. Hak cipta dilindungi.
