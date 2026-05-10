# cloud_security-learning_plan-rezkijabbarmulia

---

# Monitoring log

---

# CLI Cloudtrail Log

```
aws cloudtrail get-trail-status `
  --name rentdrive-trail
```

Cari:

```text id="jlwm5a"
IsLogging: true
```

---

# View recent events

Tanpa buka S3:

```
aws cloudtrail lookup-events --max-results 10
```

Ini sangat useful buat:

* audit
* forensic
* security monitoring

---

# Contoh hasil

Misalnya:

* login AWS
* create EC2
* change IAM policy

akan muncul di event history.

---

# Turn off logging

```
aws cloudtrail stop-logging `
  --name rentdrive-trail
```

Cek lagi:

```
aws cloudtrail get-trail-status `
  --name rentdrive-trail
```

Harus jadi:

```text id="jlwm9e"
IsLogging: false
```

---

# delete total trail

Kalau selesai belajar:

```
aws cloudtrail delete-trail `
  --name rentdrive-trail
```

Ini delete trail config-nya, tapi:

* file log di S3 tetap ada
* bucket tidak otomatis kehapus

---

# Cara hidupin lagi

Kalau trail masih ada:

```
aws cloudtrail start-logging `
  --name rentdrive-trail
```

---

# Real-world security workflow

Biasanya flow production:

AWS API Activity
→ AWS CloudTrail
→ S3 / CloudWatch Logs
→ Metric Filter
→ Alarm
→ SNS / SIEM / SOC alert

Jadi yang kamu setup ini sebenarnya fondasi detection engineering di cloud
