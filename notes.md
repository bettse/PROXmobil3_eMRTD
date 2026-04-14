# Notes

print mrz as qr code`echo $MRZ | qrencode -o - -t PNG | lp -d EVOLIS_Primacy`

- wiki about PROXmobil3: https://wiki.pm3.dev/start
- passy, my passport reader, source code: https://github.com/bettse/passy
- BAC support, not PACE
- stamper app for the same device ../stamper
- read MRZ from qr code using barcode reader
