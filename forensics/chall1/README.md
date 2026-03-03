# Dead Drop

## Summary

The challenge is a small packet capture named `deaddrop.pcap`. The traffic is plain HTTP, and the important event is a file upload to a "Secure Dead Drop" web page. The uploaded object is a PNG that already contains the flag.

Flag:

`MetaCTF{dr0p_d34d_g0rg30us_f0r3ns1c5_4b1li7y}`

## Files

- `deaddrop.pcap`
- exported HTTP objects:
  - `%2f`
  - `upload`
  - `upload(1)`
  - `flag.png`

## Solve

The first useful step is just to inspect the HTTP traffic:

```bash
tshark -r deaddrop.pcap -Y http -T fields \
  -e frame.number -e http.request.method -e http.request.uri -e http.response.code
```

This shows the whole flow:

- frame `4`: `GET /`
- frame `10`: server returns the page
- frame `24`: `POST /upload`
- frame `30`: server replies `Upload received.`

Exporting the HTTP objects in Wireshark or carving the file data from frame `24` gives the uploaded image. The request body already includes:

- filename: `flag.png`
- content type: `image/png`

If you inspect the exported image, the flag is visible directly:

```bash
file extracted/flag.png
```

Result:

- `PNG image data, 1900 x 150`

Opening the image reveals the flag banner:

`MetaCTF{dr0p_d34d_g0rg30us_f0r3ns1c5_4b1li7y}`

## Notes

This one is intentionally straightforward. No stego or protocol abuse was required beyond recovering the uploaded file from the PCAP.
