# SOCC (Secure One-way Communication Channel)
En sikker enveis kommunikasjonskanal
## Antagelser
- Jeg har antatt at en uvitende tredjepart betyr at tredjeparten ikke skal kunne lese meldingene som sendes mellom A og B
- Jeg har antatt at å avdekke et system refererer til at man ikke kan få tak i det systemet sin ip adresse
- At meldinger skal sendes uten menneskelig interaksjon har jeg tolket som at det skal være en form for automatisk sending av meldinger etter at systemene har startet

## Forutsetninger
- A og B har hvert sitt public-private key pair
- A har B sin public key
- B har A sin public key
- Portene som brukes i systemet er tilgjengelige
- IP adressene som brukes er konfigurert på forhånd
- At system B er startet når man starter system C
- At system C er startet når man startet system A
