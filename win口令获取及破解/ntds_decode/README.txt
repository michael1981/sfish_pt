

NTDS LM/NTLM Hash Dumper v0.11b
http://www.insecurety.net/
May 2013

This application dumps LM and NTLM hashes from an Active Directory 
database. It will by default ignore machines, locked or disabled accounts.
Only runs on Windows at the moment and requires Administrator privileges.

The output format is the same as pwdump by Jeremy Allison.

  <username>:<rid>:<lm hash>:<ntlm hash>:<description>:<home directory>

  NTDS LM/NTLM hash dumper v0.11b
  Copyright (c) 2013 dietrich@insecurety.net

  ntds_decode -s <SYSTEM> -d <NTDS.dit> -m -i

    -s <FILE> : SYSTEM registry hive
    -d <FILE> : Active Directory database
    -m        : Machines (omitted by default)
    -i        : Inactive, Locked or Disabled accounts (omitted by default)

You can send any feedback/requests to : dietrich@insecurety.net

-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2.0.19 (MingW32)

mQENBFGGH48BCACywTdFFe90mmtyWvYySL2djqTpw/vBmJ2uNKtGCX6FDFihI+cm
6OXN1cn0vnsrsXcIwt253VCi9zu1nS9PgPBGDhGLVMVSJGqYjaIr80Bph12+bfQt
ofTcFLQtHVGBTK/Qvx6mejbJgz+JmMrPW02RldDKosiq56GAn9uFmlTcx+PjsDp7
uRTZZLVjUIr7bGNGm2MxZAwFORH9QHZm2oFoN058eI/OLnpqXzWHgklZIZvPULsZ
AKZ+/0fIKUBJMIcBCgBZbAy2qFhaITHV7G14Hu1Wlt0W/2li2l5CoQc60eidhWSR
Gsg3lcnJjk5ILM353/VfM+xh3QNZ6OKEEhExABEBAAG0ImRpZXRyaWNoIDxkaWV0
cmljaEBpbnNlY3VyZXR5Lm5ldD6JAT4EEwECACgFAlGGH48CGyMFCQHhM4AGCwkI
BwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEGnLvsCeYn1C2EwH/3Hyi/+4kkRzteso
my6VRmWK2CxmBppxPzNPGsU8szwnv673TzBya6BS9Za5UR/BWJd8AqCF4prCzbnd
e7WGheqsGvsKSHK+HATSaRZ/NhCvhBKajNiukfxilCZRbXDcj1gqFJ0u2ngfijmL
hro2WlCf3DqA/NNTonHJR9tSa1zMXgFb5LBWRSnEdo0144t0l+IMyvR8btQzJmnB
Al0El1o4VGVKz3U2oaLonuuRQErBnLW9BC91+V3IcEF/pDi9RuSCtAod39f/amM4
mGzjFEMAigjULgCF+pVMy22ul0FvJalbjNb5F+MOQNTaw7QIJlIjDXhQJjOYnc15
2K82Lae5AQ0EUYYfjwEIAO6p/dhd5Lm6ha/3+AMhLlsnx4/+hbeE5Fpcrf4u7B1j
RQmA2FQQpoUYjpXdFU0CwJZazkM6++yUCvww1Co7be9CWNKkmmdcOesBBa7++itU
C4r5PratZJzBT0c7t93x44c8Tux5k2bD3JVwQhsdZHT2zvCNgKf2Hzu3FZQ72dvJ
aqlwq8LIqiAi82N5htgushMa5k29Zsh52Hoodtpf2yw8TDHXLSeRZOK0Y4fqCNBG
jmLyFtKJz5iQu/e3Q9hr3Mys9Qcj8iQ5qsA6Uiiz9FEX0VQpUN24Ubmo7FZqKq2J
z5KerCbTJvrvIIKr7vRQt7hzeK3+GUVTt+vmIMGL0MMAEQEAAYkBJQQYAQIADwUC
UYYfjwIbDAUJAeEzgAAKCRBpy77AnmJ9QmT/B/9/lwNRs9/7nU9I529INHMiiVh9
c5w2ly8M1vyvg9MQpqJFOCl1+K7mzkf3mlAipUWJWV5ZSmmDE9UMIwUmG1Q6ELdc
iYP5K96q55nUIhn/lHFULaX1zzEDAK+N7xgwIiuI4wMxxmUmkDU6oIcvhqUARidH
lKqL7KMp57mZV/LKFqprZ1taQFpnErqGgzRGOEZF3YFILXKq0HB38tyu8eOpsMZQ
GFmxHmzatV+4AiyEoM2EmVZ8S81+pvssRO8omNuQvamIDHT0/cLfKe5jZz3rZGch
yJRIJoiKm415PYS6ra1rOvWr9k9qhHesz5w6uLckme2f03moThXa6njV84Ut
=Aeek
-----END PGP PUBLIC KEY BLOCK-----
