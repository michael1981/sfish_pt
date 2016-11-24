#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(21643);
  script_version("$Revision: 1.22 $");

  script_name(english:"SSL Cipher Suites Supported");
  script_summary(english:"Checks which SSL cipher suites are supported");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service encrypts communications using SSL." );
 script_set_attribute(attribute:"description", value:
"This script detects which SSL ciphers are supported by the remote
service for encrypting communications." );
 script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/docs/apps/ciphers.html" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );


script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
 
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_keys("Transport/SSL");

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");

set_byte_order(BYTE_ORDER_BIG_ENDIAN);


# Make sure a port is open and supports SSL.
if (COMMAND_LINE) port = 443;
else port = get_kb_item("Transport/SSL");
if (!port || !get_port_state(port)) exit(0);
encaps = get_kb_item("Transports/TCP/"+port);
if (encaps && (encaps < ENCAPS_SSLv2 || encaps > ENCAPS_TLSv1)) exit(0);


# Cipher strength categorizations.
#
# nb: make sure these agree with what's in ssl_weak_supported_ciphers.nasl
cat = 0;
NULL_STRENGTH = cat;
labels[cat] = "Null Ciphers (no encryption)";
LOW_STRENGTH = ++cat;
labels[cat] = "Low Strength Ciphers (< 56-bit key)";
MEDIUM_STRENGTH = ++cat;
labels[cat] = "Medium Strength Ciphers (>= 56-bit and < 112-bit key)";
HIGH_STRENGTH = ++cat;
labels[cat] = "High Strength Ciphers (>= 112-bit key)";
max_strength = ++cat;
labels[cat] = "Uncategorized Ciphers";


# Determine which ciphers are supported.
supported_ciphers = make_list();

foreach encaps (make_list(ENCAPS_SSLv2, ENCAPS_SSLv3, ENCAPS_TLSv1))
{
  # See if the server supports this type of SSL by sending a client hello
  # with every possible cipher spec.
  if (encaps == ENCAPS_SSLv2)      ssl_ver = raw_string(0x00, 0x02);
  else if (encaps == ENCAPS_SSLv3) ssl_ver = raw_string(0x03, 0x00);
  else if (encaps == ENCAPS_TLSv1) ssl_ver = raw_string(0x03, 0x01);

  cipherspec = "";
  foreach cipher (sort(keys(ciphers)))
  {
    if (
      (encaps == ENCAPS_SSLv2 && "SSL2_" >< cipher) ||
      (encaps == ENCAPS_SSLv3 && "SSL3_" >< cipher) ||
      (encaps == ENCAPS_TLSv1 && "TLS1_" >< cipher)
    ) cipherspec += ciphers[cipher];
  }

  helo = client_hello(
    version    : ssl_ver,
    cipherspec : cipherspec,
    v2hello    : FALSE
  );

  soc = open_sock_tcp(port, transport:ENCAPS_IP);
  if (soc)
  {
    send(socket:soc, data:helo);
    res = recv_ssl(socket:soc);
    close(soc);

    if (
      strlen(res) > 6 &&
      (
        (
          encaps == ENCAPS_SSLv2 &&
          substr(res, 5, 6) == ssl_ver &&          # version matches and...
          getbyte(blob:res, pos:2) == 4            #   a server hello
        ) ||
        (
          encaps == ENCAPS_SSLv3 &&
          substr(res, 1, 2) == ssl_ver &&          # version matches and...
          getbyte(blob:res, pos:0) == 22           #   a handshake
        ) ||
        (
          encaps == ENCAPS_TLSv1 &&
          substr(res, 1, 2) == ssl_ver &&          # version matches and...
          getbyte(blob:res, pos:0) == 22           #   a handshake
        )
      )
    )
    {
      # Iterate over each cipher.
      foreach cipher (sort(keys(ciphers)))
      {
        # If the cipher corresponds to the supported SSL type...
        if (
          (encaps == ENCAPS_SSLv2 && "SSL2_" >< cipher) ||
          (encaps == ENCAPS_SSLv3 && "SSL3_" >< cipher) ||
          (encaps == ENCAPS_TLSv1 && "TLS1_" >< cipher)
        )
        {
          helo = client_hello(
            version    : ssl_ver,
            cipherspec : ciphers[cipher],
            cspeclen   : mkword(strlen(ciphers[cipher])),
            v2hello    : FALSE
          );

          soc = open_sock_tcp(port, transport:ENCAPS_IP);
          if (soc)
          {
            send(socket:soc, data:helo);
            res = recv_ssl(socket:soc);
            if (
              strlen(res) > 10 &&
              (
                (
                  encaps == ENCAPS_SSLv2 &&
                  substr(res, 5, 6) == ssl_ver &&          # version matches and...
                  getbyte(blob:res, pos:2) == 4 &&         # a server hello and
                  getword(blob:res, pos:9) == 3            # cipher spec length == 3
                ) ||
                (
                  encaps == ENCAPS_SSLv3 &&
                  substr(res, 9, 10) == ssl_ver &&
                  getbyte(blob:res, pos:5) == 2
                ) ||
                (
                  encaps == ENCAPS_TLSv1 &&
                  substr(res, 1, 2) == ssl_ver &&
                  getbyte(blob:res, pos:0) == 22
                )
              )
            ) supported_ciphers = make_list(supported_ciphers, cipher);
            close(soc);
          }
        }
      }
    }
  }
}
if (max_index(supported_ciphers) == 0) exit(0);


# Classify supported ciphers by strength.
reports = NULL;

foreach cipher (sort(supported_ciphers))
{
  # Stash it in the KB.
  set_kb_item(name:"SSL/Ciphers/"+port, value:cipher);

  report = "";

  if (!strlen(ciphers_desc[cipher]))
  {
    cat = max_strength;
    reports[cat] += "    " + cipher + '\n';
  }
  else
  {
    cipher_desc = ciphers_desc[cipher];
    if (cipher_desc =~ "Enc=None") cat = NULL_STRENGTH;
    else if (cipher_desc =~ "Enc=AES") cat = HIGH_STRENGTH;
    else 
    {
      pat = ".*Enc=[^|]+\(([0-9]+)\).*";
      if (ereg(pattern:pat, string:cipher_desc))
      {
        bits = ereg_replace(pattern:pat, replace:"\1", string:cipher_desc);
        nbits = int(bits);
        if (nbits == 0) cat = NULL_STRENGTH;
        else if (nbits < 56) cat = LOW_STRENGTH;
        else if (nbits < 112) cat = MEDIUM_STRENGTH;
        else cat = HIGH_STRENGTH;
      }
      else cat = max_strength;
    }

    fields = split(cipher_desc, sep:"|", keep:0);
    if (!egrep(pattern:string("^ +", fields[1]), string:reports[cat]))
      reports[cat] += "    " + fields[1] + '\n';

    i = 0;
    foreach f (fields)
    {
      if (i == 0) max = 25;
      else if (i == 2) max = 12;
      else if (i == 4) max = 15;
      else max = 9;

      if ( max < strlen(f) ) max = strlen(f);
      if (i != 1)
        report += f + crap(data:" ", length:max-strlen(f)) + "  ";
      i++;
    }
    reports[cat] += "      " + report + '\n';
  }
}
if (isnull(reports)) exit(0);


# Generate report.
info = "";
foreach cat (sort(keys(reports)))
  info += "  " + labels[cat] + '\n'
               + reports[cat] + '\n';

if (info)
{
  report = string(
    "Here is the list of SSL ciphers supported by the remote server :\n",
    "\n",
    info,
    "The fields above are :\n",
    "\n",
    "  {OpenSSL ciphername}\n",
    "  Kx={key exchange}\n",
    "  Au={authentication}\n",
    "  Enc={symmetric encryption method}\n",
    "  Mac={message authentication code}\n",
    "  {export flag}\n"
  );
  security_note(port:port, extra:report);
}
