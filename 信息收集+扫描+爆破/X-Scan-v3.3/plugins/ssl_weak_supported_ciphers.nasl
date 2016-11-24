#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26928);
  script_version("$Revision: 1.8 $");

  script_name(english:"SSL Weak Cipher Suites Supported");
  script_summary(english:"Reports any weak SSL cipher suites that are supported");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service supports the use of weak SSL ciphers." );
 script_set_attribute(attribute:"description", value:
"The remote host supports the use of SSL ciphers that offer either weak
encryption or no encryption at all." );
 script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/docs/apps/ciphers.html" );
 script_set_attribute(attribute:"solution", value:
"Reconfigure the affected application if possible to avoid use of weak
ciphers." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
 
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("ssl_supported_ciphers.nasl");
  script_require_keys("Transport/SSL");
  exit(0);
}


include("ssl_funcs.inc");


# Make sure a port is open and supports SSL.
port = get_kb_item("Transport/SSL");
if (!port || !get_port_state(port)) exit(0);

supported_ciphers = get_kb_list("SSL/Ciphers/"+port);
if (isnull(supported_ciphers)) exit(0);
supported_ciphers = make_list(supported_ciphers);
if (max_index(supported_ciphers) == 0) exit(0);


# Cipher strength categorizations.
#
# nb: make sure these agree with what's in ssl_supported_ciphers.nasl
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


# Classify supported ciphers by strength.
reports = NULL;

foreach cipher (sort(supported_ciphers))
{
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
        report += f + crap(data:" ", length:2+max-strlen(f));
      i++;
    }
    reports[cat] += "      " + report + '\n';
  }
}
if (isnull(reports)) exit(0);


# Generate report.
info = "";
foreach cat (make_list(NULL_STRENGTH, LOW_STRENGTH))
  if (reports[cat]) 
    info += "  " + labels[cat] + '\n'
                 + reports[cat] + '\n';

if (info)
{
  report = string(
    "Here is the list of weak SSL ciphers supported by the remote server :\n",
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
  security_warning(port:port, extra:report);
}
