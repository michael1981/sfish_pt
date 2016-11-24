#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31705);
  script_version("$Revision: 1.9 $");

  script_name(english:"SSL Anonymous Cipher Suites Supported");
  script_summary(english:"Reports anonymous SSL ciphers suites that are supported");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service supports the use of anonymous SSL ciphers." );
 script_set_attribute(attribute:"description", value:
"The remote host supports the use of anonymous SSL ciphers.  While this
enables an administrator to set up a service that encrypts traffic
without having to generate and configure SSL certificates, it offers
no way to verify the remote host's identity and renders the service
vulnerable to a man-in-the-middle attack." );
 script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/docs/apps/ciphers.html" );
 script_set_attribute(attribute:"solution", value:
"Reconfigure the affected application if possible to avoid use of weak
ciphers." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
 
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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


# Identify anonymous ciphers.
report = "";

foreach cipher (sort(supported_ciphers))
{
  if (strlen(ciphers_desc[cipher]))
  {
    cipher_desc = ciphers_desc[cipher];
    if (cipher_desc =~ "Au=None") 
    {
      i = 0;
      fields = split(cipher_desc, sep:"|", keep:0);
      foreach f (fields)
      {
        if (i == 0) max = 25;
        else if (i == 2) max = 12;
        else if (i == 4) max = 15;
        else max = 9;
	if ( strlen(f) > max ) max = strlen(f);
        if (i != 1)
          report += f + crap(data:" ", length:max-strlen(f)) + "  ";
        i++;
      }
      report += '\n';
    }
  }
}


# Generate report.
if (report)
{
  report = string(
    "\n",
    "The remote server supports the following anonymous SSL ciphers :\n",
    "\n",
    report,
    "\n",
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
