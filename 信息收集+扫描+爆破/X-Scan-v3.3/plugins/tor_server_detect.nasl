#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26026);
  script_version("$Revision: 1.4 $");

  script_name(english:"Tor Server Detection");
  script_summary(english:"Checks SSL certificate for evidence of a Tor server");

 script_set_attribute(attribute:"synopsis", value:
"A Tor server is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service appears to be a Tor server.  Tor is a proxy service
designed to protect the anonymity of its users.  It can also be used
to support hidden services." );
 script_set_attribute(attribute:"see_also", value:"http://tor.eff.org/" );
 script_set_attribute(attribute:"solution", value:
"Make sure use of this program is in accordance with your corporate
security policy.  And limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 9001);

  exit(0);
}




include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
  port = get_unknown_svc(9001);
  if (!port) exit(0);
}
else port = 9001;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


# TOR servers use TLS1.
if (ENCAPS_TLSv1 == get_kb_item("Transports/TCP/"+port))
{
  # Grab the certificate and validity dates.
  cert = get_server_cert(port:port, encoding:"der");

  v = stridx(cert, raw_string(0x30, 0x1e, 0x17, 0x0d));
  if (v >= 0)
  {
    v += 4;
    valid_start = substr(cert, v, v+11);
    v += 15;
    valid_end = substr(cert, v, v+11);
  }

  # If...
  if (
    # the certificate's issuer has O=Tor in it and...
    stridx(cert, "U"+mkbyte(0x04)+mkbyte(0x0a)+mkbyte(0x13)+mkbyte(0x03)+"Tor1") >= 0 &&
    # it has " <identity>" in it and...
    " <identity>" >< cert &&
    # the dates look valid and...
    (valid_start =~ "^[0-9]{12}$" && valid_end =~ "^[0-9]{12}$") &&
    # the minutes and seconds are equal and...
    substr(valid_start, 8) == substr(valid_end, 8) &&
    # the certificate is valid only for two hours.
    2 == int(substr(valid_end, 0, 7)) - int(substr(valid_start, 0, 7))
  )
  {
    # Extract some interesting info for the report.
    info = "";
    # - router name.
    name = strstr(cert, "Tor1");
    name = name - strstr(name, " <identity>");
    i = stridx(name, "U"+mkbyte(0x04)+mkbyte(0x03)+mkbyte(0x14));
    if (i >= 0)
    {
      info += "  Router name : " + substr(name, i+5) + '\n';
    }

    # Register and report the service.
    register_service(port:port, proto:"tor");

    if (info)
      report = string(
        "Nessus was able to gather the following information from the remote\n",
        "Tor server :\n",
        "\n",
        info
      );
    else report = NULL;
    security_note(port:port, extra:report);
  }
}
