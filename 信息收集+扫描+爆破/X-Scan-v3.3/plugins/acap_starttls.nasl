#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42084);
  script_version("$Revision: 1.1 $");

  script_name(english:"ACAP Service STARTTLS Command Support");
  script_summary(english:"Checks if service supports STARTTLS");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote service supports encrypting traffic."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote ACAP service supports the use of the 'STARTTLS' command to\n",
      "switch from a plaintext to an encrypted communications channel."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://en.wikipedia.org/wiki/STARTTLS"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://tools.ietf.org/html/rfc2595"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/10/09"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/acap", 674);

  exit(0);
}


include("global_settings.inc");
include("x509_func.inc");


port = get_kb_item("Services/acap");
if (!port) port = 674;
if (!get_port_state(port)) exit(1, "Port "+port+" is closed.");

encaps = get_kb_item("Transports/TCP/"+port);
if (encaps && encaps > ENCAPS_IP) exit(0, "The ACAP server on port "+port+" always encrypts traffic.");


soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");

s = recv_line(socket:soc, length:2048);
if (!strlen(s))
{
  close(soc);
  exit(1, "Failed to receive a banner from the ACAP server on port"+port+".");
}
tag = 0;


++tag;
c = string("nessus", string(tag), " STARTTLS");
send(socket:soc, data:string(c, '\r\n'));

resp = "";
while (s = recv_line(socket:soc, length:2048))
{
  s = chomp(s);
  match = eregmatch(pattern:string("^(\*|nessus", string(tag), ") (ALERT|BAD|BYE|NO|OK)"), string:s, icase:TRUE);
  if (!isnull(match))
  {
    resp = match[2];
    break;
  }
}
if (resp && "BYE" == toupper(resp))
{
  close(soc);
  exit(1, "The ACAP server on port"+port+" sent a 'BYE' message.");
}

if (resp && "OK" == toupper(resp))
{
  # nb: call get_server_cert() regardless of report_verbosity so
  #     the cert will be saved in the KB.
  cert = get_server_cert(
    port     : port, 
    socket   : soc, 
    encoding : "der", 
    encaps   : ENCAPS_TLSv1
  );
  if (report_verbosity > 0)
  {
    info = "";

    cert = parse_der_cert(cert:cert);
    if (!isnull(cert)) info = dump_certificate(cert:cert);

    if (info)
    {
      report = string(
        "\n",
        "Here is the ACAP server's SSL certificate that Nessus was able to\n",
        "collect after sending a 'STARTTLS' command :\n",
        "\n",
        crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
        info,
        crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
      );
    }
    else
    {
      report = string(
        "\n",
        "The remote ACAP service responded to the 'STARTTLS' command with an\n",
        "'", resp, "' response, suggesting that it supports that command.  However,\n",
        "Nessus failed to negotiate a TLS connection or get the associated SSL\n",
        "certificate, perhaps because of a network connectivity problem or the\n",
        "service requires a peer certificate as part of the negotiation."
      );
    }
    if (COMMAND_LINE) display(report);
    else security_note(port:port, extra:report);
  }
  else security_note(port);

  set_kb_item(name:"acap/"+port+"/starttls", value:TRUE);

  # nb: we haven't actually completed the SSL handshake so just bail.
  close(soc);
  exit(0);
}


# Be nice and logout.
++tag;
c = string("nessus", string(tag), " LOGOUT");
send(socket:soc, data:string(c, '\r\n'));

resp = "";
while (s = recv_line(socket:soc, length:2048))
{
  s = chomp(s);
  match = eregmatch(pattern:string("^(\*|nessus", string(tag), ") (ALERT|BAD|BYE|NO|OK)"), string:s, icase:TRUE);
  if (!isnull(match))
  {
    resp = match[2];
    break;
  }
}
close(soc);
