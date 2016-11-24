#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42088);
  script_version("$Revision: 1.1 $");

  script_name(english:"SMTP Service STARTTLS Command Support");
  script_summary(english:"Checks if service supports STARTTLS");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote mail service supports encrypting traffic."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote SMTP service supports the use of the 'STARTTLS' command to\n",
      "switch from a plaintext to an encrypted communications channel."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://en.wikipedia.org/wiki/STARTTLS"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://tools.ietf.org/html/rfc2487"
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
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencie("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/smtp", 25);

  exit(0);
}


include("global_settings.inc");
include("smtp_func.inc");
include("x509_func.inc");


port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(1, "Port "+port+" is closed.");

encaps = get_kb_item("Transports/TCP/"+port);
if (encaps && encaps > ENCAPS_IP) exit(0, "The SMTP server on port "+port+" always encrypts traffic.");


soc = smtp_open(port:port, helo:this_host());
if (!soc) exit(1, "Can't open socket on port "+port+".");

c = "STARTTLS";
send(socket:soc, data:string(c, '\r\n'));
s = smtp_recv_line(socket:soc);
if (strlen(s) < 4) 
{
  smtp_close(socket:soc);

  if (strlen(s)) errmsg = string("The SMTP server on port "+port+" sent an invalid response (", s, ").");
  else errmsg = string("Failed to receive a banner from the SMTP server on port", port, ".");
  exit(1, errmsg);
}
resp = substr(s, 0, 2);

if (resp && resp == "220")
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
        "Here is the SMTP service's SSL certificate that Nessus was able to\n",
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
        "The remote SMTP service responded to the 'STARTTLS' command with a\n",
        "'", resp, "' response code, suggesting that it supports that command. However,\n",
        "Nessus failed to negotiate a TLS connection or get the associated SSL\n",
        "certificate, perhaps because of a network connectivity problem or the\n",
        "service requires a peer certificate as part of the negotiation."
      );
    }
    if (COMMAND_LINE) display(report);
    else security_note(port:port, extra:report);
  }
  else security_note(port);

  set_kb_item(name:"smtp/"+port+"/starttls", value:TRUE);

  # nb: we haven't actually completed the SSL handshake so just bail.   
  close(soc);
  exit(0);
}
smtp_close(socket:soc);
