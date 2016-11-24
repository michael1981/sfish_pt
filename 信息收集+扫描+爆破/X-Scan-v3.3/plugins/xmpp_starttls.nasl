#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42089);
  script_version("$Revision: 1.1 $");

  script_name(english:"XMPP Service STARTTLS Command Support");
  script_summary(english:"Checks if service supports STARTTLS");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote instant messaging service supports encrypting traffic."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote XMPP (eXtensible Messaging and Presence Protocol) service\n",
      "supports the use of the 'STARTTLS' command to switch from a plaintext\n",
      "to an encrypted communications channel."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://en.wikipedia.org/wiki/STARTTLS"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://tools.ietf.org/html/rfc3920#section-5"
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
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencie("xmpp_server_detect.nasl");
  script_require_ports("Services/jabber", 5222, "Services/jabber_s2s", 5269);

  exit(0);
}


include("global_settings.inc");
include("x509_func.inc");


# Client-to-server.
req = string(
  '<?xml version="1.0"?>\n',
  "  <stream:stream\n",
  "    xmlns='jabber:client'\n",
  "    xmlns:stream='http://etherx.jabber.org/streams'\n",
  "    to='", get_host_name(), "'\n",
  "    version='1.0'>\n"
);

ports = get_kb_list("Services/jabber");
if (isnull(ports)) ports = make_list(5222);
foreach port (ports)
{
  if (!get_port_state(port)) continue;

  encaps = get_kb_item("Transports/TCP/"+port);
  if (encaps && encaps > ENCAPS_IP) continue;

  soc = open_sock_tcp(port);
  if (!soc) continue;

  # nb: this doesn't check for an older format as described 
  #     in <http://xmpp.org/extensions/xep-0035.html>, which
  #     was retracted in November 2003.
  send(socket:soc, data:req);
  res = recv_line(socket:soc, length:1024);
  if (
    !strlen(res) ||
    "jabber:client" >!< res ||
    "xmlns:stream=" >!< res ||
    "from=" >!< res ||
    "id=" >!< res
  )
  {
    close(soc);
    continue;
  }
  if (
    report_paranoia < 2 &&
    (
      "<stream:features>" >!< res ||
      "<starttls" >!< res
    )
  )
  {
    close(soc);
    continue;
  }

  req = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\n";
  send(socket:soc, data:req);
  res = recv_line(socket:soc, length:1024);
  if (
    strlen(res) &&
    "<proceed " >< res &&
    "xml:ns:xmpp-tls" >< res
  )
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
          "Here is the XMPP service's SSL certificate that Nessus was able to\n",
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
          "The remote XMPP service responded to the 'STARTTLS' command with a\n",
          "'proceed' element, suggesting that it supports that command. However,\n",
          "Nessus failed to negotiate a TLS connection or get the associated SSL\n",
          "certificate, perhaps because of a network connectivity problem or the\n",
          "service requires a peer certificate as part of the negotiation."
        );
      }
      if (COMMAND_LINE) display(report);
      else security_note(port:port, extra:report);
    }
    else security_note(port);

    set_kb_item(name:"xmpp/"+port+"/starttls", value:TRUE);
  }
  close(soc);
}

# Server-to-server.
req = string(
  '<?xml version="1.0"?>\n',
  "  <stream:stream\n",
  "    xmlns='jabber:server'\n",
  "    xmlns:stream='http://etherx.jabber.org/streams'\n",
  "    to='", get_host_name(), "'\n",
  "    version='1.0'>\n"
);

ports = get_kb_list("Services/jabber_s2s");
if (isnull(ports)) ports = make_list(5269);
foreach port (ports)
{
  if (!get_port_state(port)) continue;

  encaps = get_kb_item("Transports/TCP/"+port);
  if (encaps && encaps > ENCAPS_IP) continue;

  soc = open_sock_tcp(port);
  if (!soc) continue;

  send(socket:soc, data:req);
  res = recv_line(socket:soc, length:1024);
  if (
    !strlen(res) ||
    "jabber:server" >!< res ||
    "xmlns:stream=" >!< res ||
    "from=" >!< res ||
    "id=" >!< res
  )
  {
    close(soc);
    continue;
  }
  if (
    report_paranoia < 2 &&
    (
      "<stream:features>" >!< res ||
      "<starttls" >!< res
    )
  )
  {
    close(soc);
    continue;
  }

  req = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\n";
  send(socket:soc, data:req);
  res = recv_line(socket:soc, length:1024);
  if (
    strlen(res) &&
    "<proceed " >< res &&
    "xml:ns:xmpp-tls" >< res
  )
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
          "Here is the XMPP service's SSL certificate that Nessus was able to\n",
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
          "The remote XMPP service responded to the 'STARTTLS' command with a\n",
          "'proceed' element, suggesting that it supports that command. However,\n",
          "Nessus failed to negotiate a TLS connection or get the associated SSL\n",
          "certificate, perhaps because of a network connectivity problem or the\n",
          "service requires a peer certificate as part of the negotiation."
        );
      }
      if (COMMAND_LINE) display(report);
      else security_note(port:port, extra:report);
    }
    else security_note(port);

    set_kb_item(name:"xmpp/"+port+"/starttls", value:TRUE);
  }
  close(soc);
}
