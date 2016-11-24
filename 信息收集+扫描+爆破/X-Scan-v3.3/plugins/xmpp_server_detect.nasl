#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25342);
  script_version("$Revision: 1.4 $");

  script_name(english:"XMPP Server Detection");
  script_summary(english:"Tries to initiate an XMPP session");

 script_set_attribute(attribute:"synopsis", value:
"An instant messaging server is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service supports the Extensible Messaging and Presence
Protocol (XMPP), a protocol for real-time messaging." );
 script_set_attribute(attribute:"see_also", value:"http://www.xmpp.org/rfcs/rfc3920.html" );
 script_set_attribute(attribute:"solution", value:
"Make sure use of this service is in accordance with your corporate
security policy and limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 5222, 5223, 5269);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


req_c2s = string(
  '<?xml version="1.0"?>\n',
  "  <stream:stream to='", get_host_name(), "'\n",
  "    xmlns='jabber:client'\n",
  "    xmlns:stream='http://etherx.jabber.org/streams'\n",
  "    version='1.0'>\n"
);
req_s2s = string(
  '<?xml version="1.0"?>\n',
  "  <stream:stream\n",
  "    xmlns='jabber:server'\n",
  "    xmlns:stream='http://etherx.jabber.org/streams'\n",
  "    to='example.com'\n",
  "    version='1.0'>\n"
);


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) 
{
  ports = add_port_in_list(list:get_kb_list("Services/unknown"), port:5222);
}
else ports = make_list(5222);
ports = add_port_in_list(list:ports, port:5223);
ports = add_port_in_list(list:ports, port:5269);


# Loop through each port.
foreach port (ports)
{
  if (!known_service(port:port) && get_tcp_port_state(port))
  {
    # See if it supports connections from clients.
    soc = open_sock_tcp(port);
    if (soc)
    {
      # Start to initialize a session.
      send(socket:soc, data:req_c2s);
      res = recv_line(socket:soc, length:1024);
      close(soc);

      if (
        strlen(res) &&
        "jabber:client" >< res &&
        "xmlns:stream=" >< res &&
        "from=" >< res &&
        "id=" >< res
      )
      {
        register_service(port:port, ipproto:"tcp", proto:"jabber");

        report = string(
          "The remote XMPP service is used for client-to-server communications."
        );
        security_note(port:port, extra: report);
        continue;
      }
    }

    # See if it supports connections from servers.
    soc = open_sock_tcp(port);
    if (soc)
    {
      # Start to initialize a session.
      send(socket:soc, data:req_s2s);
      res = recv_line(socket:soc, length:1024);
      close(soc);

      if (
        strlen(res) &&
        "jabber:server" >< res &&
        'xmlns:stream=' >< res &&
        "from=" >< res &&
        "id=" >< res
      )
      {
        register_service(port:port, ipproto:"tcp", proto:"jabber_s2s");

        report = string(
          "The remote XMPP service is used for server-to-server communications."
        );
        security_note(port:port, extra: report);
      }
    }
  }
}
