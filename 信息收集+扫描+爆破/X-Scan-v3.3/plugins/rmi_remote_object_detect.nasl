#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22363);
  script_version("$Revision: 1.7 $");

  script_name(english:"RMI Remote Object Detection");
  script_summary(english:"Detects RMI remote objects");

 script_set_attribute(attribute:"synopsis", value:
"A Java service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"One or more Java RMI remote objects are listening on the remote host. 
They may be used by Java applications to invoke methods on those
objects remotely." );
 script_set_attribute(attribute:"see_also", value:"http://java.sun.com/products/jndi/tutorial/objects/storing/remote.html" );
 script_set_attribute(attribute:"see_also", value:"http://java.sun.com/j2se/1.5.0/docs/guide/rmi/spec/rmiTOC.html" );
 script_set_attribute(attribute:"see_also", value:"http://java.sun.com/j2se/1.5.0/docs/guide/rmi/spec/rmi-protocol3.html" );
 script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("rmiregistry_detect.nasl");
  script_require_ports("Services/unknown");
  script_require_keys("Settings/ThoroughTests");
  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if (
  !thorough_tests || 
  get_kb_item("global_settings/disable_service_discovery")
) exit(0);

port = get_unknown_svc(0);             # nb: no default
if (!port) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Probe the service.
#
# nb: with the stream procotol, an endpoint must respond with an
#     endpoint identifier.
req1 = "JRMI" +                        # magic
  mkword(2) +                          # version
  mkbyte(0x4b);                        # protocol (0x4b => stream protocol)
send(socket:soc, data:req1);
res = recv(socket:soc, length:64, min:7);


# If...
if (
  # the response is long enough and...
  strlen(res) > 6 &&
  # it's a ProtocolAck and...
  getbyte(blob:res, pos:0) == 0x4e &&
  # it contains room for an endpoint identifier
  getword(blob:res, pos:1) + 7 == strlen(res)
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"rmi_remote_object");

  names = get_kb_list("Services/rmi/" + port + "/name");
  if (!isnull(names) && report_verbosity)
  {
    info = "";
    host = get_host_name();
    nobjs = 0;

    foreach name (names)
    {
      ++nobjs;
      info += '  rmi://' + host + ':' + port + '/' + name + '\n';
    }

    if (nobjs == 1)
    {
      report = string(
        "\n",
        "The following remote object is supported :\n",
        "\n",
        info
      );
      security_note(port:port, extra:report);
    }
    else if (nobjs > 1)
    {
      report = string(
        "\n",
        "The following remote objects are supported :\n",
        "\n",
        info
      );
      security_note(port:port, extra:report);
    }
  }
  else security_note(port);
}
