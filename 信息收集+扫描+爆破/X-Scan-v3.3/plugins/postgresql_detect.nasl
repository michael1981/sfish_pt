#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(26024);
  script_version("$Revision: 1.6 $");

  script_name(english:"PostgreSQL Server Detection");
  script_summary(english:"Sends a startup message");

  script_set_attribute(
    attribute:"synopsis",
    value:"A database service is listening on the remote host."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote service is a PostgreSQL database server, or a derivative\n",
      "such as EnterpriseDB."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Limit incoming traffic to this port if desired."
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 5432, 5444);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
{
  port = get_unknown_svc(5432);
  if (!port) port = get_unknown_svc(5444);
  if (!port) exit(0);
  if (silent_service(port) ) exit(0); 
}
else port = 5432;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Send a startup message.
#
# nb: see <http://developer.postgresql.org/pgdocs/postgres/protocol-message-formats.html>.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);
user = SCRIPT_NAME;
db = "nessus";

req = mkword(0x03) + mkword(0x00) +    # protocol version (3.0)
  "user" + mkbyte(0) + 
    user + mkbyte(0) +
  "database" + mkbyte(0) +
    db + mkbyte(0) +
  "client_encoding" + mkbyte(0) +
    "UNICODE" + mkbyte(0) +
  "DateStyle" + mkbyte(0) +
    "ISO" + mkbyte(0) +
  mkbyte(0);
req = 
  mkdword(strlen(req)+4) +
  req;
send(socket:soc, data:req);
res = recv(socket:soc, length:1, min:1);
if ( ! res || res[0] !~ "(E|R)" ) exit(0);
res += recv(socket:soc, length:4, min:4);
if ( strlen(res) < 5 ) exit(0);
len = getdword(blob:res, pos:1);
if ( len > 2048 ) exit(0); 
res += recv(socket:soc, length:len - 4);


# If...
if (
  strlen(res) >= 5 &&
  # either the response is ...
  (
    # an error or...
    (
      res[0] == "E" && 
      (
        "SERROR" >< res ||
        "SFATAL" >< res ||
        "SPANIC" >< res
      )
    ) ||
    # an authentication request
    (
      res[0] == "R" &&
      (
        getdword(blob:res, pos:1) == 8 ||
        getdword(blob:res, pos:1) == 10 ||
        getdword(blob:res, pos:1) == 12
      )
    )
  )
)
{
  # Register and report the service.
  register_service(port:port, proto:"postgresql");
  security_note(port);
}
