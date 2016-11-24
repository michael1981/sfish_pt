#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22017);
  script_version("$Revision: 1.8 $");

  script_name(english:"DB2 Discovery Service Detection");
  script_summary(english:"Detects a DB2 Discovery Service");

 script_set_attribute(attribute:"synopsis", value:
"A DB2 discovery server is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a DB2 discovery service.  DB2 is a
commercial database from IBM, and the discovery service is used by DB2
to locate databases across a network." );
 script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/software/data/db2/udb/" );
 script_set_attribute(attribute:"risk_factor", value: "None" );
 script_set_attribute(attribute:"solution", value: "n/a" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


port = 523;


function get_null_string(blob, pos)
{
  local_var i, tmp;

  if (isnull(pos)) pos = 0;

  tmp = NULL;
  for (i=pos; i<strlen(blob); i++)
  {
    if (ord(blob[i]) != 0)
      tmp += blob[i];
    else
      break;
  }
  return tmp;
}


# Try to get some interesting information.
#
# - level identifier (ie, version).
soc = open_sock_udp(port);
if ( ! soc ) exit(0);
req = raw_string("DB2GETADDR", 0, "SQL05000", 0);
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);


# If the response looks right..
if (
  strlen(res) >= 16 &&
  stridx(res, raw_string("DB2RETADDR", 0)) == 0
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"udp", proto:"db2_ds");

  if (strlen(res) >= 0x120)
  {
    # Extract some info from the response packet.
    #
    # nb: from <http://publib.boulder.ibm.com/infocenter/db2luw/v8/index.jsp?topic=/com.ibm.db2.udb.common.doc/common/aboutdialog.htm>, 
    #     Product identifier: identifies the DB2 Administration Server in 
    #     the format 'ppvvrrm', where 'ppp' is the product, 'vv' is the 
    #     version, 'rr' is the release, and 'm' is the modification level.
    prod  = get_null_string(blob:res, pos:11);
    node = get_null_string(blob:res, pos:20);

    report = string(
      "\n",
      "  Node name :          ", node, "\n",
      "  Product identifier : ", prod, "\n",
      "\n"
    );
    security_note(port:port, proto:"udp", extra:report);
  }
  else security_note(port:port, proto:"udp");
}
