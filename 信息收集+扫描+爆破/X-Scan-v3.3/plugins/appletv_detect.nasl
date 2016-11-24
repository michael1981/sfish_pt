#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42825);
  script_version("$Revision: 1.1 $");

  name["english"] = "Apple TV Detection";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is a digital media receiver." );
 script_set_attribute(attribute:"description", value:
"The remote host is an Apple TV, a digital media receiver." );
 script_set_attribute(attribute:"see_also", value:"http://www.apple.com/appletv/" );
 script_set_attribute(attribute:"solution", value:
"Make sure that use of such devices is in line with your
organization's acceptable use and security policies." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/16" );
 script_end_attributes();
 
  summary["english"] = "Detects AppleTV";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports(3689);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


if ( ! get_port_state(3689) ) exit(0);
banner = get_http_banner(port:3689);
if (! banner ) exit(0);

if ( "RIPT-Server: iTunesLib/" >< banner )
{
 security_note(0);
}
