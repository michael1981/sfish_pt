#
# This script was rewritten by Tenable Network Security
#



include("compat.inc");

if(description)
{
 script_id(12295);
 script_version("$Revision: 1.14 $");
 
 name["english"] = "Dell OpenManage Web Server Detection";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"A management server is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Dell OpenManage Web Server." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?123f3863" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
script_end_attributes();

 summary["english"] = "Dell OpenManage Web Server Detection";

 script_category(ACT_GATHER_INFO);
 script_summary(english:summary["english"]);
 script_family(english:"Service detection");

 script_copyright(english:"This is script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_require_ports(1311);
 script_dependencies("http_version.nasl");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = 1311;

if ( ! get_port_state(port) ) exit(0);
# The previous version forced the use of a SSLv23 connection...

url = "/servlet/UDataArea?plugin=com.dell.oma.webplugins.AboutWebPlugin";
r = http_send_recv3(port:port, method: "GET", item:url);

if ( egrep(pattern:".*<br>Version [0-9]+\.[0-9]+\.[0-9]+<br>Copyright \(C\) Dell Inc.*", string: r[2]) )
{
 version = ereg_replace(pattern:".*<br>Version ([0-9]+\.[0-9]+\.[0-9]+)<br>.*", string: r[2], replace:"\1");

 report = string ("\n",
		"The Dell OpenManage Server version is ", version, ".\n");

 security_note (port:port, extra:report);
 register_service(port:port, ipproto:"tcp", proto:"dom");
}
