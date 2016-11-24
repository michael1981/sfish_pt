#
# (C) Tenable Network Security
#
#


include("compat.inc");

if (description)
{
 script_id(15469);
 script_version ("$Revision: 1.11 $");

 script_cve_id(
   "CVE-2004-1669", 
   "CVE-2004-1670", 
   "CVE-2004-1671", 
   "CVE-2004-1672", 
   "CVE-2004-1673", 
   "CVE-2004-1674"
 );
 script_bugtraq_id(11371);
 script_xref(name:"OSVDB", value:"9805");
 script_xref(name:"OSVDB", value:"9806");
 script_xref(name:"OSVDB", value:"9807");
 script_xref(name:"OSVDB", value:"9808");
 script_xref(name:"OSVDB", value:"9809");
 script_xref(name:"OSVDB", value:"9810");
 script_xref(name:"OSVDB", value:"9811");
 script_xref(name:"OSVDB", value:"9812");
 script_xref(name:"OSVDB", value:"9813");
 script_xref(name:"OSVDB", value:"9814");
 script_xref(name:"OSVDB", value:"11558");
 script_xref(name:"OSVDB", value:"11559");
 script_xref(name:"OSVDB", value:"11560");
 script_xref(name:"OSVDB", value:"11561");
 script_xref(name:"OSVDB", value:"11563");
 script_xref(name:"OSVDB", value:"11564");
 script_xref(name:"OSVDB", value:"11565");

 script_name(english:"IceWarp Web Mail Multiple Flaws (1)");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a webmail application that is
affected by multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IceWarp Web Mail - a webmail solution
available for the Microsoft Windows platform.

The remote version of this software is vulnerable to multiple 
input validation issues which may allow an attacker to compromise the
integrity of the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc61aa25" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/380446/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-09/0087.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IceWarp Web Mail 5.3.0 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Check the version of IceWarp WebMail");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 32000);
 exit(0);
}

include("http.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_http_port(default:32000);

if(!get_port_state(port))exit(0);

res = http_send_recv3(method:"GET", item:"/mail/", port:port);
if (isnull(res)) exit(1, "The remote server did not respond to the GET request");

if ('Merak Email Server</A><BR>IceWarp Web Mail' >< res[2])
{
 version = egrep(pattern:"IceWarp Web Mail [0-9]\.", string:res );
 if ( ! version ) exit(0);
 version = ereg_replace(pattern:".*(IceWarp Web Mail [0-9.]*).*", string:version, replace:"\1");
 set_kb_item(name:"www/" + port + "/icewarp_webmail/version", value:version);
 if ( ereg(pattern:"IceWarp Web Mail ([0-4]\.|5\.[0-2]\.)", string:version) )
	security_hole(port);
}
