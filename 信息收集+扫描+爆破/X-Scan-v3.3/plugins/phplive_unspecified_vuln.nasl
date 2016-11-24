#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15928);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2004-2485");
 script_bugtraq_id(11863);
 script_xref(name:"OSVDB", value:"12147");

 script_name(english:"PHP Live! directory/conf File Include Unspecified Issue");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHP Live! a live support system for web 
sites.

The remote version of this software contains an unspecified flaw which 
may allow an attacker to include a configuration file hosted on a third 
party server.

An attacker may exploit this flaw to execute arbitrary PHP code on the 
remote host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/apps/freshmeat/2004-11/0022.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP Live! 2.8.2" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
 
script_end_attributes();

 script_summary(english:"Checks for a flaw in PHP Live! < 2.8.2");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

foreach dir (list_uniq(make_list("/phplive", cgi_dirs())))
{
 r = http_send_recv3(method: "GET", item:dir + "/index.php", port:port);
 if (isnull(r)) exit(0);
 res = strcat(r[0], r[1], '\r\n', r[2]);
 if ( egrep(pattern:"Powered by .*PHP.*Live!", string: res) )
 {
  if ( egrep(pattern:"v([0-1]\.|2\.[0-7]|2\.8\.[0-2][^0-9]).*&copy; OSI Codes Inc.", string:res ) )
	security_hole ( port );
 }
 
}
