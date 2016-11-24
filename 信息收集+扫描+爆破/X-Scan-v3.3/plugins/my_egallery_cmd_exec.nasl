#
# (C) Tenable Network Security
#

# Ref: 
# From: "Bojan Zdrnja" <Bojan.Zdrnja@LSS.hr>
# To: <bugtraq@securityfocus.com>
# Subject: Remote execution in My_eGallery
# Date: Thu, 27 Nov 2003 09:37:36 +1300
#



include("compat.inc");

if(description)
{
 script_id(11931);
 script_version ("$Revision: 1.12 $");
 script_bugtraq_id(9113);
 script_xref(name:"OSVDB", value:"2867");

 script_name(english:"My_eGallery < 3.1.1g Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected by
a remote file inclusion vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server is hosting the 'my_egallery' PostNuke module. The
installed version is potentially affected by a remote file include 
vulnerability because the application fails to properly sanitize input
to include include statements.

An attacker may use this flaw to execute arbitrary code in the remote
host and gain a shell with the privileges of the web server." );
 script_set_attribute(attribute:"see_also", value:"http://packetstormsecurity.nl/0311-exploits/myegallery.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to My_eGallery 3.1.1g or later as this reportedly fixes the
issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 summary["english"] = "Checks for the version of My_eGallery";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

foreach dir (cgi_dirs())
{
 req = http_get(item:dir + "/modules.php?name=My_eGallery", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if (egrep(pattern:"Powered by: My_eGallery ([0-2]\.|3\.0\.|3\.1\.0|3\.1\.1\.?[a-f])", string:res)) { security_hole(port); exit(0); }
}
