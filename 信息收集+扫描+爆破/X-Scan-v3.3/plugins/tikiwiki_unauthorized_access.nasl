#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14359);
 script_bugtraq_id(10972);
 script_version("$Revision: 1.6 $");
 
 name["english"] = "TikiWiki Unauthorized Page Access";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has a PHP script that may allow
unauthorized access to certain restricted pages." );
 script_set_attribute(attribute:"description", value:
"The remote host is running TikiWiki, a content management 
system written in PHP.

The remote version of this software is vulnerable to a 
flaw which may allow an attacker to bypass the permissions 
of individual Wiki pages.

An attacker may exploit this flaw to deface the remote web 
server or gain access to pages he should otherwise not have 
access to." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to TikiWiki 1.8.4" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 summary["english"] = "Checks the version of TikiWiki";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);
function check(loc)
{
 local_var res;
 res = http_send_recv3(method:"GET", item:loc + "/tiki-index.php", port:port);
 if(isnull(res))exit(0);
 if( egrep(pattern:"This is Tiki v(0\.|1\.[0-7]\.|1\.8\.[0-3][^0-9])", string:res[2]) )
 {
   security_warning(port);
   exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

