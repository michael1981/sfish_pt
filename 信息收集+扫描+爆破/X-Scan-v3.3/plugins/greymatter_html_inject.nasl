#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: poizon@securityinfo.ru
#
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title, added CVE/OSVDB (4/29/09)


include("compat.inc");

if(description)
{
 script_id(19752);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2005-2816");
 script_bugtraq_id(14703);
 script_xref(name:"OSVDB", value:"19258");
 
 script_name(english:"Greymatter Comment Name Field Control Panel Log XSS");

 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to Cross Site Scripting." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Greymatter, an opensource weblogging and 
journal software written in perl.

A vulnerability exists in this version which may allow 
an attacker to execute arbitrary HTML and script code in
the context of the user's browser." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Checks the version of the remote Greymatter");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);

function check(loc)
{
 local_var r, req;
 req = http_get(item:string(loc, "/gm.cgi"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if (egrep(pattern:'<META NAME="Generator" CONTENT="Greymatter (0\\.|1\\.([0-2][0-9]*[a-z]?|3|3\\.[01]))">', string:r)  )
 {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
   exit(0);
 }
}

if (thorough_tests) dirs = list_uniq(make_list("/greymatter", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 check(loc:dir);
}
