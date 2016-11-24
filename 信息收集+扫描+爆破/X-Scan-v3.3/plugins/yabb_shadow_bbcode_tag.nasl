#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(15859);
 script_version ("$Revision: 1.11 $");
 script_bugtraq_id(11764);
 script_xref(name:"OSVDB", value:"12145");

 script_name(english:"YaBB Shadow BBCode Tag XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is prone to
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is using the YaBB web forum software. 

According to its version number, the remote version of this software
is vulnerable to JavaScript injection issues using shadow or glow
tags.  This may allow an attacker to inject hostile JavaScript into
the forum system, to steal cookie credentials or misrepresent site
content.  When the form is submitted the malicious JavaScript will be
incorporated into dynamically generated content." );
 script_set_attribute(attribute:"see_also", value:"http://www.yabbforum.com/archives.php?currentpage=7" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to YaBB 1 Gold SP 1.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Determines the version of YaBB");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (thorough_tests) dirs = list_uniq("/yabb", "/forum", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 url = string(dir, "/YaBB.pl");
 r = http_send_recv3(method: "GET", item:url, port:port);
 if (isnull(r)) exit(0);
 buf = r[2];
 if(egrep(pattern:"Powered by.*YaBB (1 Gold - (Release|SP1(\.[1-2].*|3(\.(1|2))?)))", string:buf) ||
    egrep(pattern:"Powered by.*YaBB (1\.([0-9][^0-9]|[0-3][0-9]|4[0-1])(\.0)?)",string:buf) ||
    egrep(pattern:"Powered by.*YaBB (9\.([0-1][^0-9]|1[0-1])(\.[0-9][^0-9]|[0-9][0-9][^0-9]|[0-9][0-9][0-9][^0-9]|[0-1][0-9][0-9][0-9][^0-9]|2000)?)",string:buf))	
   {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
   }
}
