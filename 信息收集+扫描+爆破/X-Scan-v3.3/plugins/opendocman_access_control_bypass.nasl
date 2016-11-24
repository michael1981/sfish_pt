#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(13847);
 script_bugtraq_id(10807);
 script_version("$Revision: 1.3 $");

 script_name(english:"OpenDocMan Access Control Bypass");
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that may allow unauthorized
access to certain documents." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OpenDocMan, an open source document management
system.

There is a flaw in the remote version of this software which may allow an
attacker with a given account to modify the content of some documents
he would otherwise not have access to." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenDocMan 1.2.0" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Determines if OpenDocMan is present");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
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

if(!can_host_php(port:port))exit(0, "The remote server does not support php.");

foreach dir (cgi_dirs())
{
 url = string(dir,"/index.php");
 res = http_send_recv3(method:"GET", item:url, port:port);

 if(isnull(res)) exit(1,"Null response to index.php request.");
 
 if( "OpenDocMan" >< res && egrep(pattern:"<h5> OpenDocMan v(0\.|1\.[01]\.)", string:res[2]) ) 
 {
    	security_warning(port);
	exit(0);
 }
}
