#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10071);
 script_version ("$Revision: 1.22 $");
 script_xref(name:"OSVDB", value:"62");
 
 script_name(english:"Multiple Web Server finger CGI Information Disclosure");
 script_summary(english:"Checks for the presence of /cgi-bin/finger");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"An application on the remote web server is leaking information."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The 'finger' CGI is installed.  This can be used by a remote attacker\n",
     "to enumerate accounts on the system.  Such information is typically\n",
     "valuable in conducting additional, more focused attacks."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remove the script from /cgi-bin."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed3(port:port, item:"finger");
if(res)
{
 security_warning(port);
}
