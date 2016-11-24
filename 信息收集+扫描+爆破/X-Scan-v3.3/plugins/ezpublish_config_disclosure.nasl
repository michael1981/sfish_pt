#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(11538);
 script_version ("$Revision: 1.13 $");

 script_bugtraq_id(7347);
 script_xref(name:"OSVDB", value:"6560");
 script_xref(name:"Secunia", value:"8606");

 script_name(english:"eZ Publish settings/site.ini Configuration Disclosure");
 script_summary(english:"Determine if eZ Publish config file can be retrieved");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application on the remote host has an information disclosure\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "eZ Publish, a content management system, is installed on the remote\n",
     "host.\n\n",
     "A remote attacker can retrieve the file 'settings/site.ini', which\n",
     "contains information such as database name, username, and password.\n",
     "This information could be used to mount further attacks.\n\n",
     "This version of eZ Publish also has multiple cross-site scripting\n",
     "vulnerabilities, though Nessus has not checked for those issues."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2003-04/0206.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Prevent .ini files from being downloaded from the web server."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
dir = make_list(cgi_dirs());

foreach d (dir)
{
 url = string(d, "/settings/site.ini");
 buf = http_send_recv3(method:"GET", item:url, port:port);
 if( isnull(buf) ) exit(0);
 
 if (
   "ConnectRetries" >< buf[2] &&
   "UseBuiltinEncoding" >< buf[2]
 )
 {
   security_warning(port:port);
   exit(0);
 }
}

