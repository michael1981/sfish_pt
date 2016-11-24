#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10078);
 script_bugtraq_id(1205);
 script_xref(name:"OSVDB", value:"68");
 script_version ("$Revision: 1.24 $");

 script_name(english:"Microsoft FrontPage Extensions authors.pwd Information Disclosure");
 script_summary(english:"Checks for the presence of Microsoft FrontPage extensions");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server has an information disclosure vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote web server appears to be running with Microsoft FrontPage\n",
     "extensions.  The file 'authors.pwd', which contains the encrypted\n",
     "passwords of FrontPage authors, can by accessed by anyone.  A remote\n",
     "attacker could decrypt these passwords, or possibly overwrite this file."
   )
 );
 script_set_attribute(
   attribute:"see_also", 
   value:"http://archives.neohapsis.com/archives/bugtraq/1998_2/0181.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:
     string(
       "Change the permissions of the '/vti_vt' directory to prevent access\n",
       "by unauthenticated web users."
     )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl");
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

sig = get_http_banner(port:port);
if ( sig && "IIS" >!< sig ) exit(0);
res = is_cgi_installed3(item:"/_vti_pvt/authors.pwd", port:port);
if ( res ) security_warning(port);
