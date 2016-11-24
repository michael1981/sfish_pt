#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10253);
 script_version ("$Revision: 1.19 $");

 script_cve_id("CVE-2000-0117");
 script_bugtraq_id(951);
 script_xref(name:"OSVDB", value:"201");
 
 script_name(english:"Cobalt siteUserMod.cgi Arbitrary Password Modification");
 script_summary(english:"Checks for the presence of /.cobalt/siteUserMod/siteUserMod.cgi");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The remote web server contains a CGI script that allows modification\n",
   "of arbitrary passwords."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The Cobalt 'siteUserMod' CGI appears to be installed on the remote web\n",
   "server.  Older versions of this CGI may allow a user with Site\n",
   "Administrator access to change the password of users on the system,\n",
   "such as Site Administrator or regular users, or the admin (root)\n",
   "user.\n",
   "\n",
   "Note that Nessus has only determined that a script with this name\n",
   "exists.  It has not tried to exploit the issue or determine the\n",
   "version installed."
  )
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2000-01/0417.html"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://archives.neohapsis.com/archives/bugtraq/2000-01/0421.html"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Apply the appropriate patch referenced in the vendor advisory above."
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");

 script_family(english:"CGI abuses");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

cgi = string("/.cobalt/siteUserMod/siteUserMod.cgi");
res = is_cgi_installed_ka(item:cgi, port:port);
if(res)security_hole(port);

