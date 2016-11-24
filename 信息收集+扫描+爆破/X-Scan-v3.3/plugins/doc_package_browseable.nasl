#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID and CVE



include("compat.inc");

if(description)
{
 script_id(10518);
 script_version ("$Revision: 1.24 $");

 script_cve_id("CVE-2000-1016");
 script_bugtraq_id(1707);
 script_xref(name:"OSVDB", value:"417");

 script_name(english:"/doc/packages Directory Browsable");
 script_summary(english:"Is /doc/packages browsable ?");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The /doc/packages directory is browsable.  This directory contains the
versions of the packages installed on this host.  A remote attacker can
use this information to mount further attacks." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-09/0300.html" );
 script_set_attribute(attribute:"solution", value:
"Use access restrictions for the /doc directory.  If you use Apache
you might use this in your access.conf:

  <Directory /usr/doc>
  AllowOverride None
  order deny,allow
  deny from all
  allow from localhost
  </Directory>" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", 
 		    "doc_browsable.nasl",
 		    "http_version.nasl");
 script_require_keys("www/doc_browseable");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

dir = "/doc/packages/";
r = http_send_recv3(method:"GET", item: dir, port:port);
if (isnull(r)) exit(0);

code = r[0];
buf = strcat(r[1], '\r\n', r[2]);
buf = tolower(buf);
must_see = "index of /doc";

  if((ereg(string:code, pattern:"^HTTP/[0-9]\.[0-9] 200 "))&&(must_see >< buf))
  {
    	security_warning(port);
	set_kb_item( name: 'www/'+port+'/content/directory_index', value: dir);
  }

