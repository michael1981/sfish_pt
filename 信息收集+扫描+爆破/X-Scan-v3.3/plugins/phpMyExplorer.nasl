#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10750);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2001-1168");
 script_bugtraq_id(3266);
 script_xref(name:"OSVDB", value:"621");
 	
 script_name(english:"PhpMyExplorer index.php chemin Variable Encoded Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary directories may be browsed on the remote server." );
 script_set_attribute(attribute:"description", value:
"phpMyExplorer is vulnerable to a directory traversal attack which allows
anyone to make the remote web server read and display arbitrary
directories.

For example:
    GET /index.php?chemin=..%2F..%2F..%2F..%2F%2Fetc
will return the content of the remote /etc directory" );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for the latest software release." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"phpMyExplorer dir traversal");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("webmirror.nasl", "http_version.nasl");
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


foreach dir (cgi_dirs())
{
  u = string(dir, "/index.php?chemin=..%2F..%2F..%2F..%2F..%2F..%2F..%2F%2Fetc");
  r = http_send_recv3(method:"GET", item:u, port:port);
  if (isnull(r)) exit(0);
  buf = strcat(r[0], r[1], '\r\n', r[2]);
  if ("resolv.conf" >< buf)
    security_warning(port, extra: strcat(
'\nThe following URL will exhibit the flaw :\n\n', build_url(port: port, qs: u), '\n'));
}
