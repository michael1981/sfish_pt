#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(10505);
  script_version ("$Revision: 1.22 $");
  script_cve_id("CVE-2000-0869");
  script_bugtraq_id(1656);
  script_xref(name:"OSVDB", value:"404");
  
  script_name(english:"Apache WebDAV Module PROPFIND Arbitrary Directory Listing");

 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to an information disclosure attack." );
 script_set_attribute(attribute:"description", value:
"The WebDAV module can be used to obtain a listing of the remote web
server directories even if they have a default page such as
index.html. 

This allows an attacker to gain valuable information about the
directory structure of the remote host and could reveal the presence
of files which are not intended to be visible." );
 script_set_attribute(attribute:"solution", value:
"Disable the WebDAV module, or restrict its access to authenticated and
trusted clients." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english: "Checks the presence of WebDAV");
 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

r = http_send_recv3(port: port, item: '/', version: 11, method: 'PROPFIND',
  add_headers: make_array("Content-Type", "text/xml",
			 "Depth", "1"),
  data : '<?xml version="1.0"?>\r\n<a:propfind xmlns:a="DAV:">\r\n <a:prop>\r\n  <a:displayname:/>\r\n </a:prop>\r\n</a:propfind>\r\n' );
if (isnull(r)) exit(1, "The web server did not respond.");

if("HTTP/1.1 207 " >< r[0] && "D:href" >< r[2])
 security_note(port);
