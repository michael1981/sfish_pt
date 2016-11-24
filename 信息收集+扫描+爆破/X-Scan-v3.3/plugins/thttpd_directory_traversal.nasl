#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# This script is released under the GNU GPLv2
#
# Changes by Tenable:
# - Revised title, summary, changed family (12/19/2008)

include("compat.inc");

if(description)
{
 script_id(14229);
 script_cve_id("CVE-2004-2628");
 script_bugtraq_id(10862);
 script_xref(name:"OSVDB", value:"8372");
 script_version ("$Revision: 1.12 $");
 
 script_name(english:"thttpd 2.0.7 Directory Traversal (Windows)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a path traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote web server fails to limit requests to items within the
document directory.  An attacker may exploit this flaw to read
arbitrary files on the remote system with the privileges of the http
process." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-08/0097.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
 script_summary(english:"thttpd traversal - try to read c:\boot.ini");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"c:\boot.ini", port:port);
  send(socket:soc, data:buf);
  rep = http_recv(socket:soc);
  if ( '\r\n\r\n' >< rep )
   rep = strstr(rep, '\r\n\r\n');

  if(egrep(pattern:"\[boot loader\]", string:rep))
  {
    report = string(
      "\n",
      "Requesting the file c:\boot.ini returns :\n",
      "\n",
      rep, "\n"
    );
    security_warning(port:port, extra:report);
  }

  http_close_socket(soc);
 }
}

