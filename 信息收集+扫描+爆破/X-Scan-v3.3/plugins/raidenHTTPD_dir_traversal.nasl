#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Ref: Donato Ferrante <fdonato autistici org>
#
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/1/2009)


include("compat.inc");

if (description)
{
 script_id(16313);
 script_version ("$Revision: 1.7 $");

 script_bugtraq_id(12451);
 script_xref(name:"OSVDB", value:"13575");

 script_name(english:"RaidenHTTPD Crafted Request Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of RaidenHTTPD which is
vulnerable to a remote directory traversal bug.  An attacker
exploiting this bug would be able to gain access to potentially
confidential material outside of the web root." );
 script_set_attribute(attribute:"see_also", value:"http://www3.autistici.org/fdonato/advisory/RaidenHTTPD1.1.27-adv.txt" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-01/1008.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.raidenhttpd.com/changelog.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to RaidenHTTPD version 1.1.31 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N" );

script_end_attributes();

 script_summary(english:"RaidenHTTPD directory traversal");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! get_port_state(port) ) exit(0);

banner = get_http_banner(port:port);
# Server: RaidenHTTPD/1.1.31 (Shareware)
if ( ! banner  || "RaidenHTTP" >!< banner ) exit(0);


foreach dir (make_list("windows", "winnt"))
{
  req = http_get(item:dir + "/system.ini", port:port);
  res = http_keepalive_send_recv(data:req, port:port);

  if ("[drivers]" >< tolower(res)) 
  {
    security_hole(port);
    exit(0);
  }
}
