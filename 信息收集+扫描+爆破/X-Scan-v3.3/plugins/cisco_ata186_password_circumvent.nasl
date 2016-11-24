#
# (C) Tenable Network Security, Inc.
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID and CAN
#


include("compat.inc");


if(description)
{
 script_id(11012);
 script_bugtraq_id(4711, 4712);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2002-0769");
 script_xref(name:"OSVDB", value:"8849");
 script_xref(name:"OSVDB", value:"8850");
 script_name(english:"Cisco ATA-186 Password Circumvention / Recovery");
 script_summary(english:"CISCO check");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote telephone adapter has a security bypass vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host appears to be a Cisco ATA-186 - an analog telephone\n",
     "adapter used to interface analog telephones to VoIP networks.\n\n",
     "The adapter is configured via a web interface that has a security\n",
     "bypass vulnerability.  It is possible to bypass authentication by\n",
     "sending a HTTP POST request with a single byte, which could allow\n",
     "a remote attacker to take control of the device."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2002-05/0083.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.cisco.com/warp/public/707/cisco-sa-20040329-ata-password-disclosure.shtml"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Apply the patch referenced in the vendor's advisory."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english: "CISCO");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


if (! get_port_state(port))exit(0);


r = http_send_recv3( port: port, item:"/dev/", method: "GET",	
      		     username: "", password: "" );
if (isnull(r)) exit(0);
if (r[0] !~ "^HTTP[0-9]\.[0-9] 403 ") exit(0);

r = http_send_recv3( port: port, item:"/dev/", method: "POST",
    		     username: "", password: "", data: "a");
if (r =~ "^HTTP[0-9]\.[0-9] 200 ") security_hole(port);



