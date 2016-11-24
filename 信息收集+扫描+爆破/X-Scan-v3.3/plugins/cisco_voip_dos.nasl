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
 script_id(11013);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2002-0882");
 script_bugtraq_id(4794, 4798);
 script_xref(name:"OSVDB", value:"14855");
 script_xref(name:"OSVDB", value:"14856");
 
 script_name(english:"Cisco VoIP Phone Multiple Script Malformed Request DoS");
 script_summary(english:"CISCO check");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote IP phone has multiple vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host appears to be a Cisco IP phone.  It was possible to\n",
     "reboot this device by requesting :\n\n",
     "  http://<phone-ip>/StreamingStatistics?120000\n\n",
     "This device likely has other vulnerabilities that Nessus has not\n",
     "checked for."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2002-05/0200.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?b1d74bb7"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Apply the fix referenced in the vendor's advisory."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_KILL_HOST);
 script_family(english:"CISCO");

 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

# we don't use start_denial/end_denial because they
# might be too slow (the phone takes 15 seconds to reboot)

alive = tcp_ping(port:port);
if (! alive) exit(0);
r = http_send_recv3(method:"GET", item:"/StreamingStatistics?120000", port:port);
sleep(5);
alive = tcp_ping(port:port);
if (! alive) security_hole(port);


