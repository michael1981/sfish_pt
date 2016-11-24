#
# This script was written by Andrew Hintz <http://guh.nu>
# (It is based on Renaud's template.)
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added additional CVE/BID refs, added OSVDB refs, added solution (6/27/09)


include("compat.inc");

if(description)
{
 script_id(11193);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2002-2243", "CVE-2002-2244", "CVE-2002-2274");
 script_bugtraq_id(6323, 6324, 6325);
 script_xref(name:"OSVDB", value:"55529");
 script_xref(name:"OSVDB", value:"55530");
 script_xref(name:"OSVDB", value:"55531");

 script_name(english:"akfingerd 0.5 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote finger service appears to vulnerable to a remote
attack which can disrupt the service of the finger daemon.
This denial of service does not effect other services that
may be running on the remote computer, only the finger
service can be disrupted.

akfingerd version 0.5 or earlier is running on the remote
host.  This daemon has a history of security problems, 
make sure that you are running the latest version of 
akfingerd.

Versions 0.5 and earlier of akfingerd are vulnerable to a
remote denial of service attack.  They are also vulnerable
to several local attacks." );
 script_set_attribute(attribute:"solution", value:
"akfingerd is no longer maintained. Disable the service and
find an alternative finger daemon." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
 script_end_attributes();

 
 script_summary(english:"Finger daemon DoS");
 script_category(ACT_GATHER_INFO); #This script should not disrupt the machine at all
 script_copyright(english:"This script is Copyright (C) 2002-2009 Andrew Hintz");
 script_family(english:"Finger abuses");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = string("nessusIs4Scanning2You@127.0.0.1@127.0.0.1\r\n"); #send request for forwarded finger query
  send(socket:soc, data:buf);
  data = recv(socket:soc, length:96);
  close(soc);
  if("Forwarding is not supported." >< data) #check for forwarding-denial message used by akfingerd
  {
   soc1 = open_sock_tcp(port); #start a connection and leave it open
   if(soc1)
   {
    soc2 = open_sock_tcp(port); #start another connection and issue a request on it
    if(soc2)
    {
     send(socket:soc2, data:buf);
     data2 = recv(socket:soc2, length:96);
     if(!data2) security_warning(port);  #akfingerd won't send a reply on second connection while the first is still open
     close(soc2);
    }
    else security_warning(port);
    close(soc1);
   }
  }
 }
}
