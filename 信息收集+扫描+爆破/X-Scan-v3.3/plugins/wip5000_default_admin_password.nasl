#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(34217);
 script_version ("$Revision: 1.5 $");
 script_xref(name:"OSVDB", value:"48241");

 script_name(english:"Default Password (000000) for 'admin' on WIP5000 IP Phone");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IP phone has a default password set for the 'admin' user" );
 script_set_attribute(attribute:"description", value:
"The remote host is a WIP5000 VOIP phone.  The remote host has the
default password set for the 'admin' user ('000000'). 

An attacker may connect to it and reconfigure it using this account." );
 script_set_attribute(attribute:"solution", value:
"Connect to this port with a web browser and set a strong password, or
change the password from the handheld device directly." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"Tests for the WIP5000 default account");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencies("http_version.nasl");
 script_require_ports(8080);
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");


port = 8080;
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if (!banner || "Server: IP-Phone Solution" >!< banner) exit(0);

req = http_get(item:"/index.html", port:port);
res = http_get_cache(item:"/index.html", port:port);
if ( res == NULL ) exit(0);

if ( egrep ( pattern:"^HTTP/.* 401 .*", string:res ) &&
    "IP-Phone Solution" >< res )
{
 req -= string("\r\n\r\n");
 req += string("\r\nAuthorization: Basic YWRtaW46MDAwMDAw\r\n\r\n");
 res = http_keepalive_send_recv(port:port, data:req);
 if (res == NULL ) exit(0);
 if ( egrep ( pattern:"^HTTP/.* 200 .*", string:res) &&
      "WirelessIP5000A Web Configuration Tool" >< res  )
	security_hole(port);
}

