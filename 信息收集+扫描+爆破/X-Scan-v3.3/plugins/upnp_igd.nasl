#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(35709);
 script_version("$Revision: 1.3 $");
 script_name(english: "UPnP Internet Gateway Device (IGD) Protocol Detection");

 script_set_attribute(attribute:"synopsis", value:"The remote device supports the IGD protocol.");
 script_set_attribute(attribute:"description", value:
"According to UPnP data, the remote device is a NAT router which supports
the Internet Gateway Device (IGD) Standardized Device Control Protocol.

IGD is dangerous as it allows a remote attacker to punch holes in your
firewall, for example through a malicious Flash animation.");
 script_set_attribute(attribute: "see_also", value: 
"http://www.gnucitizen.org/blog/flash-upnp-attack-faq/
http://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol");
 script_set_attribute(attribute:"solution", value:"Filter incoming traffic to this port or disable this service");
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:P");
 script_end_attributes();

 script_summary(english: "Look for IGD in the UPnP information");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Misc.");
 script_dependencie("upnp_www_server.nasl");
 script_require_keys("upnp/www");
 exit(0);
}

include('global_settings.inc');

port = get_kb_item("upnp/www");
gd = get_kb_item('upnp/'+port+'/devdescr');
if (! gd) exit(0);

# We need a real parser here
r = egrep(string: gd, pattern: '<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:[1-9]+</deviceType>');

if (r) security_warning(port: port);
