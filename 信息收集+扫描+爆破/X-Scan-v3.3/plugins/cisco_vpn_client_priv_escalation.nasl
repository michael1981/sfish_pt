#
# Script Written By Ferdy Riphagen 
# Script distributed under the GNU GPLv2 License. 
#


include("compat.inc");

if (description) {
 script_id(25550);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2006-2679");
 script_bugtraq_id(18094);
 script_xref(name:"OSVDB", value:"25888");

 script_name(english:"Cisco VPN Client Dialer Local Privilege Escalation");

 script_set_attribute(attribute:"synopsis", value:
"The remote windows host contains an application that is affected by a
privilege escalation vulnerability." );
 script_set_attribute(attribute:"description", value:
"The installed Cisco VPN Client version is prone to a privilege
escalation attack.  By using the 'Start before logon' feature in the
VPN client dialer, a local attacker may gain privileges and execute
arbitrary commands with SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/warp/public/707/cisco-sa-20060524-vpnclient.shtml" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.8.01.0300 or a later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 summary = "Detects a privilege escalation in the Cisco VPN Client by query its version number";
 script_summary(english:summary);
 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2007-2009 Ferdy Riphagen");

 script_dependencies("cisco_vpn_client_detect.nasl");
 script_require_keys("SMB/CiscoVPNClient/Version");
 exit(0);
}

version = get_kb_item("SMB/CiscoVPNClient/Version");
if (version) {
	# These versions are reported vulnerable:
	# - 2.x, 3.x, 4.0.x, 4.6.x, 4.7.x, 4.8.00.x
	# Not vulnerable:
	# - 4.7.00.0533
 	if ("4.7.00.0533" >< version) exit(0);
	if (egrep(pattern:"^([23]\.|4\.([067]\.|8\.00)).+", string:version)) {
		security_warning(port:get_kb_item("SMB/transport"));
	}
}
