#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: Wally Whacker <whacker@hackerwhacker.com>
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Updated to use compat.inc (11/16/09)
# - Revised plugin title (7/08/09)


include("compat.inc");

if(description)
{
 script_id(14660);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2000-0339");  
 script_bugtraq_id(1137);
 script_xref(name:"OSVDB", value:"1294");

 script_name(english:"ZoneAlarm Personal Firewall UDP Source Port 67 Bypass");

 script_set_attribute(attribute:"synopsis", value:
"This host is running a firewall that fails to filter certain types of
traffic." );
 script_set_attribute(attribute:"description", value:
"This version of ZoneAlarm contains a flaw that may allow a remote
attacker to bypass the ruleset.  The issue is due to ZoneAlarm not
monitoring and alerting UDP traffic with a source port of 67. 

This allows an attacker to bypass the firewall to reach protected
hosts without setting off warnings on the firewall." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-04/0145.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade at least to version 2.1.25." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 
 script_summary(english:"Check ZoneAlarm version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Firewalls");
 script_dependencies("netbios_name_get.nasl","zone_alarm_local_dos.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/transport", "zonealarm/version");

 script_require_ports(139, 445);
 exit(0);
}

zaversion = get_kb_item ("zonealarm/version");
if (!zaversion) exit (0);

if(ereg(pattern:"^([0-1]\.|2\.0|2\.1\.([0-9]|1[0-9]|2[0-4])[^0-9])", string:zaversion))
{
 security_warning(0);
}
