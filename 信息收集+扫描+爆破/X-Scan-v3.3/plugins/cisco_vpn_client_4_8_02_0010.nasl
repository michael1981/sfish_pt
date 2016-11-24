#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25906);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-4414");
  script_bugtraq_id(25332);
  script_xref(name:"OSVDB", value:"46723");

  script_name(english:"Cisco VPN Client on Windows Dial-up Networking Dialog Local Privilege Escalation");
  script_summary(english:"Checks version of vpngui.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is prone to a local
privilege escalation attack." );
 script_set_attribute(attribute:"description", value:
"The version of the Cisco VPN client installed on the remote host
reportedly allows an unprivileged local user to elevate his privileges
to the LocalSystem account by enabling the 'Start Before Login'
feature and configuring a VPN profile to use Microsoft's Dial-Up
Networking interface." );
 script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/warp/public/707/cisco-sa-20070815-vpnclient.shtml" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/476651/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco VPN Client version 4.8.02.0010 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("cisco_vpn_client_detect.nasl");
  script_require_keys("SMB/CiscoVPNClient/Version");

  exit(0);
}


ver = get_kb_item("SMB/CiscoVPNClient/Version");
if (isnull(ver)) exit(0);

iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<4; i++)
  iver[i] = int(iver[i]);

fix = split("4.8.02.0010", sep:'.', keep:FALSE);
for (i=0; i<4; i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(iver); i++)
  if ((iver[i] < fix[i]))
  {
    security_warning(get_kb_item("SMB/transport"));
    break;
  }
  else if (iver[i] > fix[i])
    break;
