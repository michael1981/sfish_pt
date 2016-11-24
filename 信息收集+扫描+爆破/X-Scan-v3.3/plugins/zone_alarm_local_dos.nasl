#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: bipin gautam <visitbipin@yahoo.com>
#
#  This script is released under the GNU GPLv2

# Changes by Tenable:
# - Updated to use compat.inc (11/16/09)
# - Revised plugin title (7/07/09)


include("compat.inc");

if(description)
{
 script_id(14726);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2004-2713");
 script_xref(name:"OSVDB", value:"9761");

 script_name(english:"ZoneAlarm Pro Configuration File/Directory Permission Weakness DoS");

 script_set_attribute(attribute:"synopsis", value:
"This host is running a firewall with a denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"This host is running a version of ZoneAlarm Pro that contains a flaw which may
allow a local denial of service. To exploit this flaw, an attacker would need
to tamper with the files located in %windir%/Internet Logs. An attacker may
modify them and prevent ZoneAlarm from starting up properly." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-08/0871.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 
 script_summary(english:"Check ZoneAlarm Pro version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Firewalls");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/ZoneAlarm Pro/DisplayName";
key2 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/ZoneAlarm Pro/DisplayVersion";

if (get_kb_item (key))
{
 version = get_kb_item (key2);
 if (version)
 {
  set_kb_item (name:"zonealarm/version", value:version);

  if(ereg(pattern:"[1-4]\.|5\.0\.|5\.1\.", string:version))
  {
   security_warning(0);
  }
 }
}
