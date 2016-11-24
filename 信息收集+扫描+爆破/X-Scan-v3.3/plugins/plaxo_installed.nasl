#
# Written by:
# This script is Copyright (C) 2005 Tom Ferris
# GPLv2
# <tommy@security-protocols.com>
# 6/29/2005
# www.security-protocols.com
#


include("compat.inc");

if(description)
{
 script_id(18591);
 script_version("$Revision: 1.2 $");

 name["english"] = "Plaxo Client Is Installed";

 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"Plaxo Client is installed." );
 script_set_attribute(attribute:"description", value:
"The remote host has the Plaxo Client software installed. Plaxo is a 
contact manager.
Make sure its use is compatible with your corporate security policy." );
 script_set_attribute(attribute:"solution", value:
"Uninstall this software if it does not match your security policy" );
 script_set_attribute(attribute:"risk_factor", value:"Low" );

script_end_attributes();


 summary["english"] = "Determines if Plaxo is installed";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2009 Tom Ferris <tommy@security-protocols.com>");
 family["english"] = "Windows";
 script_family(english:family["english"]);

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Plaxo/DisplayName";

if (get_kb_item (key))
  security_note(get_kb_item("SMB/transport"));
