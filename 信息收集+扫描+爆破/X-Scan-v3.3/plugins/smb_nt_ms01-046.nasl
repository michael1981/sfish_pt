#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10734);
 script_version ("$Revision: 1.32 $");
 script_cve_id("CVE-2001-0659");
 script_bugtraq_id(3215);
 script_xref(name:"OSVDB", value:"608");
 
 script_name(english:"MS01-046: IrDA Driver Malformed Packet Remote DoS (252795)");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to remotely shutdown the server." );
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'IrDA access violation patch' problem has not been
applied. 

This vulnerability can allow an attacker who is physically near the
W2K host to shut it down using a remote control." );
 script_set_attribute(attribute:"see_also", value:"POST SP2 Security Rollup:" );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/windows2000/downloads/critical/q311401/default.asp" );
 script_set_attribute(attribute:"solution", value:
"http://www.microsoft.com/technet/security/bulletin/ms01-046.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 script_summary(english:"Determines whether the hotfix Q252795 is installed");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 exit(0);
}

#

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(win2k:3) <= 0 ) exit(0);
if ( hotfix_missing(name:"SP2SRP1") > 0 &&
     hotfix_missing(name:"Q252795") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS01-046", value:TRUE);
 hotfix_security_warning();
 }

