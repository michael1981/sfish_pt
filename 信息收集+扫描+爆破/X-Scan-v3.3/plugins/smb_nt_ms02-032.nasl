#
# (C) Tenable Network Security, Inc.
#

# Fixed in Windows XP SP1
#
# Vulnerable versions :
# 	Media Player in Windows XP preSP1 
# 	Media Player 6.4
#	Media Player 7.1
#
# Supercedes MS01-056
#
# @DEPRECATED@

include("compat.inc");

if(description)
{
 script_id(11302);
 script_version("$Revision: 1.23 $");

 script_cve_id("CVE-2002-0372", "CVE-2002-0373", "CVE-2002-0615");
 script_bugtraq_id(5107, 5109, 5110);
 script_xref(name:"OSVDB", value:"5312");
 script_xref(name:"OSVDB", value:"5313");
 script_xref(name:"OSVDB", value:"13419");
 
 script_name(english:"MS02-032: Cumulative patch for Windows Media Player (320920)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the media
player." );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows Media Player is affected by various flaws :

  - A remote attacker may be able to execute arbitrary code 
    when sending a badly formed file.
	  
  - A local attacker may gain SYSTEM privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP :

http://www.microsoft.com/technet/security/bulletin/ms02-032.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Checks the version of Media Player");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

# FP -> superseded by many other patches.
exit(0);
