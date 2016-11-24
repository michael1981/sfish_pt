#
# (C) Tenable Network Security, Inc.
#

#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

include( 'compat.inc' );

if(description)
{
  script_id(10563);
  script_bugtraq_id(2022);
  script_xref(name:"OSVDB", value:"462");
  script_cve_id("CVE-2000-1039");
  script_version ("$Revision: 1.25 $");

  script_name(english:"MS00-091: Incomplete TCP/IP packet vulnerability (199346)");
  script_summary(english: "Determines whether the hotfix Q274372 is installed");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote host is vulnerable to denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The hotfix for the 'incomplete TCP/IP packet'
problem has not been applied.

This vulnerability allows a user to prevent this host
from communicating with the network"
  );

  script_set_attribute(
    attribute:'solution',
    value:'Apply the appropriate patches from MS00-091 or apply the latest Windows service pack.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.microsoft.com/technet/security/bulletin/ms00-091.mspx'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
  script_family(english:"Windows : Microsoft Bulletins");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  exit(0);
}

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if ( hotfix_check_sp(nt:7) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q299444") > 0 && hotfix_missing(name:"Q275567") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS00-091", value:TRUE);
 hotfix_security_warning();
 }
