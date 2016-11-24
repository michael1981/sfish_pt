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
  script_id(10485);
  script_version ("$Revision: 1.23 $");

  script_cve_id("CVE-2000-0737");
  script_bugtraq_id(1535);
  script_xref(name:"OSVDB", value:"384");

  script_name(english:"MS00-053: Service Control Manager Named Pipe Impersonation patch (269523)");
  script_summary(english:"Determines whether the hotfix Q269523 is installed");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote host is vulnerable to privilege escalation.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The hotfix for the 'Service Control Manager Named Pipe Impersonation'
problem has not been applied.

This vulnerability allows a malicious user, who has the
right to log on this host locally, to gain additional privileges."
  );

  script_set_attribute(
    attribute:'solution',
    value:'Apply the appropriate patches from MS00-053 or apply the latest Windows service pack.'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.microsoft.com/technet/security/bulletin/ms00-053.mspx'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
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

if ( hotfix_check_sp(win2k:2) <= 0 ) exit(0);

if ( hotfix_missing(name:"Q269523") > 0 )
	 {
 set_kb_item(name:"SMB/Missing/MS00-053", value:TRUE);
 hotfix_security_hole();
 }
