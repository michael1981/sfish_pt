#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(15996);
  script_version("$Revision: 1.5 $");
  script_bugtraq_id(12057);
  script_xref(name:"OSVDB", value:"12482");
  script_name(english:"Windows XP SP2 Firewall Critical Update (886185)");
  script_summary(english:"Checks the remote registry for KB886185");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote host has a flaw which may allow access controls to be circumvented."
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote version of Microsoft Windows XP SP2 lacks the critical security
update 886185.

This update fixes a flaw which renders the SP2 firewall ineffective when
the user connects to the internet using a dialup connection."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Apply the latest Windows XP service pack or the patch referenced in KB886185."
  );

  script_set_attribute(
    attribute:'see_also',
    value:"http://support.microsoft.com/kb/886185"
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
  script_family(english:"Windows : Microsoft Bulletins");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  exit(0);
}

include("smb_hotfixes.inc");


# Only XP SP2 affected
if ( hotfix_check_sp(xp:3) <= 0 ) exit(0);
if ( hotfix_check_sp(xp:2) > 0  ) exit(0);

if ( hotfix_missing(name:"886185") > 0 )
	security_hole(get_kb_item("SMB/transport"));
