#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35823);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-0085");
  script_bugtraq_id(34015);
  script_xref(name:"OSVDB", value:"52521");

  script_name(english: "MS09-007: Vulnerability in SChannel Could Allow Spoofing (960225)");
  script_summary(english:"Determines the presence of update 960225");

  script_set_attribute(
    attribute:"synopsis",
    value:"It may be possible to spoof user identities."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The Secure Channel (SChannel) authentication component included in the\n",
      "remote version of Windows does not sufficiently validate certain\n",
      "Transport Layer Security (TLS) handshake messages to ensure that a\n",
      "client does in fact have access to the private key linked to a\n",
      "certificate used for authentication.  An attacker who has access to\n",
      "the public key component of a user's certificate may be able to\n",
      "leverage this issue to authenticate as that user against services such\n",
      "as web servers that use certificate-based authentication or to\n",
      "impersonate that user."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Microsoft has released a set of patches for Windows 2000, XP, 2003,\n",
      "Vista and 2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-007.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");


if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:2) <= 0) exit(0);

if (is_accessible_share())
{
  if (
    # Windows Vista and Windows Server 2008
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Schannel.dll", version:"6.0.6001.22320", min_version:"6.0.6001.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Schannel.dll", version:"6.0.6001.18175", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Schannel.dll", version:"6.0.6000.20967", min_version:"6.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable(os:"6.0", sp:0, file:"Schannel.dll", version:"6.0.6000.16782", dir:"\system32") ||

    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Schannel.dll", version:"5.2.3790.4458", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.2", sp:1, file:"Schannel.dll", version:"5.2.3790.3293", dir:"\System32") ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"Schannel.dll", version:"5.1.2600.5721", dir:"\System32") ||
    hotfix_is_vulnerable(os:"5.1", sp:2, file:"Schannel.dll", version:"5.1.2600.3487", dir:"\System32") ||

    # Windows 2000
    hotfix_is_vulnerable(os:"5.0", file:"Schannel.dll", version:"5.1.2195.7213", dir:"\System32")
  ) {
    set_kb_item(name:"SMB/Missing/MS09-007", value:TRUE);
    hotfix_security_warning();
 }
 
  hotfix_check_fversion_end(); 
}
