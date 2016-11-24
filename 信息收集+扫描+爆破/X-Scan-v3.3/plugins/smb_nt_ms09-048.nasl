#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40891);
  script_version("$Revision: 1.4 $");

  script_cve_id( "CVE-2008-4609", "CVE-2009-1925", "CVE-2009-1926" );
  script_bugtraq_id(31545, 36265, 36269);
  script_xref(name:"OSVDB", value:"57795");
  script_xref(name:"OSVDB", value:"57796");
  script_xref(name:"OSVDB", value:"57797");

  script_name(english:"MS09-048: Vulnerabilities in Windows TCP/IP Could Allow Remote Code Execution (967723)");
  script_summary(english:"Checks version of tcpip.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:string(
      "Multiple vulnerabilities in the Windows TCP/IP implementation could\n",
      "lead to denial of service or remote code execution."
    )
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The TCP/IP implementation on the remote host has multiple flaws that\n",
      "could allow remote code execution if an attacker sent specially\n",
      "crafted TCP/IP packets over the network to a computer with a listening\n",
      "service. \n",
      "\n",
      "  - A denial of service vulnerability exists in TCP/IP \n",
      "    processing in Microsoft Windows due to the way that \n",
      "    Windows handles an excessive number of established TCP \n",
      "    connections. The effect of this vulnerability can be \n",
      "    amplified by the requirement to process specially \n",
      "    crafted packets with a TCP receive window size set to a \n",
      "    very small value or zero. An attacker could exploit the \n",
      "    vulnerability by flooding a system with specially \n",
      "    crafted packets causing the affected system to stop \n",
      "    responding to new requests or automatically restart. \n",
      "    (CVE-2008-4609)\n",
      "\n",
      "  - A remote code execution vulnerability exists in the \n",
      "    Windows TCP/IP stack due to the TCP/IP stack not \n",
      "    cleaning up state information correctly. This causes the\n",
      "    TCP/IP stack to reference a field as a function pointer \n",
      "    when it actually contains other information. n anonymous\n",
      "    attacker could exploit the vulnerability by sending \n",
      "    specially crafted TCP/IP packets to a computer that has\n",
      "    a service listening over the network. An attacker who \n",
      "    successfully exploited this vulnerability could take\n",
      "    complete control of an affected system. (CVE-2009-1925)\n",
      "\n",
      "  - A denial of service vulnerability exists in TCP/IP \n",
      "    processing in Microsoft Windows due to an error in the \n",
      "    processing of specially crafted packets with a small or\n",
      "    zero TCP receive window size. If an application closes a\n",
      "    TCP connection with pending data to be sent and an \n",
      "    attacker has set a small or zero TCP receive window \n",
      "    size, the affected server will not be able to \n",
      "    completely close the TCP connection. An attacker could \n",
      "    exploit the vulnerability by flooding a system with \n",
      "    specially crafted packets causing the affected system \n",
      "    to stop responding to new requests. The system would \n",
      "    remain non-responsive even after the attacker stops \n",
      "    sending malicious packets. (CVE-2009-1926)"
    )
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "Microsoft has released a set of patches for Windows 2003, Vista and\n",
      "2008 :\n",
      "\n",
      "http://www.microsoft.com/technet/security/Bulletin/MS09-048.mspx"
    )
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/08"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/08"
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


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

if (hotfix_check_sp(win2003:3, vista:3) <= 0) exit(0, "The host is not affected based on its version / service pack.");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

os = get_kb_item( "SMB/WindowsVersion" );

if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"tcpip.sys", version:"6.0.6002.22200", min_version:"6.0.6002.20000", dir:"\System32\drivers") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"tcpip.sys", version:"6.0.6002.18091",                               dir:"\System32\drivers") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"tcpip.sys", version:"6.0.6001.22497", min_version:"6.0.6001.20000", dir:"\System32\drivers") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"tcpip.sys", version:"6.0.6001.18311",                               dir:"\System32\drivers") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"tcpip.sys", version:"6.0.6000.21108", min_version:"6.0.6000.20000", dir:"\System32\drivers") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"tcpip.sys", version:"6.0.6000.16908",                               dir:"\System32\drivers") ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"tcpip.sys", version:"5.2.3790.4573", dir:"\System32\drivers")

)
{
  set_kb_item(name:"SMB/Missing/MS09-048", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}
