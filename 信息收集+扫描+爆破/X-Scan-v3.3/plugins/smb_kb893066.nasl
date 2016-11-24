#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(18028);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2005-0048", "CVE-2004-0790", "CVE-2004-1060", "CVE-2004-0230", "CVE-2005-0688");
 script_bugtraq_id(13124, 13116);
 script_xref(name:"OSVDB", value:"4030");
 script_xref(name:"OSVDB", value:"14578");
 script_xref(name:"OSVDB", value:"15457");
 script_xref(name:"OSVDB", value:"15463");
 script_xref(name:"OSVDB", value:"15619");

 script_name(english:"MS05-019: Vulnerabilities in TCP/IP Could Allow Remote Code Execution (893066) (uncredentialed check)");
 script_summary(english:"Checks for hotfix KB893066");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "Arbitrary code can be executed on the remote host due to a flaw in the\n",
   "TCP/IP stack."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "The remote host runs a version of Windows that has a flaw in its\n",
   "TCP/IP stack.\n",
   "\n",
   "The flaw may allow an attacker to execute arbitrary code with SYSTEM\n",
   "privileges on the remote host or to perform a denial of service attack\n",
   "against the remote host.\n",
   "\n",
   "Proof of concept code is available to perform a denial of service\n",
   "attack against a vulnerable system."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows 2000, XP and\n",
   "2003 :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms05-019.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("tcp_seq_window.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
 script_require_keys("TCP/seq_window_flaw", "Host/OS/smb");
 exit(0);
}

#

include("global_settings.inc");
if ( report_paranoia < 2 ) exit(0);
os = get_kb_item ("Host/OS/smb") ;
if ( ! os || "Windows" >!< os || "Windows 4.0" >< os ) exit(0);

if (get_kb_item("TCP/seq_window_flaw"))
 security_hole(port:get_kb_item("SMB/transport"));
