#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10835);
 script_version("$Revision: 1.18 $");

 script_cve_id("CVE-2001-0876", "CVE-2001-0877");
 script_bugtraq_id(3723);
 script_xref(name:"OSVDB", value:"692");
 script_xref(name:"OSVDB", value:"697");

 script_name(english:"MS01-059: Unchecked Buffer in Universal Plug and Play can Lead to System Compromise");
 script_summary(english:"Determines the presence of hotfix Q315000");
 
 script_set_attribute(
  attribute:"synopsis",
  value:string(
   "The Universal Plug and Play service on the remote host is prone to\n",
   "denial of service and buffer overflow attacks."
  )
 );
 script_set_attribute(
  attribute:"description", 
  value:string(
   "Using a specially-crafted NOTIFY directive, a remote attacker can\n",
   "cause code to run in the context of the Universal Plug and Play (UPnP)\n",
   "subsystem or possibly launch a denial of service attack against the\n",
   "affected host.\n",
   "\n",
   "Note that, under Windows XP, the UPnP subsystem operates with SYSTEM\n",
   "privileges."
  )
 );
 script_set_attribute(
  attribute:"solution", 
  value:string(
   "Microsoft has released a set of patches for Windows 98, 98SE, ME, and\n",
   "XP :\n",
   "\n",
   "http://www.microsoft.com/technet/security/bulletin/ms01-059.mspx"
  )
 );
 script_set_attribute(
  attribute:"cvss_vector", 
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");


if ( hotfix_check_sp(xp:1) <= 0 ) exit(0);

if ( hotfix_missing(name:"315000") > 0  )
  security_hole(kb_smb_transport());
