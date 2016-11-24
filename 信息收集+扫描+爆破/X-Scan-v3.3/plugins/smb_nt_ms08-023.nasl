#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(31796);
 script_version("$Revision: 1.6 $");

 script_cve_id("CVE-2008-1086");
 script_bugtraq_id(28606);
 script_xref(name:"OSVDB", value:"44171");

 name["english"] = "MS08-023: Security Update of ActiveX Kill Bits (948881)";


 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the hxvz.dll ActiveX control.

The version of this control installed on the remote host reportedly
contains multiple stack buffer overflows.  If an attacker can trick a
user on the affected host into visiting a specially-crafted web page,
he may be able to leverage this issue to execute arbitrary code on the
host subject to the user's privileges." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008 :

http://www.microsoft.com/technet/security/bulletin/ms08-023.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Determines if hxvz.dll kill bit is set";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsids = make_list(
"{314111b8-a502-11d2-bbca-00c04f8ec294}",
"{314111c6-a502-11d2-bbca-00c04f8ec294}"

);

foreach clsid (clsids)
{
  if (
    activex_is_installed(clsid:clsid) == TRUE &&
    activex_get_killbit(clsid:clsid) != TRUE
  )
  {
 {
 set_kb_item(name:"SMB/Missing/MS08-023", value:TRUE);
 security_hole(port:kb_smb_transport());
 }
   break;
  }
}

activex_end();
