#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(25166);
 script_version("$Revision: 1.13 $");

 script_cve_id(
  "CVE-2007-0323",
  "CVE-2007-0942",
  "CVE-2007-0944",
  "CVE-2007-0945",
  "CVE-2007-0946",
  "CVE-2007-0947",
  "CVE-2007-2221"
 );
 script_bugtraq_id(23331, 23769, 23770, 23771, 23772, 23827);
 script_xref(name:"OSVDB", value:"34399");
 script_xref(name:"OSVDB", value:"34400");
 script_xref(name:"OSVDB", value:"34401");
 script_xref(name:"OSVDB", value:"34402");
 script_xref(name:"OSVDB", value:"34403");
 script_xref(name:"OSVDB", value:"34404");
 script_xref(name:"OSVDB", value:"35873");

 script_name(english:"MS07-027: Cumulative Security Update for Internet Explorer (931768)");
 script_summary(english:"Determines the presence of update 931768");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web client." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing the IE cumulative security update 931768.

The remote version of IE is vulnerable to several flaws which may allow an 
attacker to execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003
and Vista :

http://www.microsoft.com/technet/security/Bulletin/MS07-027.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}



include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if ( hotfix_check_sp(xp:3, win2003:3, win2k:6, vista:1) <= 0 ) exit(0);

if (activex_init() != ACX_OK) exit(1, "Could not initialize the ActiveX checks.");

# Check for controls for which the killbit was set.
#
# nb: we'll collect info about missing killbits now but report 
#     them later, if Mshtml.dll appears to have been patched.
info = "";

clsids = make_list(
  "{1D95A7C7-3282-4DB7-9A48-7C39CE152A19}",
  "{D9998BD0-7957-11D2-8FED-00606730D3AA}"
);

foreach clsid (clsids)
{
  if (activex_get_killbit(clsid:clsid) != TRUE)
  {
    info += '  ' + clsid + '\n';
    if (!thorough_tests) break;
  }
}
activex_end();


# Check for patched Mshtml.dll.
if (is_accessible_share())
{
  if (
    hotfix_is_vulnerable (os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.2885", dir:"\system32") ||
    hotfix_is_vulnerable (os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4026", dir:"\system32") ||
    hotfix_is_vulnerable (os:"5.2", file:"Mshtml.dll", version:"7.0.6000.16441", min_version:"7.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable (os:"5.2", file:"Mshtml.dll", version:"7.0.6000.20544", min_version:"7.0.6000.20000", dir:"\system32") ||
    hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2800.1593", dir:"\system32") ||
    hotfix_is_vulnerable (os:"5.1", sp:2, file:"Mshtml.dll", version:"7.0.6000.16441", min_version:"7.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1593", min_version:"6.0.0.0", dir:"\system32") ||
    hotfix_is_vulnerable (os:"5.0", file:"Mshtml.dll", version:"5.0.3850.1900", dir:"\system32")
  )
  {
    set_kb_item(name:"SMB/Missing/MS07-027", value:TRUE);
    hotfix_security_hole();
    hotfix_check_fversion_end(); 
    exit (0);
  }
}
hotfix_check_fversion_end(); 


# Report if any of the killbits are unset.
if (info)
{
  set_kb_item(name:"SMB/Missing/MS07-027", value:TRUE);

  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 1) s = "s";
    else s = "";

    report = string(
      "\n",
      "The killbit has not been set for the following control", s, " :\n",
      "\n",
      info
    );

    if (!thorough_tests)
    {
      report = string(
        report,
        "\n",
        "Note that Nessus did not check whether there were other killbits\n",
        "that have not been set because 'Thorough Tests' was not enabled\n",
        "when this scan was run.\n"
      );
    }
    security_hole(port:kb_smb_transport(), extra:report);
  }
  else security_hole(kb_smb_transport());

  exit(0);
}


exit(0, "The host is not affected.");
