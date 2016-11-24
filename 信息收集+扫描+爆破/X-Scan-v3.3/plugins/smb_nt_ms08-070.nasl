#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(35069);
 script_version("$Revision: 1.10 $");

 script_cve_id(
  "CVE-2008-4252",
  "CVE-2008-4253",
  "CVE-2008-4254",
  "CVE-2008-4255",
  "CVE-2008-4256",
  "CVE-2008-3704"
 );
 script_bugtraq_id(30674, 32591, 32592, 32612, 32613, 32614);
 script_xref(name:"OSVDB", value:"47475");
 script_xref(name:"OSVDB", value:"50577");
 script_xref(name:"OSVDB", value:"50578");
 script_xref(name:"OSVDB", value:"50579");
 script_xref(name:"OSVDB", value:"50580");
 script_xref(name:"OSVDB", value:"50581");

 script_name(english: "MS08-070: Vulnerabilities in Visual Basic 6.0 ActiveX Controls Could Allow Remote Code Execution (932349)");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web client." );
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the ActiveX control for Visual
Basic 6.0 Runtime Extended Files that may allow an attacker to execute
arbitrary code on the remote host by constructing a malicious web page
and enticing a victim to visit it. 

Note that this control may have been included with Visual Studio or
FoxPro or as part of a third-party application created by one of those
products." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office /
Frontpage / FoxPro / Studio :

http://www.microsoft.com/technet/security/bulletin/ms08-070.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Determines the presence of update 932349";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows : Microsoft Bulletins";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_activex_func.inc");

if (activex_init() != ACX_OK) exit(1, "Could not initialize the ActiveX checks");

info = "";

vers = make_array();

clsids = make_list(
  "{1E216240-1B7D-11CF-9D53-00AA003C9CB6}", # Mscomct2.ocx
  "{3A2B370C-BA0A-11d1-B137-0000F8753F5D}", # Mschrt20.ocx
  "{B09DE715-87C1-11d1-8BE3-0000F8754DA1}", # Mscomct2.ocx
  "{cde57a43-8b86-11d0-b3c6-00a0c90aea82}", # Msdatgrd.ocx
  "{6262d3a0-531b-11cf-91f6-c2863c385e30}", # Msflxgrd.ocx
  "{0ECD9B64-23AA-11d0-B351-00A0C9055D8E}", # Mshflxgd.ocx
  "{C932BA85-4374-101B-A56C-00AA003668DC}", # Msmask32.ocx
  "{248dd896-bb45-11cf-9abc-0080c7e7b78d}"  # Mswinsck.ocx
 );

foreach clsid (clsids)
{ 
  file = activex_get_filename(clsid:clsid);

  if(file)
  {
    file = tolower(file);
    if ("msflxgrd.ocx" >< file) fix = "6.1.98.6"; 
    else if ("mscomct2.ocx" >< file) fix = "6.1.98.11";
    else fix = "6.1.98.12";

    if(isnull(vers[clsid]))
      vers[clsid] = activex_get_fileversion(clsid:clsid);

    if (vers[clsid] && activex_check_fileversion(clsid:clsid, fix:fix) == TRUE )
    { 
      if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) != TRUE )
      {
        info += string(
            "\n",
            "  Class Identifier   : ", clsid, "\n",
            "  Filename           : ", file, "\n",
            "  Installed version  : ", vers[clsid], "\n",
            "  Fix                : ",fix,"\n"
          );

        if (!thorough_tests) break;
      }  
    }
  }
}
activex_end();

if (info != "")
{
  set_kb_item(name:"SMB/Missing/MS08-070", value:TRUE);

  if (report_paranoia > 1)
  {
    report = string(
      "\n",
      "Nessus found the following affected control(s) installed :\n",
      "\n",
      info,
      "\n",
      "Note that Nessus did not check whether the 'kill' bit was set for\n",
      "the control(s) because of the Report Paranoia setting in effect\n",
      "when this scan was run.\n"
      );
  }
  else
  {
    report = string(
      "\n",
      "Nessus found the following affected control(s) installed :\n",
      "\n",
      info,
      "\n",
      "Moreover, the 'kill' bit was  not set for the control(s) so they\n",
      "are accessible via Internet Explorer.\n"
      );
  }
  security_hole(port:kb_smb_transport(), extra:report);
}
