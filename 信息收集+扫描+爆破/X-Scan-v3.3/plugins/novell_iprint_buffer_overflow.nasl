#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34085);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-2436");
  script_bugtraq_id(30986);
  script_xref(name:"OSVDB", value:"47897");
  script_xref(name:"Secunia", value:"31370");

  script_name(english:"Novell iPrint Client nipplib.dll ActiveX (ienipp.ocx) IppCreateServerRef Function Overflow");
  script_summary(english:"Checks version of Novell iPrint ActiveX control");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The installed version of Novell iPrint Client is affected by a buffer
overflow vulnerability. 

By passing very long arguments to either 'GetPrinterURLList()',
'GetPrinterURLList2()', or 'GetFileList2()' functions available in
ActiveX control 'ienipp.ocx', it may be possible to cause a heap-based
buffer overflow in function 'IppCreateServerRef()' provided by
'nipplib.dll'. 

Successful exploitation of this issue may result in arbitrary code
execution on the remote system." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-33/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://download.novell.com/Download?buildid=3q-_lVDVRFI~" );
 script_set_attribute(attribute:"see_also", value:"http://download.novell.com/Download?buildid=dv_yn4TOPmQ~" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 

    - Novell iPrint Client for Vista   5.08  or  
    - Novell iPrint Client for Windows 4.38" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","os_fingerprint.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

if(!get_kb_item("SMB/WindowsVersion")) exit(0);

os = get_kb_item("Host/OS");
if(isnull(os))exit(0);

if ("Vista" >< os) os = "Vista";
else os = "Windows";

vista = FALSE;
if ( "6.0" >< get_kb_item("SMB/WindowsVersion")) vista = TRUE;

# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = "{36723F97-7AA0-11D4-8919-FF2D71D0D32C}";

file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);
  v = split(ver,sep:".",keep:FALSE); 

  if ( (ver &&  vista && activex_check_fileversion(clsid:clsid, fix:"5.0.8.0") == TRUE) ||
       (ver && !vista && activex_check_fileversion(clsid:clsid, fix:"4.3.8.0") == TRUE)	 	 
     )
   {
    report = NULL;
    if (report_paranoia > 1)
      report = string(
        "\n",
        "Version ",string(v[0],".",v[1],v[2]), " of Novell iPrint Client for ",os,"\n", 
	"is installed on the remote host.\n",
        "\n",
        "Note, though, that Nessus did not check whether the 'kill' bit was\n",
        "set for the control's CLSID because of the Report Paranoia setting\n",
        "in effect when this scan was run.\n"
      );
    else if (activex_get_killbit(clsid:clsid) != TRUE)
      report = string(
        "\n",
        "Version ",string(v[0],".",v[1],v[2]), " of Novell iPrint Client for ",os,"\n",
	"is installed on the remote host.\n",
        "\n",
        "Moreover, its 'kill' bit is not set so it is accessible via Internet\n",
        "Explorer.\n"
      );
    if (report)
    {
      if (report_verbosity) security_hole(port:kb_smb_transport(), extra:report);
      else security_hole(kb_smb_transport());
    }
  }
}
activex_end();
