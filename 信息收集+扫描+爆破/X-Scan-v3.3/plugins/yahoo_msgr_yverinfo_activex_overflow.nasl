#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25955);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-4515");
  script_bugtraq_id(25494);
  script_xref(name:"OSVDB", value:"37739");

  script_name(english:"Yahoo! Messenger YVerInfo ActiveX Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks version of YVerInfo ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the 'YVerInfo' ActiveX control, distributed
as part of the Yahoo! services suite typically downloaded with the
installer for Yahoo! Messenger. 

The version of this control installed on the remote host reportedly
contains buffer overflows involving its 'fvCom' and 'info' methods. 
If an attacker can trick a user on the affected host into visiting a
specially-crafted web page, he may be able to leverage this issue to
execute arbitrary code on the host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=591" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/478167/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://messenger.yahoo.com/security_update.php?id=082907" );
 script_set_attribute(attribute:"solution", value:
"Either disable the use of this ActiveX control from within Internet
Explorer by setting its 'kill' bit or upgrade to Yahoo! Messenger
version 8.1.0.419 (version 2007.8.27.1 of the YVerInfo control itself)
or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

# nb: iDefense talks about D5184A39-CBDF-4A4F-AC1A-7A45A852C883 while
#     Yahoo's advisory uses 64AA7031-C150-4118-8D31-FD273A2BB22C.
clsid = "{64AA7031-C150-4118-8D31-FD273A2BB22C}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  # Check its version.
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"2007.8.27.1") == TRUE)
  {
    report = NULL;
    if (report_paranoia > 1)
      report = string(
        "Version ", ver, " of the vulnerable control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Note, though, that Nessus did not check whether the 'kill' bit was\n",
        "set for the control's CLSID because of the Report Paranoia setting\n",
        "in effect when this scan was run.\n"
      );
    else if (activex_get_killbit(clsid:clsid) != TRUE)
      report = string(
        "Version ", ver, " of the vulnerable control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Moreover, its 'kill' bit is not set so it is accessible via\n",
        "Internet Explorer."
      );
    if (report) security_hole(port:kb_smb_transport(), extra: report);
  }
}
activex_end();
