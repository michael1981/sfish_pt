#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31853);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2007-6681", "CVE-2008-1489");
  script_bugtraq_id(27015, 28433);
  script_xref(name:"OSVDB", value:"42207");
  script_xref(name:"OSVDB", value:"43702");

  script_name(english:"VLC Media Player < 0.8.6f Multiple Vulnerabilities");
  script_summary(english:"Checks version of VLC");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by
several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of VLC Media Player installed on the remote host
reportedly is affected by several security issues :

  - A subtitle buffer overflow (CVE-2007-6681).

  - A Real RTSP code execution problem (CVE-2008-0073).

  - MP4 integer overflows (CVE-2008-1489).

  - A cinepak integer overflow." );
 script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/developers/vlc/NEWS" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to VLC Media Player version 0.8.6f or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version");

  exit(0);
}


include("global_settings.inc");


ver = get_kb_item("SMB/VLC/Version");
if (ver && tolower(ver) =~ "^0\.([0-7]\.|8\.([0-5]|6($|[a-e])))")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "VLC Media Player version ", ver, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
