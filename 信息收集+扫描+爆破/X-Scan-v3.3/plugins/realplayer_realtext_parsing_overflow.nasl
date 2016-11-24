#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18558);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-1766", "CVE-2005-2052");
  script_bugtraq_id(13530, 14048, 14073);
  script_xref(name:"OSVDB", value:"17575");
  script_xref(name:"OSVDB", value:"17576");

  name["english"] = "RealPlayer / RealOne Player for Windows Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer /
RealOne Player for Windows is prone to several vulnerabilities :

  - A malicious MP3 file can be used to overwrite an arbitrary 
    file or execute an ActiveX control.

  - Using a specially-crafted RealMedia file, an attacker may 
    be able to cause a heap overflow and run arbitrary code 
    within the context of the affected application.

  - Using a specially-crafted AVI file, an attacker may 
    be able to cause a buffer overflow and run arbitrary 
    code within the context of the affected application.

  - A malicious website may be able to cause a local HTML
    file to be created that triggers an RM file to play
    which would then reference the local HTML file." );
 script_set_attribute(attribute:"see_also", value:"http://www.idefense.com/application/poi/display?id=250&type=vulnerabilities" );
 script_set_attribute(attribute:"see_also", value:"http://research.eeye.com/html/advisories/published/AD20050623.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/403535/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://service.real.com/help/faq/security/050623_player/EN/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade according to the vendor advisory referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  summary["english"] = "Checks RealPlayer build number";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("realplayer_detect.nasl");
  script_require_keys("SMB/RealPlayer/Product", "SMB/RealPlayer/Build");

  exit(0);
}


include("global_settings.inc");


# nb: RealOne Player and RealPlayer Enterprise are also affected,
#     but we don't currently know which specific build numbers
#     address the issues.
prod = get_kb_item("SMB/RealPlayer/Product");
if (!prod || prod != "RealPlayer") exit(0);


# Check build.
build = get_kb_item("SMB/RealPlayer/Build");
if (build)
{
  # There's a problem if the build is:
  #  - [6.0.12.1040, 6.0.12.1212), RealPlayer
  ver = split(build, sep:'.', keep:FALSE);
  if (
    int(ver[0]) < 6 ||
    (
      int(ver[0]) == 6 &&
      int(ver[1]) == 0 && 
      (
        int(ver[2]) < 12 ||
        (int(ver[2]) == 12 && int(ver[3]) >= 1040 && int(ver[3]) < 1212)
      )
    )
  )
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        prod, " build ", build, " is installed on the remote host.\n"
      );
      security_hole(port:get_kb_item("SMB/transport"), extra:report);
    }
    else security_hole(get_kb_item("SMB/transport"));
  }
}
