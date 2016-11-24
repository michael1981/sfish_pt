#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15395);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2004-1481", "CVE-2005-0189", "CVE-2005-0190", "CVE-2005-0192");
 script_bugtraq_id(11307, 11308, 11309, 11335, 12311, 12315);
 script_xref(name:"OSVDB", value:"10418");
 script_xref(name:"OSVDB", value:"10419");
 script_xref(name:"OSVDB", value:"13938");
 script_xref(name:"OSVDB", value:"15442");

 name["english"] = "RealPlayer Remote Vulnerabilities";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by multiple remote
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer /
RealOne Player for Windows may allow an attacker to execute arbitrary
code and delete arbitrary files on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.service.real.com/help/faq/security/040928_player/EN/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade according to the vendor advisory referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks RealPlayer build number";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
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
  #  - [6.0.12.0, 6.0.12.1053), RealPlayer 10.5
  ver = split(build, sep:'.', keep:FALSE);
  if (
    int(ver[0]) < 6 ||
    (
      int(ver[0]) == 6 &&
      int(ver[1]) == 0 &&
      (
        int(ver[2]) < 12 ||
        (int(ver[2]) == 12 && int(ver[3]) < 1053)
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
