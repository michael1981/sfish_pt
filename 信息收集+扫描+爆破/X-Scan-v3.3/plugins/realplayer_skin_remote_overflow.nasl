#
#  (C) Tenable Network Security
#
#


include("compat.inc");

if(description)
{
 script_id(15789);
 script_version("$Revision: 1.12 $");

 script_cve_id("CVE-2004-1094");
 script_bugtraq_id(11555);
 script_xref(name:"OSVDB", value:"19906");
 
 name["english"] = "RealPlayer Skin File Remote Buffer Overflow";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by a remote buffer
overflow." );
 script_set_attribute(attribute:"description", value:
"According to its build number, the installed version of RealPlayer /
RealOne Player for Windows may allow an attacker to execute arbitrary
code on the remote host, with the privileges of the user running
RealPlayer because of an overflow vulnerability in the third-party
compression library 'DUNZIP32.DLL'. 

To do so, an attacker would need to send a corrupted skin file (.RJS)
to a remote user and have him open it using RealPlayer." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-10/1044.html" );
 script_set_attribute(attribute:"see_also", value:"http://service.real.com/help/faq/security/041026_player/EN/" );
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


# nb: RealOne Player is also affected, but we don't currently know 
#     which specific build number addresses the issue.
prod = get_kb_item("SMB/RealPlayer/Product");
if (!prod || prod != "RealPlayer") exit(0);


# Check build.
build = get_kb_item("SMB/RealPlayer/Build");
if (build)
{
  # There's a problem if the build is:
  #  - [6.0.12.0, 6.0.12.1056), Real Player
  ver = split(build, sep:'.', keep:FALSE);
  if (
    int(ver[0]) < 6 ||
    (
      int(ver[0]) == 6 &&
      int(ver[1]) == 0 &&
      (
        int(ver[2]) < 12 ||
        (int(ver[2]) == 12 && int(ver[3]) < 1056)
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
