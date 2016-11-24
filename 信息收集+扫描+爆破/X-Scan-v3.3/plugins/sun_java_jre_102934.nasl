#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25370);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2007-2788", "CVE-2007-2789");
  script_bugtraq_id(24004);
  script_xref(name:"OSVDB", value:"36199");
  script_xref(name:"OSVDB", value:"36200");

  script_name(english:"Sun Java Runtime Environment Image Parsing Vulnerabilities (102934)");
  script_summary(english:"Checks version of Sun JRE"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by several
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the Sun Java Runtime Environment
(JRE) installed on the remote host reportedly is affected by a buffer
overflow in its image processing code as well as another issue that
may cause the Java Virtual Machine to hang." );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-102934-1" );
 script_set_attribute(attribute:"solution", value:
"Update to Sun Java JDK and JRE 6 Update 1 / JDK and JRE 5.0 Update 11
/ SDK and JRE 1.3.1_20 or later and remove if necessary any affected
versions." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}


include("global_settings.inc");


# Check each installed JRE.
installs = get_kb_list("SMB/Java/JRE/*");
if (isnull(installs)) exit(0);

info = "";
foreach install (keys(installs))
{
  ver = install - "SMB/Java/JRE/";
  if (
    ver =~ "^1\.6\.0_00" ||
    ver =~ "^1\.5\.0_(0[0-9]|10)[^0-9]?" ||
    ver =~ "^1\.4\.([01]_|2_(0[0-9]|1[0-4][^0-9]?))" ||
    ver =~ "^1\.3\.(0_|1_[01][0-9])"
  ) info += '  - ' + ver + ', under ' + installs[install] + '\n';
}


# Report if any were found to be vulnerable.
if (info)
{
  if (report_verbosity)
  {
    if (max_index(split(info)) > 1) s = "s of Sun's JRE are";
    else s = " of Sun's JRE is";

    report = string(
      "\n",
      "The following vulnerable instance", s, " installed on the\n",
      "remote host :\n",
      "\n",
      info
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
