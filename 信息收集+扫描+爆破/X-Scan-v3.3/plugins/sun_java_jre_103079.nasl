#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26923);
  script_version("$Revision: 1.9 $");

  script_cve_id(
    "CVE-2007-5232",
    "CVE-2007-5236",
    "CVE-2007-5237",
    "CVE-2007-5238",
    "CVE-2007-5239",
    "CVE-2007-5240",
    "CVE-2007-5273",
    "CVE-2007-5274",
    "CVE-2007-5689"
  );
  script_bugtraq_id(25918, 25920, 26185);
  script_xref(name:"OSVDB", value:"37759");
  script_xref(name:"OSVDB", value:"37760");
  script_xref(name:"OSVDB", value:"37761");
  script_xref(name:"OSVDB", value:"37762");
  script_xref(name:"OSVDB", value:"37763");
  script_xref(name:"OSVDB", value:"37764");
  script_xref(name:"OSVDB", value:"37765");
  script_xref(name:"OSVDB", value:"40834");
  script_xref(name:"OSVDB", value:"45527");

  script_name(english:"Sun Java Runtime Environment and Web Start Multiple Vulnerabilities (103072, 103073, 103078, 103079, 103112)");
  script_summary(english:"Checks version of Sun JRE"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the Sun Java Runtime Environment
(JRE) and/or Web Start installed on the remote host reportedly is
affected by several issues that could be abused to move / copy local
files, read or write local files, circumvent network access
restrictions, or elevate privileges." );
 script_set_attribute(attribute:"see_also", value:"http://conference.hitb.org/hitbsecconf2007kl/?page_id=148" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-103072-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-103073-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-103078-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-103079-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-103112-1" );
 script_set_attribute(attribute:"solution", value:
"Update to Sun JDK and JRE 6 Update 3 / JDK and JRE 5.0 Update 13 / SDK
and JRE 1.4.2_16 / SDK and JRE 1.3.1_21 or later and remove if
necessary any other affected versions." );
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
    ver =~ "^1\.6\.0_0[0-2][^0-9]?" ||
    ver =~ "^1\.5\.0_(0[0-9]|1[0-2])[^0-9]?" ||
    ver =~ "^1\.4\.([01]_|2_(0[0-9]|1[0-5][^0-9]?))" ||
    ver =~ "^1\.3\.(0_|1_([01][0-9]|20[^0-9]?))"
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
