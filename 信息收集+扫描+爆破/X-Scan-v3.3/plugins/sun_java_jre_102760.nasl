#
#  (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(24022);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2007-0243");
  script_bugtraq_id(22085);
  script_xref(name:"OSVDB", value:"32834");

  script_name(english:"Sun Java Runtime Environment GIF Image Handling Buffer Overflow (102760)");
  script_summary(english:"Checks version of Sun JRE"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a version of Sun's Java Runtime
Environment that is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the Sun JRE installed on the remote
host has a buffer overflow issue that can be triggered when parsing a
GIF image with the image width in an image block set to 0.  If an
attacker can trick a user on the affected system into processing a
specially-crafted image file, say by visiting a malicious web site, he
may be able to leverage this flaw to execute arbitrary code on the
affected system subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-005.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-01/0329.html" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-102760-1" );
 script_set_attribute(attribute:"solution", value:
"Update to Sun Java 2 JDK and JRE 5.0 Update 10 / SDK and JRE 1.4.2_13
/ SDK and JRE 1.3.1_19 or later and remove if necessary any affected
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
    ver =~ "^1\.5\.0_0[0-9][^0-9]?" ||
    ver =~ "^1\.4\.([01]_|2_(0[0-9]|1[0-2][^0-9]?))" ||
    ver =~ "^1\.3\.(0_|1_(0[0-9]|1[0-8][^0-9]?))"
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
