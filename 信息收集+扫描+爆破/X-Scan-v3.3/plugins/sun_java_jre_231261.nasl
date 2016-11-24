#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31344);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2008-0657");
  script_bugtraq_id(27650);
  script_xref(name:"OSVDB", value:"41146");
  script_xref(name:"OSVDB", value:"41147");
  script_xref(name:"Secunia", value:"28795");

  script_name(english:"Sun Java Runtime Environment Privilege Escalation (231261)");
  script_summary(english:"Checks version of Sun JRE"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
privilege escalation vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Sun Java Runtime Environment (JRE) installed on the
remote host reportedly contains two vulnerabilities that may
independently allow an untrusted application or applet to elevate its
privileges by, for example, granting itself permission to read and
write local files or execute local applications subject to the
privileges of the user running the application or applet." );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-231261-1" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun JDK and JRE 6 Update 2 / JDK and JRE 5.0 Update 14 or
later and remove any affected versions." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");

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
    ver =~ "^1\.6\.0_0[01][^0-9]?" ||
    ver =~ "^1\.5\.0_(0[0-9]|1[0-3])[^0-9]?"
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
