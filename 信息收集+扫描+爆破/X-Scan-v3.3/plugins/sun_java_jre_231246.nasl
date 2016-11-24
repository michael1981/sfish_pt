#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30149);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2008-0628");
  script_bugtraq_id(27553);
  script_xref(name:"OSVDB", value:"40931");

  script_name(english:"Sun Java Runtime Environment External XML Entities Restriction Bypass (231246)");
  script_summary(english:"Checks version of Sun JRE"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
security bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the Sun Java Runtime Environment
(JRE) installed on the remote host reportedly allows processing of
external entity references even when the 'external general entities'
property is set to 'FALSE'.  This could allow an application to access
certain URL resources, such as files or web pages, or to launch a
denial of service attack against the system. 

Note that successful exploitation requires that specially-crafted XML
data be processed by a trusted application rather than by an untrusted
applet or Java Web Start application." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2008-02/0007.html" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-231246-1" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun JDK and JRE 6 Update 4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:P" );
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
  if (ver =~ "^1\.6\.0_0[0-3][^0-9]?")
    info += '  - ' + ver + ', under ' + installs[install] + '\n';
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
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
