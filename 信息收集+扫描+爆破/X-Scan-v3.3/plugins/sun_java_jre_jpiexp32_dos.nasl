#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30148);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-0012");
  script_bugtraq_id(27185);
  script_xref(name:"OSVDB", value:"43435");

  script_name(english:"Sun Java Runtime Environment jpiexp32.dll DoS");
  script_summary(english:"Checks version of Sun JRE"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is prone to a denial
of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the Sun Java Runtime Environment
(JRE) installed on the remote host reportedly contains an issue in
'jpiexp32.dll' that can lead to a null pointer exception when an HTML
object references a Java applet but does not define the 'name'
attribute.  If a remote attacker can trick a user on the affected host
into visiting a specially-crafted web page, he may be able to leverage
this issue to cause the JRE and Internet Explorer to crash." );
 script_set_attribute(attribute:"see_also", value:"http://research.corsaire.com/advisories/c060905-002.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/485942/100/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Java 2 JDK and JRE 5.0 update 14 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P" );
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
  if (ver =~ "^1\.5\.0_(0[0-9]|1[0-3])[^0-9]?")
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
