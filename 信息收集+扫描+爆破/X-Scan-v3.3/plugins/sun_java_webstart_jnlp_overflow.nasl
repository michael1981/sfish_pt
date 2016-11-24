#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25693);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-3655");
  script_bugtraq_id(24832);
  script_xref(name:"OSVDB", value:"37756");

  script_name(english:"Sun Java Web Start JNLP File Handling Overflow (102996)");
  script_summary(english:"Checks version of Sun JRE"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that may be prone to a
buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"There is reportedly a buffer overflow in the Java Web Start utility
distributed with the version of Sun Java Runtime Environment (JRE)
installed on the remote host.  If an attacker can convince a user on
the affected host to open a specially-crafted JNLP file, he may be
able to execute arbitrary code subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://research.eeye.com/html/advisories/published/AD20070705.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/473224/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/473356/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-102996-1" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Java JDK and JRE 6 Update 2 / JDK and JRE 5.0 Update 12
or later and remove if necessary any affected versions." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
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
    ver =~ "^1\.6\.0_0[01][^0-9]?" ||
    ver =~ "^1\.5\.0_(0[0-9]|1[01])[^0-9]?"
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
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
