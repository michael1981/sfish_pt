#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(23931);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-6731", "CVE-2006-6736", "CVE-2006-6737", "CVE-2006-6745");
  script_bugtraq_id(21673, 21674, 21675);
  script_xref(name:"OSVDB", value:"32357");
  script_xref(name:"OSVDB", value:"32358");
  script_xref(name:"OSVDB", value:"32393");
  script_xref(name:"OSVDB", value:"32394");
  script_xref(name:"OSVDB", value:"32931");
  script_xref(name:"OSVDB", value:"32932");
  script_xref(name:"OSVDB", value:"32933");
  script_xref(name:"OSVDB", value:"32934");

  script_name(english:"Sun Java Runtime Environment Multiple Vulnerabilities (102729 and 102732)");
  script_summary(english:"Checks version of Sun JRE"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a version of Sun's Java Runtime
Environment that is affected by several vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the Sun JRE installed on the remote
host has two buffer overflow issues that may allow an untrusted applet
to elevate its privileges to, for example, read or write local files
or to execute local applications subject to the privileges of the user
running the applet. 

In addition, another set of vulnerabilities may allow an untrusted
applet to access data in other applets." );
 script_set_attribute(attribute:"see_also", value:"http://scary.beasts.org/security/CESA-2005-008.txt" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-102729-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-102732-1" );
 script_set_attribute(attribute:"solution", value:
"Update to Sun Java 2 JDK and JRE 5.0 Update 8 / SDK and JRE 1.4.2_13 /
SDK and JRE 1.3.1_19 or later and remove if necessary any affected
versions." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

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
    ver =~ "^1\.5\.0_0[0-7][^0-9]?" ||
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
