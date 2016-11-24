#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25709);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2007-3716");
  script_bugtraq_id(24850);
  script_xref(name:"OSVDB", value:"36664");

  script_name(english:"Sun Java Runtime Environment XML Signature Command Injection (102993)");
  script_summary(english:"Checks version of Sun JRE"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that may allow arbitrary
command injection." );
 script_set_attribute(attribute:"description", value:
"The version of Sun Java Runtime Environment (JRE) installed on the
remote host reportedly does not securely process XSLT stylesheets
containing XSLT Transforms in XML Signatures.  If an attacker can pass
a specially-crafted XSLT stylesheet to a trusted Java application
running on the remote host, he may be able to execute arbitrary code
subject to the privileges under which the application operates." );
 script_set_attribute(attribute:"see_also", value:"http://www.isecpartners.com/advisories/2007-04-dsig.txt" );
 script_set_attribute(attribute:"see_also", value:"http://www.isecpartners.com/files/XMLDSIG_Command_Injection.pdf" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/473552/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-102993-1" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Java JDK and JRE 6 Update 2 or later and remove any
affected versions." );
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
  if (ver =~ "^1\.6\.0_0[01][^0-9]?")
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
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
