#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15926);
 script_bugtraq_id(11757);
 script_version("$Revision: 1.8 $");

 script_name(english:"Sun Java Applet Invocation Version Specification");
 script_summary(english:"Checks for older versions of the Java SDK and JRE");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "The remote Windows host contains a runtime environment that is\n",
     "affected by multiple vulnerabilities."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote version of Windows contains a version of the Java JRE\n",
     "which is older than 1.4.2_06 / 1.3.1_13.\n\n",
     "Even if a newer version of this software is installed, a malicious\n",
     "Java applet may invoke a particular version of the Java JRE to be\n",
     "executed with.\n\n",
     "As a result, a rogue Java applet could exploit this vulnerability by\n",
     "requesting to be executed with an older, vulnerable version of the JRE."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.securityfocus.com/archive/1/382281"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.securityfocus.com/archive/1/382413"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-102557-1"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Uninstall any outdated versions of the JRE."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");

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
  if (ver =~ "^(0\.|1\.[0-2]\.|1\.3\.0|1\.3\.1_([0-9]$|1[0-2]$)|1\.4\.([01]|2_0[0-5]))")
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
