#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(18480);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2005-1973", "CVE-2005-1974");
 script_bugtraq_id(13958, 13945);
 script_xref(name:"IAVA", value:"2005-t-0024");
 script_xref(name:"OSVDB", value:"17299");
 script_xref(name:"OSVDB", value:"17340");
 script_xref(name:"Secunia", value:"15671");

 script_name(english:"Sun JRE Java Plug-in JavaScript Security Restriction Bypass (2)");
 script_summary(english:"Determines the version of Java JRE plugin");
 
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
     "The remote host is using a vulnerable version of Sun Java Runtime\n",
     "Plug-in, an web browser addon used to display Java applets.\n\n",
     "It has been reported that the JRE Plug-in Security can be bypassed.\n",
     "A remote attacker could exploit this by tricking a user into viewing\n",
     "a maliciously crafted web page.\n\n",
     "Additionally, a denial of service vulnerability is present in this\n",
     "version of the JVM.  This issue is triggered by viewing an applet\n",
     "that misuses the serialization API."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-101749-1"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to JRE 1.4.2_08 / 1.5.0 update 2 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 
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
    ver =~ "^1\.4\.([01]_|2_0*[0-7][^0-9])" ||
    ver =~ "^1\.5\.0_0*[01][^0-9]"
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
