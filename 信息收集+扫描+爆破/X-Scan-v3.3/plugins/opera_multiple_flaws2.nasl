#
# This script was written by Renaud Deraison
#
# See the Nessus Scripts License for details
#
#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if(description)
{
 script_id(13844);
 script_bugtraq_id(10679, 10763, 10764);
 script_xref(name:"Secunia", value:"12028");
 
 script_version("$Revision: 1.9 $");

 name["english"] = "Opera < 7.53 Multiple Vulnerabilities";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by 
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is 
vulnerable to two security issues :

  - A cross domain frame loading vulnerability.
  - An unspecified vulnerability in the way it handles
    certificates.

An attacker may exploit one of these flaws to impersonate 
a web server." );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/753/" );
 script_set_attribute(attribute:"solution", value:
"Install Opera 7.53 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Determines the version of Opera.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("opera_installed.nasl");
 script_require_keys("SMB/Opera/Version");

 exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 7 ||
  (ver[0] == 7 && ver[1] < 53)
)
{
  if (report_verbosity && version_ui)
  {
    report = string(
      "\n",
      "Opera ", version_ui, " is currently installed on the remote host.\n"
    );
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
