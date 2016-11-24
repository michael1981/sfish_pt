#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18503);
 script_version("$Revision: 1.10 $");

 script_cve_id("CVE-2003-1420", "CVE-2005-1475");
 script_bugtraq_id(6962, 12723, 13970, 13969, 14009);
 script_xref(name:"OSVDB", value:"17580");
 script_xref(name:"OSVDB", value:"17741");
 script_xref(name:"Secunia", value:"13253");
 script_xref(name:"Secunia", value:"15008");
 script_xref(name:"Secunia", value:"15411");
 script_xref(name:"Secunia", value:"15423");
 script_xref(name:"Secunia", value:"15488");

 script_name(english:"Opera < 8.01 Multiple Vulnerabilities");
 script_summary(english:"Determines the version of Opera.exe");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by 
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is earlier than
8.01 and thus reportedly affected by multiple issues :

  - It may be possible for a malicious web site to spoof 
    dialog boxes.

  - It may be possible for a XMLHttpRequest object to gain
    unauthorized access to sensitive data.

  - The installed version is affected by multiple cross-site
    scripting vulnerabilities.

  - When using the GET form, file path information could be 
    disclosed." );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/801/" );
 script_set_attribute(attribute:"solution", value:
"Install Opera 8.01 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );

 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
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
  ver[0] < 8 ||
  (ver[0] == 8 && ver[1] < 1)
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
