#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14336);
 script_version("$Revision: 1.9 $");

 script_bugtraq_id(10997);
 script_xref(name:"OSVDB", value:"9154");
 
 script_name(english:"Opera getElementsByTagName JavaScript Method DoS");
 script_summary(english:"Determines the version of Opera.exe");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a denial of
service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is vulnerable to a
remote denial of service.  An attacker may cause the browser to crash
by crafting a rogue HTML page containing a specific JavaScript
command." );
 script_set_attribute(attribute:"solution", value:
"Install Opera 7.24 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P" );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("opera_installed.nasl");
 script_require_keys("SMB/Opera/Version");
 exit(0);
}

#

include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 7 ||
  (ver[0] == 7 && ver[1] < 24)
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
