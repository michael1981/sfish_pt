#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14346);
 script_cve_id("CVE-2004-1490");
 script_bugtraq_id(10961, 11883);
 
 script_version("$Revision: 1.11 $");

 name["english"] = "Opera Resource Detection"; 

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Opera on the remote host contains a flaw that allows an
attacker to determine the existence of files and directories on the
remote host. 

To exploit this flaw, an attacker would need to set up a rogue website
and lure a user of the remote host into visiting it with Opera." );
 script_set_attribute(attribute:"see_also", value:"http://www.greymagic.com/security/advisories/gm008-op/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/754/" );
 script_set_attribute(attribute:"solution", value:
"Install Opera 7.54 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );


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
  (ver[0] == 7 && ver[1] < 54)
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
