#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# Ref: GreyMagic Software
# This script is released under the GNU GPLv2


include("compat.inc");

if(description)
{
 script_id(14261);
 script_cve_id("CVE-2004-2570");
 script_bugtraq_id(10873);
 script_xref(name:"OSVDB", value:"8331");
 
 script_version("$Revision: 1.10 $");

 name["english"] = "Opera remote location object cross-domain scripting vulnerability";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by 
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The version of Opera on the remote host fails to block write access to
the 'location' object.  This could allow a user to create a specially
crafted URL to overwrite methods within the 'location' object that would
execute arbitrary code in a user's browser within the trust relationship
between the browser and the server, leading to a loss of confidentiality
and integrity." );
 script_set_attribute(attribute:"see_also", value:"http://www.greymagic.com/security/advisories/gm008-op/" );
 script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/754/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Opera 7.54 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 summary["english"] = "Determines the version of Opera.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
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
