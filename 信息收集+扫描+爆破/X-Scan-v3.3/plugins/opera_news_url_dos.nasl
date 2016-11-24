#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
# (C) Tenable Network Security
#
# Ref: David F. Madrid <conde0@telefonica.net>
# This script is released under the GNU GPLv2


include("compat.inc");

if(description)
{
 script_id(14249);
 script_bugtraq_id(7430);
 
 script_version("$Revision: 1.7 $");

 name["english"] = "Opera web browser news url denial of service vulnerability";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"An install browser is vulnerable to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host reportedly crashes
when processing a 'news:' URL of excessive length, that may result in
a denial of service.  It has been reported that this issue will
trigger a condition that will prevent Opera from functioning until the
program has been reinstalled." );
 script_set_attribute(attribute:"solution", value:
"Install Opera 7.20 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );


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
  (ver[0] == 7 && ver[1] < 20)
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
