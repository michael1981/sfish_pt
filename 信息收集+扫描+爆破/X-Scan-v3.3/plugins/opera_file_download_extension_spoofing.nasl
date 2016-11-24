#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# Ref: Secunia <http://www.secunia.com>
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title, output formatting (10/30/09)


include("compat.inc");

if(description)
{
 script_id(14247);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2004-2083");
 script_bugtraq_id(9640);
 script_xref(name:"OSVDB", value:"3917");

 script_name(english:"Opera < 7.50 File Download Extension Spoofing");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code might be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host contains a flaw that
may allow a malicious user to trick a user into running arbitrary
code. 

The issue is triggered when an malicious web site provides a file for
download, but crafts the filename in such a way that the file is
executed, rather than saved. 

It is possible that the flaw may allow arbitrary code execution
resulting in a loss of confidentiality, integrity, and/or
availability." );
 script_set_attribute(attribute:"solution", value:
"Install Opera 7.50 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Determines the version of Opera.exe");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
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
  (ver[0] == 7 && ver[1] < 50)
)
{
  if (report_verbosity && version_ui)
  {
    report = string(
      "\n",
      "Opera ", version_ui, " is currently installed on the remote host.\n"
    );
    security_note(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_note(get_kb_item("SMB/transport"));
}
