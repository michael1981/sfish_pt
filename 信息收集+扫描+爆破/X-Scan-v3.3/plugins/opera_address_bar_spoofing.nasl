#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# Ref: Jakob Balle
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title, output formatting (10/30/09)


include("compat.inc");

if(description)
{
 script_id(14244);
 script_version("$Revision: 1.10 $");
 script_cve_id("CVE-2004-2260");
 script_bugtraq_id(10337);
 script_xref(name:"OSVDB", value:"6108");

 script_name(english:"Opera < 7.50 onUnload Address Bar Spoofing");

 script_set_attribute(attribute:"synopsis", value:
"An installed browser is vulnerable to address bar spoofing." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Opera - an alternative web browser.

This version of Opera is vulnerable to a security weakness 
that may permit malicious web pages to spoof address bar information.

This is reportedly possible through malicious use of the 
JavaScript 'unOnload' event handler when the browser 
is redirected to another page.

This issue could be exploited to spoof the domain of a malicious web page, 
potentially causing the victim user to trust the spoofed domain." );
 script_set_attribute(attribute:"solution", value:
"Install Opera 7.50 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

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
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(get_kb_item("SMB/transport"));
}
