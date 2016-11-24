#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17637);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2005-0903");
 script_bugtraq_id(12905);
 script_xref(name:"OSVDB", value:"15295");
 
 script_name(english: "QuickTime < 6.5.2 PictureViewer Malformed JPEG Overflow (Windows)");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is using QuickTime, a popular media player/Plug-in
which handles many Media files.

The remote version of this software contains a buffer overflow vulnerability
in its PictureViewer which may allow an attacker to execute arbitrary code
on the remote host.

To exploit this vulnerability, an attacker needs to send a malformed image
file to a victim on the remote host and wait for her to open it using
QuickTime PictureViewer" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to QuickTime version 6.5.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english: "Determines the version of QuickTime Player/Plug-in");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security");
 script_family(english: "Windows");
 script_dependencies("quicktime_installed.nasl");
 script_require_keys("SMB/QuickTime/Version");

 exit(0);
}


ver = get_kb_item("SMB/QuickTime/Version");
if (ver && ver =~ "^([0-5]\.|6\.([0-4]\.|5\.[01]$))") security_hole(get_kb_item("SMB/transport"));
