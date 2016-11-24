#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25956);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-2498");
  script_bugtraq_id(23723);
  script_xref(name:"OSVDB", value:"34433");

  script_name(english:"Winamp < 5.35 MP4 File Handling Buffer Overflow");
  script_summary(english:"Checks the version number of Winamp"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Winamp, a popular media player for Windows. 

The version of Winamp installed on the remote Windows host reportedly
contains a flaw involving its handling of 'MP4' files.  If an attacker
can trick a user on the affected host into opening a specially-crafted
MP4 file, he may be able to leverage this issue to execute arbitrary
code on the host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://milw0rm.com/exploits/3823" );
 script_set_attribute(attribute:"see_also", value:"http://www.winamp.com/player/version-history" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Winamp version 5.35 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

#

include("global_settings.inc");


# Nullsoft issued a patch for 5.34 that we can't detect so we only
# run the check if reporting is paranoid.

if (report_paranoia < 2) exit(0);


# Check version of Winamp.

#
# nb: the KB item is based on GetFileVersion, which may differ
#     from what the client reports.

ver = get_kb_item("SMB/Winamp/Version");
if (ver && ver =~ "^([0-4]\.|5\.([0-2]\.|3\.[0-4]\.))") 
  security_hole(get_kb_item("SMB/transport"));
