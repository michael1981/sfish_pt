#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(29998);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2008-0065");
  script_bugtraq_id(27344);
  script_xref(name:"OSVDB", value:"41707");
  script_xref(name:"Secunia", value:"27865");

  script_name(english:"Winamp < 5.52 Ultravox Streaming Metadata in_mp3.dll Multiple Tag Overflow");
  script_summary(english:"Checks the version number of Winamp"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by multiple buffer overflow vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Winamp, a popular media player for Windows. 

The version of Winamp installed on the remote Windows host reportedly
contains two stack-based buffer overflows in 'in_mp3.dll' when parsing
Ultravox streaming metadata that can be triggered by overly-long
'<artist>' and '<name>' tag values.  If an attacker can trick a user
on the affected host into opening a specially-crafted file, he may be
able to leverage this issue to execute arbitrary code on the host
subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-2/advisory/" );
 script_set_attribute(attribute:"see_also", value:"http://www.winamp.com/player/version-history" );
 script_set_attribute(attribute:"see_also", value:"http://forums.winamp.com/showthread.php?threadid=285024" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Winamp version 5.52 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

# Check version of Winamp.

#
# nb: the KB item is based on GetFileVersion, which may differ
#     from what the client reports.

version = get_kb_item("SMB/Winamp/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = split("5.5.2.1800", sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(ver); i++)
  if ((ver[i] < fix[i]))
  {
    security_hole(get_kb_item("SMB/transport"));
    break;
  }
  else if (ver[i] > fix[i])
    break;
