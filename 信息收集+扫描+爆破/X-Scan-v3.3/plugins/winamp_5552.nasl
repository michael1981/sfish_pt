#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38858);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2009-1831");
  script_bugtraq_id(35052);
  script_xref(name:"OSVDB", value:"54902");

  script_name(english:"Winamp < 5.552 Modern Skins Support Module (gen_ff.dll) MAKI File Handling Overflow");
  script_summary(english:"Checks the version number of Winamp");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
affected by an integer overflow vulnerability." );

  script_set_attribute(attribute:"description", value:
"The remote host is running Winamp, a media player for Windows.

The version of Winamp installed on the remote host is earlier than
5.552. Such versions are reportedly affected by an integer overflow 
vulnerability when processing '.maki' files. An attacker
could exploit this to execute arbitrary code in the context of the
affected application.");
  script_set_attribute(attribute:"see_also", value:
"http://vrt-sourcefire.blogspot.com/2009/05/winamp-maki-parsing-vulnerability.html");
  script_set_attribute(attribute:"see_also", value:
"http://forums.winamp.com/showthread.php?threadid=303193#notes9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Winamp version 5.552 or later.");
  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

# Check version of Winamp.

#
# nb : the KB item is based on GetFileVersion, which may differ
#      from what the client reports.

version = get_kb_item("SMB/Winamp/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = split("5.5.5.2435", sep:'.', keep:FALSE);
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
