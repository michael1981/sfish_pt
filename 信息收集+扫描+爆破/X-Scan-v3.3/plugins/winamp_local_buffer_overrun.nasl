#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(16199);
  script_version("$Revision: 1.5 $");
  script_bugtraq_id(10678);

  script_name(english:"Winamp < 5.0.4 Filename Handler Local Buffer Overflow");
  script_summary(english:"Determines the version of Winamp");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote application is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is using Winamp, a popular media player
which handles many files format (mp3, wavs and more...)

The remote version of this software is vulnerable to a local buffer
overrun when handling a large file name. This buffer overflow may
be exploited to execute arbitrary code on the remote host.

An attacker may exploit this flaw by sending a file with an outrageously
long file name to a victim on the remote host. When the user will attempt
to open this file using Winamp, a buffer overflow condition will occur."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to Winamp 5.0.4 or newer."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2004-03/0187.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C'
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
  script_family(english:"Windows");
  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

#

version = get_kb_item("SMB/Winamp/Version");
if ( ! version ) exit(0);

if(version =~ "^([0-4]\.|5\.0\.[0-3]\.)")
  security_hole(0);
