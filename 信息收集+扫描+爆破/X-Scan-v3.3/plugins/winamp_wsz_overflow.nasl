#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(16204);
  script_version("$Revision: 1.6 $");
  script_cve_id("CVE-2004-0820");
  script_bugtraq_id(11053);
  script_xref(name:"OSVDB", value:"9195");

  script_name(english:"Winamp < 5.0.5 Skin File (.WSZ) Local Zone Arbitrary Code Execution");

  script_set_attribute(
    attribute:'synopsis',
    value:'The version of Winamp on the remote host is vulnerable to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is using Winamp, a popular media player
which handles many files format (mp3, wavs and more...)

The remote version of this software is vulnerable to a code execution
flaw when processing a malformed .WSZ Winamp Skin file.

An attacker may exploit this flaw by sending a malformed .wsz file
to a victim on the remote host, and wait for him to load it within
Winamp."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to Winamp 5.0.5 or newer"
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.securityfocus.com/archive/1/373146'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C'
  );

  script_end_attributes();

  script_summary(english:"Determines the version of Winamp");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_family(english:"Windows");
  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

#

version = get_kb_item("SMB/Winamp/Version");
if ( ! version ) exit(0);

if(version =~ "^([0-4]\.|5\.0\.[0-4]\.)")
  security_hole(get_kb_item("SMB/transport"));
