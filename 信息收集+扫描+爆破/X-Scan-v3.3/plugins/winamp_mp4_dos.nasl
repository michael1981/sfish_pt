#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(15952);
  script_version("$Revision: 1.11 $");
  script_cve_id("CVE-2004-1396");
  script_bugtraq_id(11909);
  script_xref(name:"OSVDB", value:"12491");

  script_name(english:"Winamp < 5.0.7 Multiple File Handling DoS");
  script_summary(english:"Determines the version of Winamp");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote host is vulnerable to denial of service attacks.'
  );

  script_set_attribute(
    attribute:'description',
    value:
"The remote host is using Winamp, a popular media player that handles
many file formats (mp3, wavs and more...)

The remote version of this software is vulnerable to denial of service
attacks when it processes malformed .mp4 / .m4a or .nsv / .nsa files. 

An attacker may exploit this flaw by sending malformed files to a
victim on the remote host. "
  );

  script_set_attribute(
    attribute:'solution',
    value: "Upgrade to Winamp version 5.0.7 or later."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/bugtraq/2004-12/0120.html'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P'
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

if(version =~ "^([0-4]\.|5\.0\.[0-7]\.)")
  security_note(get_kb_item("SMB/transport"));
