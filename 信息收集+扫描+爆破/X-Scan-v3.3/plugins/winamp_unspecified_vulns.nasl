#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(16152);
  script_version("$Revision: 1.12 $");
  script_cve_id("CVE-2004-1150");
  script_bugtraq_id(12245, 12381);
  script_xref(name:"OSVDB", value:"12858");
  script_xref(name:"OSVDB", value:"12922");
  script_xref(name:"OSVDB", value:"12923");
  script_xref(name:"OSVDB", value:"12924");

  script_name(english:"Winamp < 5.0.8c Multiple Unspecified Vulnerabilities");

  script_set_attribute(
    attribute:'synopsis',
    value:'The version of Winamp on the remote host is vulnerable to multiple vulnerabilities.'
  );

  script_set_attribute(
    attribute:'description',
    value:
"The remote host is using Winamp, a popular media player which handles
many file formats (mp3, wavs and more...). 

The remote version of this software has various unspecified
vulnerabilities that may allow an attacker to execute arbitrary code
on the remote host. 

An attacker may exploit these flaws by sending malformed files to a
victim on the remote host."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Upgrade to Winamp 5.0.8c or newer."
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://marc.info/?l=bugtraq&m=110684140108614&w=2'
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P'
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

if(version =~ "^([0-4]\.|5\.0\.[0-8]\.)")
  security_warning(get_kb_item("SMB/transport"));
