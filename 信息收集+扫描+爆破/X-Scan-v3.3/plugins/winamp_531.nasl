#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22921);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2006-5567");
  script_bugtraq_id(20744);
  script_xref(name:"OSVDB", value:"30051");
  script_xref(name:"OSVDB", value:"30052");

  script_name(english:"Winamp < 5.31 Multiple Buffer Overflows");
  script_summary(english:"Checks the version number of Winamp"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
susceptible to multiple buffer overflow attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Winamp, a popular media player for Windows. 

The version of Winamp installed on the remote Windows host reportedly
contains two overflow flaws, one involving the 'ultravox-max-msg'
header used in its support of the Ultravox protocol and the other in
its Ultravox Lyrics3 parsing code.  Using a specially-crafted stream,
a remote attacker may be able to leverage these issues to execute
arbitrary code subject to the privileges of the user." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=431" );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=432" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/449721/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/449722/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.winamp.com/player/version-history" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Winamp version 5.31 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
  script_dependencies("winamp_in_cdda_buffer_overflow.nasl");
  script_require_keys("SMB/Winamp/Version");
  exit(0);
}

# Check version of Winamp.

#
# nb: the KB item is based on GetFileVersion, which may differ
#     from what the client might report.

ver = get_kb_item("SMB/Winamp/Version");
if (ver && ver =~ "^([0-4]\.|5\.([012]\.|3\.0\.))") 
  security_hole(get_kb_item("SMB/transport"));
