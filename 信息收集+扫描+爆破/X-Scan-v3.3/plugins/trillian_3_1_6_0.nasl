#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25547);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-3305");
  script_bugtraq_id(24523);
  script_xref(name:"OSVDB", value:"37446");

  script_name(english:"Trillian < 3.1.6.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Trillian");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an instant messaging application that is
affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of Trillian installed on the remote host reportedly is
affected by a heap buffer overflow issue involving improper handling
of UTF-8 sequences when word-wrapping UTF-8 text.  A remote attacker
may be able to leverage these issues to execute arbitrary code as the
current user." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=545" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/471673/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://blog.ceruleanstudios.com/?p=150" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Trillian 3.1.6.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("trillian_installed.nasl");
  script_require_keys("SMB/Trillian/Version");

  exit(0);
}


ver = get_kb_item("SMB/Trillian/Version");
if (ver && ver =~ "^([0-2]\.|3\.(0\.|1\.[0-5]\.))")
  security_hole(get_kb_item("SMB/transport"));
