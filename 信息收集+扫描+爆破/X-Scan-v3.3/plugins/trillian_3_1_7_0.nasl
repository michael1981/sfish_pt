#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25757);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2007-3832", "CVE-2007-3833");
  script_bugtraq_id(24927);
  script_xref(name:"OSVDB", value:"38170");
  script_xref(name:"OSVDB", value:"38171");

  script_name(english:"Trillian aim:// URI Handler Vulnerabilities");
  script_summary(english:"Checks version number of Trillian");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an instant messaging application that is
affected by two vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Trillian installed on the remote host contains a buffer
overflow in its AIM protocol URI handler in 'aim.dll' and also allows
creation of arbitrary files with arbitrary content using specially-
crafted 'aim://'' URIs.  A remote attacker may be able to leverage
these issues to execute arbitrary code as the current user." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f055f2d5" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2007-07/0297.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/786920" );
 script_set_attribute(attribute:"see_also", value:"http://blog.ceruleanstudios.com/?p=170" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Trillian 3.1.7.0 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("trillian_installed.nasl");
  script_require_keys("SMB/Trillian/Version");

  exit(0);
}


ver = get_kb_item("SMB/Trillian/Version");
if (ver && ver =~ "^([0-2]\.|3\.(0\.|1\.[0-6]\.))")
  security_hole(get_kb_item("SMB/transport"));
