#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18034);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2004-1774", "CVE-2005-3202", "CVE-2005-3203", "CVE-2005-4832");
  script_bugtraq_id(13145, 13144, 13139, 13238, 13236, 13235, 13234, 13239, 15031, 15033);
  script_xref(name:"OSVDB", value:"9867");
  script_xref(name:"OSVDB", value:"15553");
  script_xref(name:"OSVDB", value:"15735");
  script_xref(name:"OSVDB", value:"20051");
  script_xref(name:"OSVDB", value:"20052");
  script_xref(name:"OSVDB", value:"20053");
  script_xref(name:"IAVA", value:"2002-a-0003");
  script_xref(name:"IAVA", value:"2005-A-0011");
  script_xref(name:"IAVA", value:"2005-A-0014");
  script_xref(name:"IAVA", value:"2005-A-0012");

  script_name(english:"Oracle Database 10g Multiple Remote Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server suffers from multiple flaws." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of Oracle on the
remote host is reportedly subject to multiple vulnerabilities, some of
which don't require authentication.  They may allow an attacker to
craft SQL queries such that they would be able to retrieve any file on
the system and potentially retrieve and/or modify confidential data on
the target's Oracle server." );
 script_set_attribute(attribute:"solution", value:
"http://www.red-database-security.com/advisory/oracle_htmldb_css.html
http://www.red-database-security.com/advisory/oracle_htmldb_plaintext_password.html
http://www.oracle.com/technology/deploy/security/pdf/cpuapr2005.pdf" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for multiple remote vulnerabilities in Oracle Database");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_family(english:"Databases");
  script_dependencie("oracle_tnslsnr_version.nasl");
  script_require_ports("Services/oracle_tnslsnr");

  exit(0);
}

#broken
exit (0);

port = get_kb_item("Services/oracle_tnslsnr");
if (isnull(port)) exit(0);


version = get_kb_item(string("oracle_tnslsnr/", port, "/version"));
if (version) {
  if (ereg(pattern:".*Version (8\.(0\.|1\.([0-6]\.|7\.[0-4]))|9\.(0\.(0\.|1\.[0-5]|2\.[0-6]|3\.[0-1]|4\.[0-1])|2\.0\.[0-6])|10\.(0\.|1\.0\.[0-4])|11\.([0-4]\.|5\.[0-9][^0-9]))", string:version)) security_hole(port);
}
