#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(17654);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-0701");
  script_bugtraq_id(12749);
  script_xref(name:"OSVDB", value:"14631");

  script_name(english:"Oracle 8i/9i Database Server UTL_FILE Traversal Arbitrary File Manipulation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by directory traversal flaws." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the installation of Oracle on the
remote host is reportedly subject to multiple directory traversal
vulnerabilities that may allow a remote attacker to read, write, or
rename arbitrary files with the privileges of the Oracle Database
server.  An authenticated user can craft SQL queries such that they
would be able to retrieve any file on the system and potentially
retrieve and/or modify files in the same drive as the affected
application." );
 script_set_attribute(attribute:"see_also", value:"http://www.argeniss.com/research/ARGENISS-ADV-030501.txt" );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2005-March/032273.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technology/deploy/security/pdf/cpu-jan-2005_advisory.pdf" );
 script_set_attribute(attribute:"solution", value:
"Apply the January 2005 Critical Patch Update." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P" );
script_end_attributes();

 
  script_summary(english:"Checks for multiple remote directory traversal vulnerabilities in Oracle Database 8i/9i");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
  script_family(english:"Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  script_require_ports("Services/oracle_tnslsnr");

  exit(0);
}

include('global_settings.inc');
if ( report_paranoia < 1 ) exit(0);

port = get_kb_item("Services/oracle_tnslsnr");
if (isnull(port)) exit(0);


version = get_kb_item(string("oracle_tnslsnr/", port, "/version"));
if (
  version &&
  ereg(pattern:".*Version (8\.(0\.([0-5]\.|6\.[0-3])|1\.([0-6]\.|7\.[0-4]))|9\.(0\.(0\.|1\.[0-5]|2\.[0-6]|3\.[0-1]|4\.[0-1])|2\.0\.[0-5])|10\.(0\.|1\.0\.[0-3]))", string:version)
) security_warning(port);
