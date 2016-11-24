#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18205);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2005-1495");
  script_bugtraq_id(13510);
  script_xref(name:"OSVDB", value:"16258");

  script_name(english:"Oracle Database 9i/10g Fine Grained Auditing (FGA) SELECT Statement Logging Weakness");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server may allow logging to be disabled." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Oracle Database that,
according to its version number, suffers from a flaw in which Fine
Grained Auditing (FGA) becomes disabled when the user SYS runs a
SELECT statement." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b7e6e40" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-05/0044.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the 10.1.0.4 patch set for Oracle 10g." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N" );
script_end_attributes();

 
  script_summary(english:"Checks for fine grained audit logging failure vulnerability in Oracle Database 9i/10g");
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


ver = get_kb_item(string("oracle_tnslsnr/", port, "/version"));
if (ver) {
  if (
    ver =~ ".*Version (5\.0\.0\.([012]\.0\.0|2\.9\.0))" ||
    ver =~ ".*Version 8\.1\.7" ||
    ver =~ ".*Version 9\.(0\.([0124][^0-9]?|1\.[2-5]|4\.0)|2\.0\.0(\.[1-6])?)" ||
    ver =~ ".*Version 10\.1\.0\.0\.([2-4][^0-9]?|3\.1)"
  ) security_note(port);
}
