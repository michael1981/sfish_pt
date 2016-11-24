#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
	script_id(14641);
 	script_version ("$Revision: 1.17 $");
	script_cve_id("CVE-2004-0637", "CVE-2004-0638", "CVE-2004-1362", "CVE-2004-1363",
		      "CVE-2004-1364", "CVE-2004-1365", "CVE-2004-1366", "CVE-2004-1367",
		      "CVE-2004-1368", "CVE-2004-1369", "CVE-2004-1370", "CVE-2004-1371");
	script_bugtraq_id(10871, 11091, 11100, 11099, 11120);
 	script_xref(name:"IAVA", value:"2004-A-0014");
	if ( NASL_LEVEL >= 2200 )
	{
	  script_xref(name:"OSVDB", value:"9817");
	  script_xref(name:"OSVDB", value:"9819");
	  script_xref(name:"OSVDB", value:"9861");
	  script_xref(name:"OSVDB", value:"9865");
	  script_xref(name:"OSVDB", value:"9866");
	  script_xref(name:"OSVDB", value:"9867");
	  script_xref(name:"OSVDB", value:"9868");
	  script_xref(name:"OSVDB", value:"9869");
	  script_xref(name:"OSVDB", value:"9870");
	  script_xref(name:"OSVDB", value:"9871");
	  script_xref(name:"OSVDB", value:"9872");
	  script_xref(name:"OSVDB", value:"9873");
	  script_xref(name:"OSVDB", value:"9874");
	  script_xref(name:"OSVDB", value:"9875");
	  script_xref(name:"OSVDB", value:"9876");
	  script_xref(name:"OSVDB", value:"9877");
	  script_xref(name:"OSVDB", value:"9878");
	  script_xref(name:"OSVDB", value:"9879");
	  script_xref(name:"OSVDB", value:"9880");
	  script_xref(name:"OSVDB", value:"9881");
	  script_xref(name:"OSVDB", value:"9882");
	  script_xref(name:"OSVDB", value:"9883");
	  script_xref(name:"OSVDB", value:"9884");
	  script_xref(name:"OSVDB", value:"9885");
	  script_xref(name:"OSVDB", value:"9886");
	  script_xref(name:"OSVDB", value:"9887");
	  script_xref(name:"OSVDB", value:"9888");
	  script_xref(name:"OSVDB", value:"9889");
	  script_xref(name:"OSVDB", value:"9890");
	  script_xref(name:"OSVDB", value:"9891");
	  script_xref(name:"OSVDB", value:"9892");
	}

	script_name(english: "Oracle Database Multiple Remote Vulnerabilities (Mar 2005)");

 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote Oracle Database, according to its version number, contains
a remote command execution vulnerability that may allow an attacker
who can execute SQL statements with certain privileges to execute
arbitrary commands on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technology/deploy/security/pdf/2004alert68.pdf" );
 script_set_attribute(attribute:"solution", value:
"Apply vendor supplied patches." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


	script_summary(english: "Checks the version of the remote Database");

	script_category(ACT_GATHER_INFO);
	script_family(english: "Databases");
	script_copyright(english: "This script is (C) 2004-2009 Tenable Network Security, Inc.");
	script_dependencie("oracle_tnslsnr_version.nasl");
        script_require_ports("Services/oracle_tnslsnr");
	exit(0);
}


include('global_settings.inc');

if ( report_paranoia < 1 ) exit(0);

port = get_kb_item("Services/oracle_tnslsnr");
if ( isnull(port)) exit(0);

version = get_kb_item(string("oracle_tnslsnr/",port,"/version"));
if (version)
{
  if (ereg(pattern:".*Version (8\.(0\.([0-5]\.|6\.[0-3])|1\.([0-6]\.|7\.[0-4]))|9\.(0\.(0\.|1\.[0-5]|2\.[0-3]|3\.[0-1]|4\.[0-1])|2\.0\.[0-5])|10\.(0\.|1\.0\.[0-2]))", string:version)) security_hole(port);
}

