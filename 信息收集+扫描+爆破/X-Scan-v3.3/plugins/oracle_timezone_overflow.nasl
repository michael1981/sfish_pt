#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
	script_id(12047);
 	script_version ("$Revision: 1.17 $");

	script_cve_id("CVE-2003-1208");
	script_bugtraq_id(9587);
	script_xref(name:"OSVDB", value:"3837");
	script_xref(name:"OSVDB", value:"3838");
	script_xref(name:"OSVDB", value:"3839");
	script_xref(name:"OSVDB", value:"3840");

	script_name(english:"Oracle Database 9i Multiple Functions Local Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a 
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Oracle Database, according to its version number, 
is vulnerable to a buffer overflow in the query SET 
TIME_ZONE. An attacker with a database account may use this 
flaw to gain the control on the whole database, or even to 
obtain a shell on this host." );
 script_set_attribute(attribute:"see_also", value:"http://www.ngssoftware.com/advisories/ora-time-zone/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle 9.2.0.3 - http://metalink.oracle.com" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();


	script_summary(english: "Checks the version of the remote database");

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
    if(ereg(pattern:".*Version (9\.0\.[0-1]|9\.2\.0\.[0-2]).*", string:version))
	security_hole(port);
}
