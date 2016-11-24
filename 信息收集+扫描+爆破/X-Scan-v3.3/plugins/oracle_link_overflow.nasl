#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
	script_id(11563);
 	script_version ("$Revision: 1.14 $");
	script_cve_id("CVE-2003-0222");
	script_bugtraq_id(7453);
	script_xref(name:"OSVDB", value:"7736");

	script_name(english:"Oracle Net Services CREATE DATABASE LINK Query Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Oracle Database, according to its version number,
is vulnerable to a buffer overflow in the query CREATE 
DATABASE LINK. An attacker with a database account may use 
this flaw to gain the control on the whole database, or even 
to obtain a shell on this host." );
 script_set_attribute(attribute:"see_also", value:"http://otn.oracle.com/deploy/security/pdf/2003alert54.pdf" );
 script_set_attribute(attribute:"solution", value:
"Apply vendor supplied patches." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C" );

script_end_attributes();

	script_summary(english: "Checks the version of the remote Database");

	script_category(ACT_GATHER_INFO);
	script_family(english:"Databases");
	script_copyright(english:"This script is (C) 2003-2009 Tenable Network Security, Inc.");
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
  if(ereg(pattern:".*Version ([0-7]\.|8\.0\.[0-6]|8\.1\.[0-7]|9\.0\.[0-1]|9\.2\.0\.[0-2]).*", string:version))
	security_hole(port);
}
