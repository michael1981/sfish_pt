#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security, Inc.
#
#  Ref: Oleksandr Byelkin & Dean Ellis
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs (6/8/09)


include("compat.inc");

if(description)
{
 script_id(15449);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CVE-2004-0835","CVE-2004-0837");
 script_bugtraq_id(11357);
 script_xref(name:"OSVDB", value:"10659");
 script_xref(name:"OSVDB", value:"10660");

 script_name(english:"MySQL < 3.23.59 / 4.0.21 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the MySQL database which is
older than 4.0.21 or 3.23.59.

MySQL is a database which runs on both Linux/BSD and Windows platform.
The remote version of this software is vulnerable to specially 
crafted 'ALTER TABLE SQL' query which can be exploited to bypass some 
applied security restrictions or cause a denial of service.

To exploit this flaw, an attacker would need the ability to execute 
arbitrary SQL statements on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://marc.theaimsgroup.com/?l=bugtraq&m=110140517515735&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of MySQL 3.23.59 or 4.0.21 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	
script_end_attributes();

 
 script_summary(english:"Checks for the remote MySQL version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Databases");
 script_dependencie("mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/mysql");
if(!port) port = 3306;
if ( ! get_port_state(port) ) exit(0);

ver=get_mysql_version(port:port);
if (isnull(ver)) exit(0);
if(ereg(pattern:"^(3\.([0-9]\.|1[0-9]\.|2[0-2]\.|23\.(([0-9]|[1-4][0-9]|5[0-8])[^0-9]))|4\.0\.([0-9]|1[0-9]|20)[^0-9])", string:ver))security_hole(port);	  

