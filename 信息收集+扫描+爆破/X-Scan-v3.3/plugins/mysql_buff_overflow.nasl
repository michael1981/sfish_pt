#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security, Inc.
#
#  Ref: Lukasz Wojtow
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (6/9/09)


include("compat.inc");

if(description)
{
 script_id(14319);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2004-0836");
 script_bugtraq_id(10981);
 script_xref(name:"OSVDB", value:"10658");
 
 script_name(english:"MySQL < 4.0.21 mysql_real_connect() Function Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a remote code execution
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of MySQL which is older than 
4.0.21.

MySQL is a database which runs on both Linux/BSD and Windows platform.
This version is vulnerable to a length overflow within it's 
mysql_real_connect() function.  The overflow is due to an error in the
processing of a return Domain (DNS) record.  An attacker, exploiting
this flaw, would need to control a DNS server which would be queried
by the MySQL server.  A successful attack would give the attacker
the ability to execute arbitrary code on the remote machine." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=4017" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=110140517515735&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of MySQL 4.0.21 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"Checks for the remote MySQL version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Databases");
 script_dependencie("find_service1.nasl", "mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 exit(0);
}

#
# The script code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/mysql");
if(!port)
	port = 3306;

ver=get_mysql_version(port:port);
if(ver==NULL) 
	exit(0);
if(ereg(pattern:"([0-3]\.[0-9]\.[0-9]|4\.0\.([0-9]|1[0-9]|20)[^0-9])", string:ver))security_hole(port);	 

