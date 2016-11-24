#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security, Inc.
#
#  Ref:  Jeroen van Wolffelaar <jeroen@wolffelaar.nl>
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title (6/9/09)


include("compat.inc");

if(description)
{
 script_id(14343);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2004-0457");
 script_bugtraq_id(10969);
 script_xref(name:"OSVDB", value:"9015");
 
 script_name(english:"MySQL < 4.0.21 mysqlhotcopy Insecure Temporary File Creation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database serer is affected by an insecure temporary file
creation vulnerability." );
 script_set_attribute(attribute:"description", value:
"You are running a version of MySQL which is older than version 4.0.21.

Mysqlhotcopy is reported to contain an insecure temporary file 
creation vulnerability. 

The result of this is that temporary files created by the application
may use predictable filenames. 

A local attacker may also possibly exploit this vulnerability to execute 
symbolic link file overwrite attacks. 

*** Note : this vulnerability is local only" );
 script_set_attribute(attribute:"see_also", value:"http://www.debian.org/security/2004/dsa-540" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of MySQL 4.0.21 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P" );

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
if(!port)port = 3306;

ver=get_mysql_version(port:port);
if ((isnull)) exit(0);
if(ereg(pattern:"^3\.|4\.0\.([0-9]|1[0-9]|20)[^0-9]", string:ver))security_warning(port);	  

