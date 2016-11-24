#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 
 script_id(14831);  
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2004-2149");
 script_bugtraq_id(11261);
 script_xref(name:"OSVDB", value:"10244");
 
 script_name(english:"MySQL libmysqlclient Prepared Statements API Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a remote code execution 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"You are running a version of MySQL 4.1.x which is older than version 4.1.5.

There is a flaw in the remote version of this software which may allow
an attacker to crash the affected service, thus denying access to
legitimate users." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=5194" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL 4.1.5 or later, as this reportedly fixes the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

 script_end_attributes();

 script_summary(english:"Checks for the remote MySQL version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
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
if(!port)port = 3306;

ver=get_mysql_version(port:port); 
if (isnull(ver)) exit(0);
if(ereg(pattern:"^4\.1\.[0-4][^0-9]", string:ver))security_warning(port);
