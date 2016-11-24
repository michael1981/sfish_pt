#
# (C) Tenable Network Security, Inc.
#

#
# Ref: http://www.mysql.com/doc/en/News-3.23.55.html
# 


include("compat.inc");

if(description)
{
 script_id(11299);  
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2003-0073");
 script_bugtraq_id(6718);
 script_xref(name:"OSVDB", value:"9910");
 script_xref(name:"RHSA", value:"RHSA-2003:093-01");

 script_name(english:"MySQL < 3.23.55 mysql_change_user() Double-free Memory Pointer DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database service is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, a version of MySQL before 3.23.55 is running
on the remote host.  If you have not patched this version, then an
attacker with valid credentials may be able to crash this service
remotely by exploiting a double free bug. 

Further exploitation to gain a shell on the host might be possible,
although it's unconfirmed so far." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL 3.23.55 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P" );
script_end_attributes();

 
 script_summary(english:"Checks for the remote MySQL version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
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
if(ereg(pattern:"^3\.(([0-9]\..*|(1[0-9]\..*)|(2[0-2]\..*))|23\.([0-4][0-9]|5[0-4])[^0-9])", string:ver))security_warning(port);	  

