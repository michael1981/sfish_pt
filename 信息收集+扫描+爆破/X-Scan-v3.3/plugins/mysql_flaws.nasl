#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10626);  
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2000-0045", "CVE-2001-1275", "CVE-2001-0407");
 script_bugtraq_id(2380, 2522, 926);
 script_xref(name:"OSVDB", value:"520");
 script_xref(name:"OSVDB", value:"8979");
 script_xref(name:"OSVDB", value:"9906");
 script_xref(name:"IAVA", value:"2001-t-0004");

 script_name(english:"MySQL < 3.23.36 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"You are running a version of MySQL which is older than version 
3.23.36. Such versions are potentially affected by multiple
vulnerabilities.  

  - It is possible to modify arbitrary files and gain
    privileges by creating a database with '..' characters.
    (CVE-2001-0407)

  - Users with a MySQL account can use the 'SHOW GRANTS'
    command to obtain the encrypted administrator password
    from the 'mysql.user' table. (CVE-2001-1275)

  - Local users can modify passwords for arbitrary MySQL
    users via the 'GRANT' privilege. (CVE-2000-0045)" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=98089552030459&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=98089552030459&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-01/0126.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-01/0158.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-03/0396.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-03/0237.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 3.23.36 or later as this reportedly fixes the
issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 script_summary(english:"Checks for the remote MySQL version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
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
if(ereg(pattern:"^3\.(([0-9]\..*)|(1[0-9]\..*)|(2(([0-2]\..*)|3\.(([0-9]$)|([0-2][0-9])|(3[0-5])))))",
string:ver)) security_hole(port);
