#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17313);  
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2005-0709", "CVE-2005-0710", "CVE-2005-0711");
 script_bugtraq_id(12781);
 script_xref(name:"OSVDB", value:"14676");
 script_xref(name:"OSVDB", value:"14677");
 script_xref(name:"OSVDB", value:"14678");
 
 script_name(english:"MySQL < 4.0.24 / 4.1.10a Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of MySQL which older than version
4.0.24 or 4.1.10a.  Such versions are potentially affected by multiple
issues.
 
  - MySQL uses predictable file names when creating 
    temporary tables, which allows local users with 'CREATE
    TEMPORARY TABLE' privileges to overwrite arbitrary files
    via a symlink attack. (CVE-2005-0711)

  - A flaw exists that may allow a malicious user to gain
    access to unauthorized privileges when an authenticated
    user with 'INSERT' and 'DELETE' privileges bypasses 
    library path restrictions using 'INSERT INTO' to modify
    the 'mysql.func' table. (CVE-2005-0709)

  - A flaw exists that may allow a mlicious user to load
    arbitrary libraries when an authenticated user with 
    'INSERT' and 'DELETE' privileges use the 'CREATE 
    FUNCTION' command to specify and load an arbitrary
    custom library. (CVE-2005-0710)" );
 script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/TA23465?viewlocale=en_US" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-101864-1" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2005-q1/0082.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2005-q1/0083.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2005-q1/0084.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL 4.0.24, 4.1.10a, or later as this reportedly fixes 
the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for the remote MySQL version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
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
if(ereg(pattern:"^([0-3]\.|4\.0\.([0-9]|1[0-9]|2[0-3])([^0-9]|$)|4\.1\.[0-9][^0-9])", string:ver))security_warning(port);	
