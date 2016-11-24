#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 
 script_id(15477);  
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2004-0957", "CVE-2004-0956");
 script_bugtraq_id(11435, 11432);
 script_xref(name:"OSVDB", value:"10985");
 script_xref(name:"OSVDB", value:"10959");
 
 script_name(english:"MySQL < 4.0.21 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"You are running a version of MySQL which is older than version 4.0.21.
Such versions are potentially affected by two flaws :

  - There is an unauthorized database GRANT privilege 
    vulnerability, which may allow an attacker to misuse the
    GRANT privilege it has been given and to use it against
    other databases. (CVE-2004-0957)

  - A denial of service vulnerability may be triggered by 
    the misuse of the FULLTEXT search functionality.
    (CVE-2004-0956)" );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=3870" );
 script_set_attribute(attribute:"see_also", value:"http://www.novell.com/linux/security/securitysupport.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.gentoo.org/security/en/glsa/glsa-200410-22.xml" );
 script_set_attribute(attribute:"see_also", value:"http://www.debian.org/security/2005/dsa-707" );
 script_set_attribute(attribute:"see_also", value:"http://www.novell.com/linux/security/securitysupport.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.ubuntulinux.org/usn/usn-109-1" );
 script_set_attribute(attribute:"see_also", value:"http://rhn.redhat.com/errata/RHSA-2004-611.html" );
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=3933" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL 4.0.21 or later, as this reportedly fixes the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );

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
if(ereg(pattern:"^([0-3]\.|4\.0\.([0-9]|1[0-9]|20)([^0-9]|$))", string:ver))security_warning(port);	
