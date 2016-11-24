#
# (C) Tenable Network Security, Inc.
#

# Ref: 
# From: Stefan Esser <s.esser@e-matters.de>
# Message-ID: <20021212112625.GA431@php.net>
# To: full-disclosure@lists.netsys.com
# Cc: vulnwatch@vulnwatch.org, bugtraq@securityfocus.com
# Subject: [VulnWatch] Advisory 04/2002: Multiple MySQL vulnerabilities
#
# URL:
# http://security.e-matters.de/advisories/042002.html 
#


include("compat.inc");

if(description)
{
 
 script_id(11192);  
 script_version ("$Revision: 1.23 $");

 script_cve_id("CVE-2002-1373", "CVE-2002-1374", "CVE-2002-1375", "CVE-2002-1376");
 script_bugtraq_id(6368, 6370, 6373, 6374, 6375, 8796);
 script_xref(name:"OSVDB", value:"8885");
 script_xref(name:"OSVDB", value:"8886");
 script_xref(name:"OSVDB", value:"8887");
 script_xref(name:"OSVDB", value:"8888");
 script_xref(name:"OSVDB", value:"8889");
 script_xref(name:"RHSA", value:"RHSA-2002");
 script_xref(name:"SuSE", value:"SUSE-SA");
 
 script_name(english:"MySQL < 3.23.54 / 4.0.6 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server may be disabled remotely." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of MySQL older than 3.23.54 or
4.0.6. 

The remote version of this product contains several flaw which may
allow an attacker to crash this service remotely." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-12/0108.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade MySQL to version 3.23.54 or 4.0.6." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
 script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/12/12");
 script_end_attributes();
 
 script_summary(english:"Checks for the remote MySQL version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
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

ver = get_mysql_version(port:port); 
if (isnull(ver)) exit(0);

if(ereg(pattern:"^3\.(([0-9]\..*|(1[0-9]\..*)|(2[0-2]\..*))|23\.([0-4][0-9]|5[0-3])[^0-9])",
  	  string:ver))security_warning(port);	  
else if(ereg(pattern:"^4\.0\.[0-5][^0-9]", string:ver))security_warning(port);	  
