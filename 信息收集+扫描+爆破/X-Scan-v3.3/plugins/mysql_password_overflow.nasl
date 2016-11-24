#
# (C) Tenable Network Security, Inc.
#

#
# Ref:
#  From: Jedi/Sector One <j@c9x.org>
#  To: bugtraq@securityfocus.com
#  Subject: Buffer overflow in MySQL
#  Message-ID: <20030910213018.GA5167@c9x.org>
#


include("compat.inc");

if(description)
{
 
 script_id(11842);  
 script_version ("$Revision: 1.17 $");

 script_cve_id("CVE-2003-0780");
 script_bugtraq_id(8590);
 script_xref(name:"OSVDB", value:"2537");
 script_xref(name:"RHSA", value:"RHSA-2003:281-01");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:042");
 
 script_name(english:"MySQL sql_acl.cc get_salt_from_password Function Password Handling Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is susceptible to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of MySQL installed on the remote
host fails to validate the length of a user-supplied password in the
'User' table in the 'get_salt_from_password()' function.  Using a
specially-crafted value for a new password, an authenticated attacker
with the 'ALTER DATABASE' privilege may be able to leverage this issue
to trigger a buffer overflow and execute arbitrary code subject to the
privileges under which the database service runs." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2003-q3/3652.html" );
 script_set_attribute(attribute:"see_also", value:"http://lists.mysql.com/announce/168" );
 script_set_attribute(attribute:"see_also", value:"http://lists.mysql.com/announce/169" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL 3.23.58 / 4.0.15 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C" );
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

include("global_settings.inc");
include("misc_func.inc");

# Banner checks of MySQL are prone to false-positives so we only
# run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/mysql");
if (!port) port = 3306;
if (!get_tcp_port_state(port)) exit(0);

ver=get_mysql_version(port:port); 
if (isnull(ver)) exit(0);
if(ereg(pattern:"^3\.(([0-9]\..*|(1[0-9]\..*)|(2[0-2]\..*))|23\.([0-4][0-9]|5[0-7])[^0-9])",
  	  string:ver))security_hole(port);	  
if(ereg(pattern:"^4\.0\.([0-5][^0-9]|1[0-4])", string:ver))security_hole(port);	  
