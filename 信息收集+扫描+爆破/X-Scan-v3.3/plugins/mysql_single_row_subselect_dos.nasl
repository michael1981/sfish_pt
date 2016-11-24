#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2
#


include("compat.inc");

if(description)
{
 script_id(24905);
 script_version ("$Revision: 1.5 $");

 script_cve_id("CVE-2007-1420"); 	
 script_bugtraq_id(22900);
 script_xref(name:"OSVDB", value:"33974");
 
 name["english"] = "MySQL Single Row Subselect Remote DoS";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of MySQL on the remote host is
older than 5.0.37.  Such versions are vulnerable to a remote denial of
service when processing certain single row subselect queries.  A
malicious user can crash the service via a specially-crafted SQL
query." );
 script_set_attribute(attribute:"see_also", value:"http://www.sec-consult.com/284.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/462339/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/releasenotes-cs-5-0-37.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.0.37 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C" );
script_end_attributes();

 
 summary["english"] = "Checks the remote MySQL version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2007 David Maciejak");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_dependencie("mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 exit(0);
}

#
# here the code
#

include("global_settings.inc");
include("misc_func.inc");

# Only run the plugin if we're being paranoid to avoid false-positives,
# which might arise because the software is open-source.
if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/mysql");
if (!port) port = 3306;
if (!get_tcp_port_state(port)) exit(0);


ver = get_mysql_version(port:port);
if(ver==NULL) exit(0);
if(ereg(pattern:"^5\.0\.([0-9]($|[^0-9])|[12][0-9]($|[^0-9])|3[0-6]($|[^0-9]))", string:ver))
  security_warning(port);	  
