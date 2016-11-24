#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: taqua
#
# This script is released under the GNU GPLv2
#

# Changes by Tenable:
# - Revised plugin title (3/30/2009)


include("compat.inc");

if(description)
{
 script_id(20376);
 script_version ("$Revision: 1.10 $");

 script_cve_id("CVE-2005-4586");
 script_bugtraq_id(16077);
 script_xref(name:"OSVDB", value:"22039");
  
 script_name(english:"PHPSurveyor Multiple SQL Injections");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PHPSurveyor, a set of PHP scripts that
interact with MySQL to develop surveys, publish surveys and collect
responses to surveys. 

The remote version of this software is prone to a SQL injection flaw. 
Using specially crafted requests, an attacker can manipulate database
queries on the remote system." );
 script_set_attribute(attribute:"see_also", value:"http://www.phpsurveyor.org/mantis/view.php?id=286" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=381050&group_id=74605" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHPSurveyor version 0.991 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks for PHPSurveyor sid SQL injection flaw";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2006-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencies("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# the code
#

 include("global_settings.inc");
 include("http_func.inc");
 include("http_keepalive.inc");
 include("misc_func.inc");

 port = get_http_port(default:80);
 if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
 if (!can_host_php(port:port) ) exit(0);

 # Check a few directories.
 if (thorough_tests) dirs = list_uniq(make_list("/phpsurveyor", "/survey", cgi_dirs()));
 else dirs = make_list(cgi_dirs());

 foreach dir (dirs)
 { 
  req = http_get(item:string(dir,"/admin/admin.php?sid=0'"),port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  if(egrep(pattern:"mysql_num_rows(): supplied argument is not a valid MySQL .+/admin/html.php", string:r))
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
 }
