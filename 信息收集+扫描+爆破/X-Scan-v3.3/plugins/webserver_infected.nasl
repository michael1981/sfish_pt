#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(29871);
 script_version ("$Revision: 1.5 $");
 
 script_name(english:"Web Site Malicious Javascript Link Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server seems to have been compromised by malware." );
 script_set_attribute(attribute:"description", value:
"The remote web site seems to link to malicious javascript files 
hosted on a third party web site.

This typically means that the remote web site has been compromised, 
and it may infect its visitors as well." );
 script_set_attribute(attribute:"solution", value:
"Restore your web site to its original state, and audit your dynamic
pages for SQL injection vulnerabilities." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8fa1760" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca2eff80" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 script_summary(english:"This plugin uses the results of webmirror.nasl");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

list = get_kb_list("www/" + port + "/infected/pages");
if ( isnull(list) ) exit(0);
list = make_list(list);
foreach item ( list )
{
 if ( item =~ "link: " ) 
 {
  item = str_replace(find:"page:", replace:"The URL http://" + get_host_name() + "/", string:item);
  item = str_replace(find:"link:", replace:"links to:", string:item);
  report += item + '\n';
 }
}

if ( strlen(report) )
{
 security_hole(port:port, extra: report);
 set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
