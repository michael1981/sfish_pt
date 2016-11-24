#
# (C) Tenable Network Security, Inc.
#

# Ref:
# Message-ID: <20030222014450.22428.qmail@www.securityfocus.com>
# From: "Grégory" Le Bras <gregory.lebras@security-corp.org>
# To: bugtraq@securityfocus.com
# Subject: [SCSA-006] XSS & Function
#
# We don't check for all the listed BIDs since no patch has
# ever been made (ie: vulnerable to one => vulnerable to all)



include("compat.inc");

if(description)
{
 script_id(11282);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2003-1238", "CVE-2003-1370", "CVE-2003-1371");
 script_bugtraq_id(6697, 6699, 6700, 6916, 6917);
 script_xref(name:"OSVDB", value:"50552");
 script_xref(name:"OSVDB", value:"52891");
 script_xref(name:"OSVDB", value:"58499");
 script_xref(name:"OSVDB", value:"58500");
 script_xref(name:"OSVDB", value:"58501");

 script_name(english:"Nuked-Klan 1.2b Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"It is possible to execute arbitrary PHP code on the remote host using
a flaw in the 'Nuked Klan' package.  An attacker may leverage this
flaw to leak information about the remote system or even execute
arbitrary commands. 

In addition to this problem, this service is vulnerable to various
cross-site scripting attacks." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-03/0275.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2003-02/0276.html" );
 script_set_attribute(attribute:"solution", value:
"Contact the author for a patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N" );

script_end_attributes();

 script_summary(english:"Executes phpinfo()");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc, module)
{
 local_var	url, req, r, report;

 if (! loc && report_paranoia < 2) return;	# Might generate a FP

 url = strcat(loc, "/index.php?file=", module, "&op=phpinfo");
 req = http_get(item: url, port:port);	
 r = http_keepalive_send_recv(port:port, data:req);
 if (isnull(r)) exit(0);
 if("allow_call_time_pass_reference" >< r){
        report = string(
          "A vulnerable instance of Nuke Clan can be found at the following URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );
 	security_warning(port:port, extra:report);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
  }
}


dirs = list_uniq(make_list("/nuked-clan", "/clan-nic", "/klan", "/clan", cgi_dirs()));


foreach dir (dirs)
{
 check(loc:dir, module:"News");
 #check(loc:dir, module:"Team");
 #check(loc:dir, module:"Lien");
}
