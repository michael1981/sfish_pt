#
# (C) Tenable Network Security, Inc.
#

# References:
# Date: 27 Mar 2003 17:26:19 -0000
# From: "Grégory" Le Bras <gregory.lebras@security-corporation.com>
# To: bugtraq@securityfocus.com
# Subject: [SCSA-012] Multiple vulnerabilities in Sambar Server
#


include("compat.inc");

if(description)
{
 script_id(11492);
 script_version ("$Revision: 1.13 $");

 script_bugtraq_id(7209);
 if (NASL_LEVEL >= 2200)
 {
  script_xref(name:"OSVDB", value:"5097");
  script_xref(name:"OSVDB", value:"5100");
  script_xref(name:"OSVDB", value:"5101");
  script_xref(name:"OSVDB", value:"5102");
  script_xref(name:"OSVDB", value:"5103");
  script_xref(name:"OSVDB", value:"5104");
  script_xref(name:"OSVDB", value:"5105");
  script_xref(name:"OSVDB", value:"5106");
  script_xref(name:"OSVDB", value:"5107");
  script_xref(name:"OSVDB", value:"5108");
  script_xref(name:"OSVDB", value:"5803");
  script_xref(name:"OSVDB", value:"5804");
  script_xref(name:"OSVDB", value:"5805");
  script_xref(name:"OSVDB", value:"5806");
  script_xref(name:"OSVDB", value:"5807");
  script_xref(name:"OSVDB", value:"5808");
  script_xref(name:"OSVDB", value:"5809");
  script_xref(name:"OSVDB", value:"5810");
  script_xref(name:"OSVDB", value:"5811");
  script_xref(name:"OSVDB", value:"5812");
  script_xref(name:"OSVDB", value:"5813");
  script_xref(name:"OSVDB", value:"5814");
  script_xref(name:"OSVDB", value:"5815");
  script_xref(name:"OSVDB", value:"5816");
  script_xref(name:"OSVDB", value:"5817");
  script_xref(name:"OSVDB", value:"5818");
  script_xref(name:"OSVDB", value:"5819");
  script_xref(name:"OSVDB", value:"5820");
 }

 script_name(english:"Sambar Server Multiple Script XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts CGIs which are affected by cross site
scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The Sambar web server comes with a set of CGIs are that vulnerable
to a cross site scripting attack.

An attacker may use this flaw to steal the cookies of your web users." );
 script_set_attribute(attribute:"solution", value:
"Delete these CGIs" );
 script_set_attribute(attribute: "cvss_vector", value:"CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_end_attributes();

 
 script_summary(english:"Tests for XSS attacks");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses : XSS");
 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
 exit(0);
}

# The script code starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

cgis = make_list("/netutils/ipdata.stm?ipaddr=",
		 "/netutils/whodata.stm?sitename=",
		 "/netutils/finddata.stm?user=",
		 "/isapi/testisa.dll?check1=",
		 "/cgi-bin/environ.pl?param1=",
		 "/samples/search.dll?login=AND&query=",
		 "/wwwping/index.stm?wwwsite=",
		 "/syshelp/stmex.stm?bar=456&foo=",
		 "/syshelp/cscript/showfunc.stm?func=",
		 "/syshelp/cscript/showfnc.stm?pkg=",
		 "/sysuser/docmgr/ieedit.stm?path=",
		 "/sysuser/docmgr/edit.stm?path=",
		 "/sysuser/docmgr/iecreate.stm?path=",
		 "/sysuser/docmgr/create.stm?path=",
		 "/sysuser/docmgr/info.stm?path=",
		 "/sysuser/docmgr/ftp.stm?path=",
		 "/sysuser/docmgr/htaccess.stm?path=",
		 "/sysuser/docmgr/mkdir.stm?path=",
		 "/sysuser/docmgr/rename.stm?path=",
		 "/sysuser/docmgr/search.stm?path=",
		 "/sysuser/docmgr/sendmail.stm?path=",
		 "/sysuser/docmgr/template.stm?path=",
		 "/sysuser/docmgr/update.stm?path=",
		 "/sysuser/docmgr/vccheckin.stm?path=",
		 "/sysuser/docmgr/vccreate.stm?path=",
		 "/sysuser/docmgr/vchist.stm?path=",
		 "/cgi-bin/testcgi.exe?");
		 
report = NULL;

foreach c (cgis)
{
 u = c+"<script>foo</script>";
 r = http_send_recv3(method: "GET", item: u, port:port);
 if (isnull(r)) exit(0);
 if(r[0] =~ "^HTTP/1\.[01] +200 " && "<script>foo</script>" >< r[2])
 {
  report = strcat(report, ' ', build_url(port: port, qs: u), '\n');
 }
}


if ( report != NULL )
{
 text = "
The following Sambar default CGIs are vulnerable :

" + report;

 security_warning(port: port, extra: text);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
