#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22300);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-4542");
  script_bugtraq_id(19820);
  script_xref(name:"OSVDB", value:"28337");
  script_xref(name:"OSVDB", value:"28338");

  script_name(english:"Webmin / Usermin Null Byte Filtering Vulnerabilities");
  script_summary(english:"Checks if nulls in a URL are filtered by miniserv.pl");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Webmin or Usermin, web-based interfaces for
Unix / Linux system administrators and end-users. 

Webmin and Usermin both come with the Perl script 'miniserv.pl' to
provide basic web services, and the version of 'miniserv.pl' installed
on the remote host fails to properly filter null characters from URLs. 
An attacker may be able to exploit this to reveal the source code of CGI
scripts, obtain directory listings, or launch cross-site scripting
attacks against the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://www.lac.co.jp/business/sns/intelligence/SNSadvisory_e/89_e.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/security.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Webmin version 1.296 / Usermin 1.226 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P" );
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("webmin.nasl");
  script_require_ports("Services/www", 10000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:10000, embedded: TRUE);
if (!get_kb_item("www/" + port + "/webmin"));


# Some files don't require authentication; eg, those matching the
# pattern '^[A-Za-z0-9\\-/]+\\.gif'. So request a bogus gif file; if
# nulls are filtered, we'll get an error saying "Error - File not 
# found"; otherwise, we'll get a login form because the null will 
# cause the regex to fail.

w = http_send_recv3(method:"GET",item:string("/nessus%00.gif"), port:port);
if (isnull(w)) exit(0);
res = w[2];

# There's a problem if we see a login form.
if ("<form action=/session_login.cgi " >< res)
{
 security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

