#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16276);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id(12398); 
 script_xref(name:"OSVDB", value:"13241");

 script_name(english:"phpPgAds dest Parameter HTTP Response Splitting");

 script_set_attribute(attribute:"synopsis", value:
"The remote web application is vulnerable to HTTP response splitting." );
 script_set_attribute(attribute:"description", value:
"There is a flaw in the remote phpPgAds/phpAdsNew, a banner management
and tracking system written in PHP.

This version of phpPgAds/phpAdsNew is affected by an HTTP response
splitting vulnerability.

An attacker, exploiting this flaw, would be able to redirect users to
another site to perform another attack (steal their credentials)." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpPGAds/phpAdsNew 2.0.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N" );

 script_end_attributes();

 script_summary(english:"Checks for the presence of phpPGAds/phpAdsNew");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("webmirror.nasl", "http_version.nasl");
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

function check(loc)
{
 local_var u, r;
 u = strcat(loc, "admin/index.php");
 r = http_send_recv3(port: port, method: "GET", item: u);
 if (isnull(r)) exit(0);

 if ( egrep(pattern:"<meta name='generator' content='(phpPgAds|phpAdsNew) ([0-1]\..*|2\.0|2\.0\.[0-1]) - http://www\.phpadsnew\.com'>", string:r[2]))
 {
   security_warning(port);
   exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

