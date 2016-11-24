#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11365);
 script_bugtraq_id(4069);
 script_cve_id("CVE-2002-0257");
 script_xref(name:"OSVDB", value:"9286");
 script_version ("$Revision: 1.19 $");

 script_name(english:"Auction Deluxe auction.pl Multiple Variable XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"The remote Auction Deluxe server is vulnerable to a cross-site
scripting attack. 

As a result, a user could easily steal the cookies of your legitimate
users and impersonate them." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Auction Deluxe 3.30 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 summary["english"] = "Checks for auction.pl";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl", "no404.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);


foreach dir ( cgi_dirs() )
{
 r = http_send_recv3(port: port, method: 'GET', 
   item:string(dir, "/auction.pl?searchstring=<script>foo</script>"));
 if (isnull(r)) exit(0);
 if (r[0] !~ "^HTTP/[0-9]\.[0-9] +200 ") exit(0);

 str = egrep(pattern: "<script>foo</script>", string: r[2], icase:TRUE);
 if(str)
 {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
 }
}
