#
# (C) Tenable Network Security, Inc.
#

# Ref: 
#  Date: 18 Jun 2003 16:33:36 -0000
#  Message-ID: <20030618163336.11333.qmail@www.securityfocus.com>
#  From: Lorenzo Manuel Hernandez Garcia-Hierro <security@lorenzohgh.com>
#  To: bugtraq@securityfocus.com  
#  Subject: phpMyAdmin XSS Vulnerabilities, Transversal Directory Attack ,
#   Information Encoding Weakness and Path Disclosures
#


include("compat.inc");

if(description)
{
 script_id(11761);
 script_version ("$Revision: 1.19 $");
 script_bugtraq_id(7962, 7963, 7964, 7965);
 if (NASL_LEVEL >= 2200)
 {
  script_xref(name:"OSVDB", value:"8450");
  script_xref(name:"OSVDB", value:"8451");
  script_xref(name:"OSVDB", value:"8452");
  script_xref(name:"OSVDB", value:"8453");
  script_xref(name:"OSVDB", value:"8454");
  script_xref(name:"OSVDB", value:"8455");
  script_xref(name:"OSVDB", value:"8456");
  script_xref(name:"OSVDB", value:"8457");
  script_xref(name:"OSVDB", value:"8458");
  script_xref(name:"OSVDB", value:"8459");
  script_xref(name:"OSVDB", value:"8460");
  script_xref(name:"OSVDB", value:"8461");
  script_xref(name:"OSVDB", value:"8462");
  script_xref(name:"OSVDB", value:"8463");
  script_xref(name:"OSVDB", value:"8464");
  script_xref(name:"OSVDB", value:"8465");
  script_xref(name:"OSVDB", value:"8466");
  script_xref(name:"OSVDB", value:"8467");
  script_xref(name:"OSVDB", value:"8468");
  script_xref(name:"OSVDB", value:"8469");
  script_xref(name:"OSVDB", value:"8470");
  script_xref(name:"OSVDB", value:"8471");
  script_xref(name:"OSVDB", value:"8472");
  script_xref(name:"OSVDB", value:"8473");
  script_xref(name:"OSVDB", value:"8474");
  script_xref(name:"OSVDB", value:"8475");
  script_xref(name:"OSVDB", value:"8476");
  script_xref(name:"OSVDB", value:"8477");
  script_xref(name:"OSVDB", value:"8478");
  script_xref(name:"OSVDB", value:"8479");
  script_xref(name:"OSVDB", value:"8480");
  script_xref(name:"OSVDB", value:"8481");
  script_xref(name:"OSVDB", value:"8482");
  script_xref(name:"OSVDB", value:"8483");
  script_xref(name:"OSVDB", value:"8484");
  script_xref(name:"OSVDB", value:"8485");
  script_xref(name:"OSVDB", value:"8486");
  script_xref(name:"OSVDB", value:"8487");
  script_xref(name:"OSVDB", value:"8488");
  script_xref(name:"OSVDB", value:"8489");
  script_xref(name:"OSVDB", value:"8490");
  script_xref(name:"OSVDB", value:"8491");
  script_xref(name:"OSVDB", value:"8492");
  script_xref(name:"OSVDB", value:"8493");
  script_xref(name:"OSVDB", value:"8494");
  script_xref(name:"OSVDB", value:"8495");
  script_xref(name:"OSVDB", value:"8496");
  script_xref(name:"OSVDB", value:"8497");
  script_xref(name:"OSVDB", value:"8498");
  script_xref(name:"OSVDB", value:"8499");
  script_xref(name:"OSVDB", value:"8500");
  script_xref(name:"OSVDB", value:"8501");
  script_xref(name:"OSVDB", value:"8502");
  script_xref(name:"OSVDB", value:"8503");
  script_xref(name:"OSVDB", value:"8504");
  script_xref(name:"OSVDB", value:"8505");
 }
 script_name(english:"phpMyAdmin < 2.5.2 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpMyAdmin that is vulnerable
to several attacks :

 - It may be tricked into disclosing the physical path of the remote PHP
   installation.
   
 - It is vulnerable to cross-site scripting, which may allow an attacker
   to steal the cookies of your users.
   
 - It is vulnerable to a flaw which may allow an attacker to list the
   contents of arbitrary directories on the remote server.

An attacker may use these flaws to gain more knowledge about the remote
host and therefore set up more complex attacks against it." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/325641" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/327511" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 2.5.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks for the presence of phpMyAdmin");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phpMyAdmin_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
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


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  test_cgi_xss(port: port, dirs: make_list(dir), cgi: "/db_details_importdocsql.php",
 pass_str: "Ignoring file passwd",
 qs: "submit_show=true&do=import&docpath=../../../../../../../../../../etc");
}
