#
# This script was rewritten by Tenable Network Security, Inc.
# Ref: albanian haxorz
# 

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs (6/4/09)


include("compat.inc");

if(description)
{
  script_id(17199);
  script_version("$Revision: 1.11 $");
  script_cve_id("CVE-2005-0495");
  script_bugtraq_id(12596);
  script_xref(name:"OSVDB", value:"14017");
  script_xref(name:"OSVDB", value:"14018");
  
  script_name(english:"Zeroboard < 4.1pl6 Multiple XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host runs Zeroboard, a web BBS application popular in
Korea. 

The remote version of this software is vulnerable to cross-site
scripting attacks due to a lack of sanitization of user-supplied data. 
Successful exploitation of this issue may allow an attacker to execute
malicious script code in a user's browser within the context of the
affected web site." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/390933" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Zeroboard 4.1pl6 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

  script_summary(english:"Checks for Zeroboard XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

test_cgi_xss(port: port, cgi: "/zboard.php", 
  qs: "id=gallery&sn1=FOO='%3E%3Cscript%3Ebar%3C/script%3E",
  pass_str: "<script>bar</script>");
