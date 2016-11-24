#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17160);
  script_version("$Revision: 1.7 $");
  script_cve_id("CVE-2005-0478", "CVE-2005-0479", "CVE-2005-0480", "CVE-2005-0481", "CVE-2005-0482");
  script_bugtraq_id(12592);
  script_xref(name:"OSVDB", value:"13952");
  script_xref(name:"OSVDB", value:"13953");
  script_xref(name:"OSVDB", value:"13955");
  script_xref(name:"OSVDB", value:"13956");
  script_xref(name:"OSVDB", value:"13957");
  script_xref(name:"OSVDB", value:"13958");
 
  script_name(english:"TrackerCam Multiple Remote Vulnerabilities");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The remote host is running TrackerCam, a HTTP software that allows a\n",
      "user to publish a webcam feed thru a web site.\n",
      "\n",
      "The remote version of this software is affected by multiple\n",
      "vulnerabilities :\n",
      "\n",
      "  - Buffer overflows which may allow an attacker to execute\n",
      "    arbitrary code on the remote host.\n",
      "\n",
      "  - A directory traversal bug that may allow an attacker to\n",
      "    read arbitrary files on the remote host with the \n",
      "    privileges of the web server daemon.\n",
      "\n",
      "  - A cross site scripting issue that may allow an attacker\n",
      "    to use the remote host to perform a cross-site scripting\n",
      "    attack."
    )
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/390918/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();
 
  script_summary(english:"Checks for flaws in TrackerCam");
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");

  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 8090);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8090);

banner = get_http_banner(port:port);
if ( "Server: TrackerCam/" >!< banner ) exit(0);

w = http_send_recv3(method:"GET", item:"/tuner/ComGetLogFile.php3?fn=../HTTPRoot/tuner/ComGetLogFile.php3", port:port);
if (isnull(w)) exit(1, "the web server did not answer");
res = strcat(w[0], w[1], '\r\n', w[2]);
if ( "$fcontents = file ('../../log/'.$fn);" >< res )
{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

