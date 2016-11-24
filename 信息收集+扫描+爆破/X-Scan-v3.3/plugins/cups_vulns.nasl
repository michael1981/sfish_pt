#
# (C) Tenable Network Security, Inc.
#

#
# This script checks for CVE-2002-1368, but incidentally covers
# all the issues listed, as they were all corrected in the
# same package
#

include("compat.inc");


if(description)
{
 script_id(11199);
 script_version("$Revision: 1.16 $");
 script_cve_id(
   "CVE-2002-1366",
   "CVE-2002-1367",
   "CVE-2002-1368",
   "CVE-2002-1369",
   "CVE-2002-1372",
   "CVE-2002-1383",
   "CVE-2002-1384"
 );
 script_bugtraq_id(6433, 6434, 6435, 6436, 6437, 6438, 6440, 6475);
 script_xref(name:"OSVDB", value:"10739");
 script_xref(name:"OSVDB", value:"10740");
 script_xref(name:"OSVDB", value:"10741");
 script_xref(name:"OSVDB", value:"10742");
 script_xref(name:"OSVDB", value:"10744");
 script_xref(name:"OSVDB", value:"10745");
 script_xref(name:"OSVDB", value:"10746");
 script_xref(name:"OSVDB", value:"10747");
 script_xref(name:"SuSE", value:"SUSE-SA:2003:002");
 
 script_name(english:"CUPS < 1.1.18 Multiple Vulnerabilities");
 script_summary(english:"Crashes the remote CUPS server");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote printer service has multiple vulnerabilities."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote CUPS server seems vulnerable to various flaws (buffer\n",
     "overflow, denial of service, privilege escalation) which could\n",
     "allow a remote attacker to shut down this service or remotely gain\n",
     "the privileges of the 'lp' user."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to CUPS version 1.1.18 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www",631);
 script_require_keys("www/cups", "Settings/ParanoidReport");
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);


function check(port)
{
 local_var banner, r, req;
 #
 # This attack is non-destructive.
 # A non-patched cups will reply nothing to :
 # POST /printers HTTP/1.1\r\nContent-length: -1\r\n\r\n" (and won't
 # crash until we add another \r\n at the end of the request), 
 # whereas a patched cups will immediately reply with a code 400
 #

 if(http_is_dead(port:port))return(0);
 banner = get_http_banner(port:port);
 if(!banner)return(0); # we need to make sure this is CUPS

 if(egrep(pattern:"^Server: .*CUPS/.*", string:banner))
 {
 r = http_send_recv3(method:"POST", item: "/printers", port: port,
   add_headers: make_array("Authorization", "Basic AAA",
   		"Content-Length", "-1"));
 
 if (http_is_dead(port: port)) security_hole(port);	# The server dumbly waits for our data
 }
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:631);

foreach port (ports)
{
 check(port:port);
}
