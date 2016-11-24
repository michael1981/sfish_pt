#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");

if (description)
{
 script_id(17245);
 script_cve_id("CVE-2005-0483");
 script_bugtraq_id(12586);
 script_xref(name:"OSVDB", value:"14014");
 script_xref(name:"OSVDB", value:"14015");
 script_xref(name:"OSVDB", value:"14016");
 script_version("$Revision: 1.8 $");

 script_name(english:"glFTPd Multiple Script ZIP File Handling Arbitrary File / Directory Access");
 script_summary(english:"Checks the banner of the remote glFTPD server");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is suceptible to directory traversal attacks." );
 script_set_attribute(attribute:"description", value:
"The remote glFTPD server fails to properly sanitize user supplied
input to the 'sitenfo.sh', 'sitezpichk.sh', and 'siteziplist.sh'. An
attacker could exploit this flaw to disclose arbitrary files by
sending a spcially crafted request to teh remote host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2005-02/0315.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to glFTPD 2.01 RC1 or later, as this reportedly fixes the
issues." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_family(english: "FTP");

 script_copyright(english: "Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}


#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if ( egrep(pattern:"^220.* glftpd (1\.|2\.00_RC[1-7] )", string:banner) )
	security_warning(port);

