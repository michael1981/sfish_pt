#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: LSS Security
#
#  This script is released under the GNU GPL v2

# Changes by Tenable:
# - Revised plugin title (1/31/2009)


include("compat.inc");

if(description)
{
 script_id(15484);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id(11430);
 script_cve_id ("CVE-2004-1602");
 script_xref(name:"OSVDB", value:"10758");
 
 script_name(english:"ProFTPD Login Timing Account Name Enumeration");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server may disclose the list of valid usernames." );
 script_set_attribute(attribute:"description", value:
"The remote ProFTPd server is as old or older than 1.2.10

It is possible to determine which user names are valid on the remote host 
based on timing analysis attack of the login procedure.

An attacker may use this flaw to set up a list of valid usernames for a
more efficient brute-force attack against the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a newer version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
                 
                 
                     
script_end_attributes();

                    
 
 script_summary(english:"Checks the version of the remote proftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
                  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/proftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_kb_item("Services/ftp");
if(!port)port = 21;

banner = get_ftp_banner(port:port);
if(egrep(pattern:"^220 ProFTPD 1\.2\.([0-9][^0-9]|10[^0-9])", string:banner))
{
  security_warning(port);
}
