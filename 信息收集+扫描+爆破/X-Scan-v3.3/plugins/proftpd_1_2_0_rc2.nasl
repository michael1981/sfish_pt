#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11407);
 script_bugtraq_id(6781);
 script_cve_id("CVE-2001-0318");
 script_xref(name:"OSVDB", value:"5705");
 script_version ("$Revision: 1.8 $");
 
 script_name(english:"ProFTPD 1.2.0rc2 Malformed cwd Command Format String");
             
 script_set_attribute(attribute:"synopsis", value:
"It might be possible to run arbitrary code on this server." );
 script_set_attribute(attribute:"description", value:
"The remote ProFTPd server is as old or older than 1.2.0rc2

There is a very hard to exploit format string vulnerability in
this version, which may allow an attacker to execute arbitrary
code on this host.

The vulnerability is believed to be nearly impossible to exploit
though." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a newer version" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
                 
script_end_attributes();

 script_summary(english:"Checks if the version of the remote proftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
                  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/proftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#



include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if (get_kb_item('ftp/'+port+'/broken') || 
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);

# get_ftp_banner will return NULL if the server is fake.
banner = get_ftp_banner(port:port);

if ( egrep(pattern:"^220 ProFTPD 1\.[0-1]\..*", string:banner) ||
     egrep(pattern:"^220 ProFTPD 1\.2\.0(pre.*|rc[1-2][^0-9])", string:banner))
  security_hole(port);
