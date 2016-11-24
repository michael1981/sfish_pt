#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11450);
 script_version ("$Revision: 1.6 $");

 script_cve_id("CVE-2001-0456");
 script_xref(name:"OSVDB", value:"5638");
 
 script_name(english:"ProFTPD on Debian Linux postinst Installation Privilege Escalation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by several flaws." );
 script_set_attribute(attribute:"description", value:
"The following problems have been reported for the version of proftpd in 
Debian 2.2 (potato):

   1. There is a configuration error in the postinst script, when the user 
      enters 'yes', when asked if anonymous access should be enabled. 
      The postinst script wrongly leaves the 'run as uid/gid root' 
      configuration option in /etc/proftpd.conf, and adds a 
      'run as uid/gid nobody' option that has no effect.
      
   2. There is a bug that comes up when /var is a symlink, and 
       proftpd is restarted. When stopping proftpd, the /var 
       symlink is removed; when it's started again a file named 
       /var is created." );
 script_set_attribute(attribute:"see_also", value:"http://www.debian.org/security/2001/dsa-032" );
 script_set_attribute(attribute:"solution", value:
"Upgrade your proftpd server to proftpd-1.2.0pre10-2.0potato1" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P" );
                 
                     
script_end_attributes();

 script_summary(english:"Checks if the version of the remote proftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
                  
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
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

banner = get_ftp_banner(port:port);

if(egrep(pattern:"^220 ProFTPD 1\.(0\..*|2\.0pre([0-9][^0-9]|10)).*debian.*", string:banner, icase:TRUE))security_warning(port);

