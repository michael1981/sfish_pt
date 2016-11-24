#
# This script was written by H D Moore
# 


include("compat.inc");

if(description)
{
    script_id(10990);
    script_version ("$Revision: 1.21 $"); 

    # script_cve_id("CVE-MAP-NOMATCH");
    # NOTE: reviewed, and no CVE id currently assigned (jfs, december 2003)
    script_xref(name:"OSVDB", value:"813");

    script_name(english:"Multiple Vendor Embedded FTP Service Any Username Authentication Bypass");
    script_summary(english: "FTP Service Allows Any Username");

    script_set_attribute(attribute:"synopsis", value:
"A random username and password can be used to authenticate to the
remote FTP server." );
    script_set_attribute(attribute:"description", value:
"The FTP server running on the remote host can be accessed using a
random username and password.  Nessus has enabled some countermeasures
to prevent other plugins from reporting vulnerabilties incorrectly
because of this." );
    script_set_attribute(attribute:"solution", value:
"Contact the FTP server's documentation so that the service handles
authentication requests properly." );
    script_set_attribute(attribute:"solution", value:"n/a" );
    script_set_attribute(attribute:"risk_factor", value:"None" );
    script_set_attribute(attribute:"plugin_publication_date", value:
"2002/06/05");
    script_end_attributes();

    script_category(ACT_GATHER_INFO);
    script_copyright(english:"This script is Copyright (C) 2002-2009 Digital Defense Inc.");

    script_family(english: "FTP");
    script_dependencie("ftpserver_detect_type_nd_version.nasl"); 
    script_require_ports("Services/ftp", 21);
    exit(0);
}


#
# The script code starts here
#
include('global_settings.inc');
include('ftp_func.inc');
include('misc_func.inc');

port = get_kb_item("Services/ftp");
if (!port)port = 21;
if (! get_port_state(port)) exit(0);
if ( get_kb_item("ftp/" + port + "/broken") || get_kb_item("ftp/" + port + "/backdoor")) exit(0);

n_cnx = 0; n_log = 0;

banner = get_ftp_banner(port:port);
if ( ! banner )
{
 # debug_print("get_ftp_banner(port: ", port, ") failed\n");
 exit(0);
}


for (i = 0; i < 4; i ++)
{
 soc = open_sock_tcp(port);
 if(soc)
 {
   n_cnx ++;
   u = rand_str(); p = rand_str();
   if (ftp_authenticate(socket:soc, user: u, pass: p))
   {
     debug_print("ftp_authenticate(user: ", u, ", pass: ", p, ") = OK\n");
     n_log ++;
   }
   ftp_close(socket: soc);
 }
 else
  sleep(1);

 debug_print('n_log=', n_log, '/ n_cnx=', n_cnx, '\n');
 if (n_cnx > 0 && n_log > 0 )	# >= n_cnx ?
 {
  set_kb_item(name:"ftp/" + port + "/AnyUser", value:TRUE);
  # if (report_verbosity > 1)
   security_note(port:port);
  exit(0);
 }
}

