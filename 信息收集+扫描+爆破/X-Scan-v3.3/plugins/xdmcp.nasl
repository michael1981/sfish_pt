#
# This script was written by Pasi Eronen <pasi.eronen@nixu.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
#  - Description
#  - Extract and display the load and the hostname
#  - Title revision, family change (9/17/09)


include("compat.inc");

if(description)
{
 script_id(10891);
 script_version("$Revision: 1.14 $");

 script_name(english:"X Display Manager Control Protocol (XDMCP) Detection");
 script_set_attribute(attribute:"synopsis", value:
"XDMCP is running on the remote host." );
 script_set_attribute(attribute:"description", value:
"XDMCP allows a Unix user to remotely obtain a graphical X11 login (and
therefore act as a local user on the remote host). 

If an attacker gains a valid login and password, he may be able to use
this service to gain further access on the remote host.  An attacker
may also use this service to mount a dictionary attack against the
remote host to try to log in remotely. 

Note that XDMCP (the Remote Desktop Protocol) is vulnerable to
Man-in-the-middle attacks, making it easy for attackers to steal the
credentials of legitimates users by impersonating the XDMCP server. 
In addition to this, XDMCP is not a ciphered protocol which make it
easy for an attacker to capture the keystrokes entered by the user." );
 script_set_attribute(attribute:"solution", value:
"Disable the XDMCP if you do not use it, and do not allow this service
to run across the Internet" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks if XDM has XDMCP protocol enabled");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Pasi Eronen");
 script_family(english:"Service detection");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

#
# The script code starts here
#
function report(hostname, status)
{
  local_var report;

  if ( hostname ) report += ' Hostname : ' + hostname + '\n';
  if ( status   ) report += ' Status   : ' + status + '\n';
 
  if ( report ) report = '\nUsing XDMCP, it was possible to obtain the following information\nabout the remote host :\n\n' + report + '\n';
  security_note(port:177, protocol:"udp", extra:report);
  register_service(port:177, proto:"xdmcp", ipproto:"udp");
  exit(0);
}

# this magic info request packet
req = raw_string(0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00);

if(!get_udp_port_state(177))exit(0);

soc = open_sock_udp(177);

if(soc)
{
        send(socket:soc, data:req);
        result  = recv(socket:soc, length:1000);
        if (result &&
	    strlen(result) > 3 &&
	    ord(result[0]) == 0 &&
	    ord(result[1]) == 1 &&
	    ord(result[2]) == 0 &&
	    ord(result[3]) == 5 )
		{
	 	offset = 6;
		if ( strlen(result) <= offset ) report();
	 	len = ord(result[offset]) * 256 + ord(result[offset+1]); offset += 2;
		offset += len;
		if ( strlen(result) <= offset ) report();
		len = ord(result[offset]) * 256 + ord(result[offset+1]); offset += 2;
		if ( strlen(result) <= offset + len ) report();
		hostname = substr(result, offset, offset + len - 1);
		offset += len;
		if ( strlen(result) <= offset ) report(hostname:hostname);
		len = ord(result[offset]) * 256 + ord(result[offset+1]); offset += 2;
		if ( strlen(result) < offset + len ) report(hostname:hostname);
		status = substr(result, offset, offset + len - 1);
		report(hostname:hostname, status:status);
		}
        
}
