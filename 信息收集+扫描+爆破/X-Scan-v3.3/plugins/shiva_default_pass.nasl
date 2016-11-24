#
# This script was written by Stefaan Van Dooren <stefaanv@kompas.be>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable
# - Updated to use compat.inc, added CVSS score (11/20/2009)



include("compat.inc");

if(description)
{
	script_id(10500);
  	script_cve_id("CVE-1999-0508");
  	script_xref(name:"OSVDB", value:"399");
 	script_version ("$Revision: 1.9 $");
	name["english"] = "Shiva Integrator Default Password";
	script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote router can be accessed with default credentials." );
 script_set_attribute(attribute:"description", value:
"The remote Shiva router uses the default password. 
This means that anyone who has (downloaded) a user manual can 
telnet to it and reconfigure it to lock you out of it, and to 
prevent you to use your internet connection." );
 script_set_attribute(attribute:"solution", value:
"telnet to this router and set a different password immediately." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
	summary["english"] = "Logs into the remote Shiva router";
	script_summary(english:summary["english"]);
 
	script_category(ACT_GATHER_INFO);
 
	script_copyright(english:"This script is Copyright (C) 2000 Stefaan Van Dooren");
	family["english"] = "Misc.";
	script_family(english:family["english"]);
	script_require_ports(23);
 
	exit(0);
}

#
# The script code starts here
#
port = 23;
if(get_port_state(port))
{
	soc = open_sock_tcp(port);
	if(soc)
	{
		data = string("hello\n\r");
		send(data:data, socket:soc);
		buf = recv(socket:soc, length:4096);
		if ("ntering privileged mode" >< buf)
			security_hole(port);
		close(soc);
	}
}

