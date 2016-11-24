#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(12219);
 script_version ("$Revision: 1.11 $");
 name["english"] = "Sasser Virus Detection";

 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is infected by a virus." );
 script_set_attribute(attribute:"description", value:
"The Sasser worm is infecting this host.  Specifically,
a backdoored command server may be listening on port 9995 or 9996
and an ftp server (used to load malicious code) is listening on port 
5554 or 1023.  There is every indication that the host is currently 
scanning and infecting other systems." );
 script_set_attribute(attribute:"see_also", value:"http://www.lurhq.com/sasser.html" );
 script_set_attribute(attribute:"solution", value:
"- Use an Anti-Virus package to remove it.
- See http://www.microsoft.com/technet/security/bulletin/ms04-011.asp" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 summary["english"] = "Sasser Virus Detection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_require_ports(5554);
 exit(0);
}

# start script

include("ftp_func.inc");
login = "anonymous";
pass  = "bin";

# there really is no telling how many Sasser variants there will be :<
ports[0] =  5554;           
ports[1] =  1023;

foreach port ( ports)
{
 if ( get_port_state(port) )
   {
        soc = open_sock_tcp(port);
        if (soc) 
        {
            if(ftp_authenticate(socket:soc, user:login, pass:pass)) security_hole(port);
	    close(soc);
        }
    }
}





