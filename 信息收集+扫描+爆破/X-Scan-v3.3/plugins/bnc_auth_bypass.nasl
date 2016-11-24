#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(15703);
 script_version ("$Revision: 1.8 $");

 script_cve_id("CVE-2004-2612");
 script_bugtraq_id(11650);
 script_xref(name:"OSVDB", value:"12144");
 
 script_name(english:"BNC IRC Server Incorrect Password Authentication Bypass");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IRC proxy is susceptible to an authentication bypass issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the BNC IRC proxy that
contains a flaw in its authentication process that accepted only
logins with incorrect passwords.  An attacker may use this issue to
gain access to the remote IRC proxy server." );
 script_set_attribute(attribute:"see_also", value:"http://www.gotbnc.com/changes.html#2.9.1" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BNC version 2.9.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();

 
 summary["english"] = "Check BNC authentication bypass";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_require_ports(6667, 6669, 8080, "Services/irc-bnc");
 exit(0);
}

include("misc_func.inc");

pwd = string("Nessus", rand());
nick = "nessus";
user = "nessus";


#most common bnc ports 6667,6669,8080

ports = make_service_list("Services/irc-bnc", 6667, 6669, 8080);

foreach port (ports)
{
   if(get_port_state(port))
   {

    soc = open_sock_tcp(port);
    if (soc)
    {

     req = 'user nessus nessus nessus nessus\nnick nessus ~\n';
     send(socket: soc, data: req);

     r = recv(socket:soc, length:4096);
     if (r)
     {

       if ("NOTICE AUTH :You need to say /quote PASS <password>" >!< r) exit(0);
       {
         req = string ('pass ', pwd, '\n');
         send (socket:soc, data:req);

         r = recv(socket:soc, length:4096);
         if ((r) && ("NOTICE AUTH :Welcome to BNC" >< r))
         { 
          security_hole(port);
          exit(0);
         }
       }
     }
   close (soc);
  }
 }
}
