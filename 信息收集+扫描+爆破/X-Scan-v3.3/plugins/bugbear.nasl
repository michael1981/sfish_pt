#
# This script was written by Michel Arboi <arboi@alussinan.org>
# Well, in fact I started from a simple script by Thomas Reinke and 
# heavily hacked every byte of it :-]
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added links to the Bugtraq message archive and Microsoft Knowledgebase
#
# There was no information on the BugBear protocol. 
# I found a worm in the wild and found that it replied to the "p" command;
# the data look random but ends with "ID:"  and a number
# Thomas Reinke confirmed that his specimen of the worm behaved in the 
# same way. 
# We will not provide the full data here because it might contain 
# confidential information.
# 
# References:
#
# Date: Tue, 1 Oct 2002 02:07:29 -0400
# From:"Russ" <Russ.Cooper@RC.ON.CA>
# Subject: Alert:New worms, be aware of internal infection possibilities
# To:NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM
#


include("compat.inc");

if(description)
{
 script_id(11135);
 script_xref(name:"IAVA", value:"2001-a-0004");
 script_bugtraq_id(2524);
 script_cve_id("CVE-2001-0154"); # For MS01-020 - should be changed later
 script_version ("$Revision: 1.19 $");
 script_name(english:"Bugbear Worm Infection Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"The BugBear backdoor is listening on this port.  An attacker may
connect to it to retrieve secret information such as passwords,
credit card numbers, etc.

The BugBear worm includes a keylogger and can kill antivirus and
firewall software.  It propagates through email and open Windows
shares. 

Depending on the antivirus vendor, it is known as Tanatos,
I-Worm.Tanatos, NATOSTA.A, W32/Bugbear-A, Tanatos, W32/Bugbear@MM,
WORM_BUGBEAR.A, Win32.BugBear..." );
 script_set_attribute(attribute:"see_also", value:"http://www.sophos.com/virusinfo/analyses/w32bugbeara.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.ealaddin.com/news/2002/esafe/bugbear.asp" );
 script_set_attribute(attribute:"see_also", value:"http://securityresponse.symantec.com/avcenter/venc/data/w32.bugbear@mm.html" );
 script_set_attribute(attribute:"see_also", value:"http://vil.nai.com/vil/content/v_99728.htm" );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/default.aspx?scid=KB;en-us;329770&" );
 script_set_attribute(attribute:"solution", value:
"- Use an Anti-Virus package to remove it.
- Close your Windows shares
- Update your IE browser 
  See 'Incorrect MIME Header Can Cause IE to Execute E-mail Attachment'
  http://www.microsoft.com/technet/security/bulletin/MS01-020.mspx" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
 summary["english"] = "Detect Bugbear worm";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Michel Arboi & Thomas Reinke");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_require_ports(36794);
 script_dependencies("find_service1.nasl");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");

port = 36794;

if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (! soc) exit(0);

# We just need to send a 'p' without CR
send(socket: soc, data: "p");
# I never saw a buffer bigger than 247 bytes but as the "ID:" string is 
# near the end, we'd better use a big buffer, just in case
r = recv(socket: soc, length: 65536);
close(soc);

if ("ID:" >< r) {
 security_hole(port); 
 register_service(port: port, proto: "bugbear");
 exit(0); 
}
