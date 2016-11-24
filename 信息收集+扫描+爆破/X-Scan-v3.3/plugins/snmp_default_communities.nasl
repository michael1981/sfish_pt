#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


#
# Thanks to the following persons for having sent additional
# SNMP communities over time :
#
# Javier Fernandez-Sanguino, Axel Nennker and the following references :
#
# From: Raphael Muzzio (rmuzzio_at_ZDNETMAIL.COM)
# Date: Nov 15 1998
# To: bugtraq@securityfocus.com
# Subject:  Re: ISS Security Advisory: Hidden community string in SNMP
# (http://lists.insecure.org/lists/bugtraq/1998/Nov/0212.html)
#
# Date: Mon, 5 Aug 2002 19:01:24 +0200 (CEST)
# From:"Jacek Lipkowski" <sq5bpf@andra.com.pl>
# To: bugtraq@securityfocus.com
# Subject: SNMP vulnerability in AVAYA Cajun firmware
# Message-ID: <Pine.LNX.4.44.0208051851050.3610-100000@hash.intra.andra.com.pl>
#
# From:"Foundstone Labs" <labs@foundstone.com>
# To: da@securityfocus.com, vulnwatch@vulnwatch.org
# Subject: Foundstone Labs Advisory - Information Leakage in Orinoco and Compaq Access Points
# Message-ID: <9DC8A3D37E31E043BD516142594BDDFAC476B0@MISSION.foundstone.com>
#
# CC:da@securityfocus.com, vulnwatch@vulnwatch.org
# To:"Foundstone Labs" <labs@foundstone.com>
# From:"Rob Flickenger" <rob@oreillynet.com>
# In-Reply-To: <9DC8A3D37E31E043BD516142594BDDFAC476B0@MISSION.foundstone.com>
# Message-Id: <D8F6A4EC-ABE3-11D6-AF54-0003936D6AE0@oreillynet.com>
# Subject: Re: [VulnWatch] Foundstone Labs Advisory - Information Leakage in Orinoco and Compaq Access Points
#
# http://www.securityfocus.com/archive/1/313714/2003-03-01/2003-03-07/0
# http://www.iss.net/issEn/delivery/xforce/alertdetail.jsp?id=advise15
#

if(description)
{
 script_id(10264);
 script_version ("$Revision: 1.83 $");

 script_cve_id(
  "CVE-1999-0186",
  "CVE-1999-0254",
  "CVE-1999-0516",
  "CVE-1999-0517",
  "CVE-2004-0311",
  "CVE-2004-1474"
 );
 script_bugtraq_id(177, 2112, 6825, 7081, 7212, 7317, 9681, 986, 10576, 11237);
 script_xref(name:"IAVA", value:"2001-B-0001");
 script_xref(name:"OSVDB", value:"209");
 script_xref(name:"OSVDB", value:"3985");
 script_xref(name:"OSVDB", value:"5770");
 script_xref(name:"OSVDB", value:"8076");
 script_xref(name:"OSVDB", value:"10206");
 script_xref(name:"OSVDB", value:"11964");

 script_name(english:"SNMP Agent Default Community Names");
 script_summary(english:"Default community names of the SNMP Agent");

 script_set_attribute(
  attribute:"synopsis",
  value:"The community names of the remote SNMP server can be guessed."
 );
 script_set_attribute(
  attribute:"description",
  value:string(
   "It is possible to obtain the default community names of the remote\n",
   "SNMP server.\n",
   "\n",
   "An attacker may use this information to gain more knowledge about the\n",
   "remote host or to change the configuration of the remote system (if\n",
   "the default community allow such modifications)."
  )
 );
 script_set_attribute(
  attribute:"solution",
  value:string(
   "Disable the SNMP service on the remote host if you do not use it,\n",
   "filter incoming UDP packets going to this port, or change the default\n",
   "community string."
  )
 );
 script_set_attribute(
  attribute:"cvss_vector",
  value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_set_attribute(
  attribute:"plugin_publication_date",
  value:"2002/11/25"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"SNMP");
 script_dependencies("find_service2.nasl");
 exit(0);
}

include ("global_settings.inc");
include ("misc_func.inc");
include ("snmp_func.inc");

# Protect against the fact that this host may be configured for SNMPv3 auth.
set_snmp_version( version:1 );

port = get_kb_item("SNMP/port");
if(!port)port = 161;


default = make_list("private", "public", "cisco");
extra = make_list(
  "0392a0",
  "ANYCOM",
  "Cisco router",
  "ILMI",
  "NoGaH$@!",
  "OrigEquipMfr",
  "Secret C0de",
  "TENmanUFactOryPOWER",
  "admin",
  "agent",
  "agent_steal",
  "all",
  "all private",
  "apc",
  "blue",
  "c",
  "cable-docsis",
  "cascade",
  "cc",
  "comcomcom",
  "community",
  "core",
  "default",
  "default",
  "freekevin",
  "fubar",
  "guest",
  "hp_admin",
  "ilmi",
  "internal",
  "localhost",
  "manager",
  "monitor",
  "openview",
  "password",
  "proxy",
  "regional",
  "riverhead",
  "rmon",
  "rmon_admin",
  "secret",
  "security",
  "snmp",
  "snmpd",
  "system",
  "test",
  "tivoli",
  "write",
  "xyzzy",
  "yellow"
);
if (thorough_tests) default = make_list(default, extra);


comm_list = "";
comm_number = 0;
foreach community (default)
{
  soc = open_sock_udp(port);
  if (!soc) exit (0); # Hu ?

  rep = snmp_request_next (socket:soc, community:community, oid:"1.3", timeout:3);
  if (!isnull(rep))
  {
    # Sun ...
    if ((rep[1] != "/var/snmp/snmpdx.st") && (rep[1] != "/etc/snmp/conf"))
    {
      set_kb_item(name:"SNMP/default/community", value:community);
      comm_list = strcat('  - ' + community + '\n');
      comm_number++;
    }
  }
  close(soc);
}

# We're done with actual sends, so set the SNMP_VERSION back, if needed.
reset_snmp_version();

if (comm_number > 0)
{
  if (comm_number > 5)
    report = string (
      "\n",
      "The remote SNMP server replies to more than 5 default community\n",
      "strings. This may be due to a badly configured server or an SNMP\n",
      "server on a printer."
    );
  else
  {
    if (comm_number == 1) s = "";
    else s = "s";
    report = string (
      "\n",
      "The remote SNMP server replies to the following default community\n",
      "string", s, " :\n",
      "\n",
      comm_list
    );
  }

  if (comm_number != 1 || (comm_number == 1 && "public" >!< comm_list))
    security_hole(port:port, extra:report, protocol:"udp");
}
